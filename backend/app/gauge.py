"""Animated risk gauge rendered as a GIF for the Gmail card.

Gmail cards cannot run HTML or JavaScript, but they can show images, and
animated GIFs play. The gauge fills up to the score while the number counts
up, and the shield mascot in the middle gets more worried as risk rises.

The image depends ONLY on the score (0-100): no email data is ever encoded
in the URL or the picture. That also means at most 101 distinct images, so
every one is cached after its first render.
"""

import io
import math
from functools import lru_cache

from PIL import Image, ImageDraw, ImageFont

from app.scoring import verdict_for

SCALE = 2  # draw at 2x, then downsample for smooth anti-aliased edges
WIDTH, HEIGHT = 600, 360
CENTER = (300, 250)
RADIUS = 200
THICKNESS = 30
FRAMES = 28
FRAME_MS = 40
HOLD_MS = 60_000  # last frame stays (GIF plays once)

BACKGROUND = (255, 255, 255)
TRACK = (232, 234, 237)
INK = (32, 33, 36)
MUTED = (95, 99, 104)
LEVEL_COLORS = {
    "safe": (24, 128, 56),
    "suspicious": (227, 116, 0),
    "likely_malicious": (217, 48, 37),
    "malicious": (165, 14, 14),
}


def _font(size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.load_default(size=size * SCALE)


def _pt(x: float, y: float) -> tuple[float, float]:
    return x * SCALE, y * SCALE


def _arc_box() -> list[float]:
    cx, cy = CENTER
    return [*_pt(cx - RADIUS, cy - RADIUS), *_pt(cx + RADIUS, cy + RADIUS)]


def _draw_arc(draw: ImageDraw.ImageDraw, value: float, color) -> None:
    box = _arc_box()
    draw.arc(box, 180, 360, fill=TRACK, width=THICKNESS * SCALE)
    end_x, cap = CENTER[0] + RADIUS - THICKNESS / 2, THICKNESS / 2
    draw.ellipse([*_pt(end_x - cap, CENTER[1] - cap), *_pt(end_x + cap, CENTER[1] + cap)], fill=TRACK)
    if value > 0:
        draw.arc(box, 180, 180 + 180 * value / 100, fill=color, width=THICKNESS * SCALE)
        # Round cap at the moving end of the arc.
        angle = math.radians(180 + 180 * value / 100)
        r = RADIUS - THICKNESS / 2
        ex, ey = CENTER[0] + r * math.cos(angle), CENTER[1] + r * math.sin(angle)
        cap = THICKNESS / 2
        draw.ellipse([*_pt(ex - cap, ey - cap), *_pt(ex + cap, ey + cap)], fill=color)
    sx = CENTER[0] - RADIUS + THICKNESS / 2
    draw.ellipse([*_pt(sx - THICKNESS / 2, CENTER[1] - THICKNESS / 2),
                  *_pt(sx + THICKNESS / 2, CENTER[1] + THICKNESS / 2)],
                 fill=color if value > 0 else TRACK)


def _draw_shield(draw: ImageDraw.ImageDraw, level: str, color) -> None:
    """A shield with a face whose expression follows the risk level."""
    cx, top, w, h = CENTER[0], 92, 104, 122
    outline = [
        (cx, top), (cx + w / 2, top + 18), (cx + w / 2, top + h * 0.48),
        (cx + w * 0.36, top + h * 0.78), (cx, top + h), (cx - w * 0.36, top + h * 0.78),
        (cx - w / 2, top + h * 0.48), (cx - w / 2, top + 18),
    ]
    draw.polygon([_pt(x, y) for x, y in outline], fill=color)

    eye_y, eye_dx, eye_r = top + 50, 18, 7
    white = (255, 255, 255)
    for side in (-1, 1):
        ex = cx + side * eye_dx
        if level == "malicious":  # angry eyebrows
            draw.line([_pt(ex + 10 * side, eye_y - 16), _pt(ex - 10 * side, eye_y - 9)],
                      fill=white, width=4 * SCALE)
        draw.ellipse([*_pt(ex - eye_r, eye_y - eye_r), *_pt(ex + eye_r, eye_y + eye_r)], fill=white)

    mouth_y, mouth_w = top + 80, 26
    box = [*_pt(cx - mouth_w, mouth_y - 16), *_pt(cx + mouth_w, mouth_y + 12)]
    if level == "safe":
        draw.arc(box, 20, 160, fill=white, width=5 * SCALE)  # smile
    elif level == "suspicious":
        draw.line([_pt(cx - 18, mouth_y), _pt(cx + 18, mouth_y)], fill=white, width=5 * SCALE)
    else:
        frown = [*_pt(cx - mouth_w, mouth_y - 2), *_pt(cx + mouth_w, mouth_y + 26)]
        draw.arc(frown, 200, 340, fill=white, width=5 * SCALE)  # frown


def _draw_text(draw: ImageDraw.ImageDraw, value: int, level: str, label: str, color) -> None:
    number = str(value)
    big = _font(46)
    small = _font(20)
    number_w = draw.textlength(number, font=big)
    suffix_w = draw.textlength(" / 100", font=small)
    x = CENTER[0] * SCALE - (number_w + suffix_w) / 2
    y = (CENTER[1] + 4) * SCALE
    draw.text((x, y), number, font=big, fill=INK, stroke_width=SCALE, stroke_fill=INK)
    draw.text((x + number_w, y + 22 * SCALE), " / 100", font=small, fill=MUTED)
    label_font = _font(24)
    lw = draw.textlength(label, font=label_font)
    draw.text((CENTER[0] * SCALE - lw / 2, (CENTER[1] + 66) * SCALE), label, font=label_font,
              fill=color, stroke_width=1, stroke_fill=color)


def _frame(value: int, final_label: str | None) -> Image.Image:
    level, label = verdict_for(value)
    color = LEVEL_COLORS[level]
    image = Image.new("RGB", (WIDTH * SCALE, HEIGHT * SCALE), BACKGROUND)
    draw = ImageDraw.Draw(image)
    _draw_arc(draw, value, color)
    _draw_shield(draw, level, color)
    _draw_text(draw, value, level, final_label or "Scanning…", color)
    return image.resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS)


def _ease_out(t: float) -> float:
    return 1 - (1 - t) ** 3


@lru_cache(maxsize=101)
def render_gauge(score: int, animated: bool = True) -> bytes:
    """Return GIF bytes for a score in 0..100."""
    if not 0 <= score <= 100:
        raise ValueError("score must be between 0 and 100")
    final_label = verdict_for(score)[1]

    if not animated:
        frames = [_frame(score, final_label)]
        durations = [HOLD_MS]
    else:
        values = sorted({round(score * _ease_out(i / (FRAMES - 1))) for i in range(FRAMES)})
        frames = [_frame(v, None) for v in values[:-1]] + [_frame(score, final_label)]
        durations = [FRAME_MS] * (len(frames) - 1) + [HOLD_MS]

    buffer = io.BytesIO()
    frames[0].save(
        buffer, format="GIF", save_all=True, append_images=frames[1:],
        duration=durations, optimize=True, disposal=1,
    )  # no "loop" argument: the animation plays once and stops on the result
    return buffer.getvalue()
