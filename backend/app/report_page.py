"""The full web report: one self-contained HTML page with no JavaScript.

Security design:
- Every value derived from the email is passed through html.escape().
- No scripts at all; animations are pure CSS.
- The stylesheet is a static block allowed by its SHA-256 hash in the
  Content-Security-Policy, so even an injected <style> or <script> would
  be refused by the browser.
"""

import base64
import hashlib
import math
from html import escape

CATEGORY_LABELS = {
    "authentication": "Authentication",
    "sender": "Sender",
    "links": "Links",
    "content": "Content",
    "attachments": "Attachments",
}
SEVERITY_LABELS = {
    "critical": "Critical", "high": "High risk", "medium": "Medium risk",
    "low": "Low risk", "trust": "Reassuring", "info": "Info",
}

STYLE = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#202124;--muted:#5f6368;--line:#e3e5e8;
--safe:#188038;--suspicious:#e37400;--likely_malicious:#d93025;--malicious:#a50e0e;
--critical:#a50e0e;--high:#d93025;--medium:#e37400;--low:#b98900;--trust:#188038;--info:#5f6368}
@media (prefers-color-scheme:dark){:root{--bg:#17181a;--card:#222326;--ink:#e8eaed;--muted:#9aa0a6;--line:#3a3c40}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:24px 16px 48px}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:20px 22px;margin-bottom:16px;
animation:rise .5s ease-out both}
.card:nth-child(2){animation-delay:.1s}.card:nth-child(3){animation-delay:.2s}.card:nth-child(4){animation-delay:.3s}
@keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
h1{font-size:22px;margin:0 0 4px;font-weight:600}h2{font-size:18px;margin:0 0 14px;font-weight:600}
.meta{color:var(--muted);font-size:14px;overflow-wrap:anywhere}
.hero{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(0,1fr);gap:16px;align-items:center}
.hero img{width:100%;height:auto;border-radius:12px}
@media (max-width:640px){.hero{grid-template-columns:1fr}}
.summary{font-size:18px;margin:8px 0 0}
.radar svg{width:100%;max-width:460px;display:block;margin:0 auto}
.radar .grid{fill:none;stroke:var(--line)}.radar .axis{stroke:var(--line)}
.radar .shape{fill:rgba(217,48,37,.22);stroke:var(--high);stroke-width:2;transform-origin:230px 160px;
animation:grow 1s .3s ease-out both}
.radar text{fill:var(--muted);font-size:12px}
@keyframes grow{from{transform:scale(0)}to{transform:scale(1)}}
.finding{border-left:4px solid var(--line);padding:4px 0 4px 14px;margin:0 0 18px}
.finding:last-child{margin-bottom:0}
.pill{display:inline-block;font-size:12px;font-weight:600;padding:2px 9px;border-radius:999px;color:#fff;margin-bottom:6px}
.f-title{font-weight:600}.f-text{margin:2px 0}
.evidence{font:13px/1.5 ui-monospace,Consolas,monospace;color:var(--muted);overflow-wrap:anywhere;margin:6px 0}
.tip{background:var(--bg);border-radius:10px;padding:8px 12px;font-size:14px;margin-top:8px}
.critical{border-color:var(--critical)}.critical .pill{background:var(--critical)}
.high{border-color:var(--high)}.high .pill{background:var(--high)}
.medium{border-color:var(--medium)}.medium .pill{background:var(--medium)}
.low{border-color:var(--low)}.low .pill{background:var(--low)}
.trust{border-color:var(--trust)}.trust .pill{background:var(--trust)}
.info{border-color:var(--info)}.info .pill{background:var(--info)}
details summary{cursor:pointer;font-weight:600}details p,details li{color:var(--muted);font-size:15px}
.checks{list-style:none;padding:0;margin:0}.checks li{padding:6px 0;border-bottom:1px solid var(--line);display:flex;gap:10px;justify-content:space-between}
.checks li:last-child{border-bottom:0}.status{font-size:13px;color:var(--muted);text-align:right}
footer{color:var(--muted);font-size:13px;text-align:center;margin-top:24px}
"""
STYLE_HASH = "sha256-" + base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        f"default-src 'none'; img-src 'self'; style-src '{STYLE_HASH}'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow",
}


def _radar(category_scores: dict[str, int]) -> str:
    cx, cy, radius = 230, 160, 110
    keys = list(CATEGORY_LABELS)
    angles = [math.radians(-90 + i * 360 / len(keys)) for i in range(len(keys))]

    def point(angle: float, fraction: float) -> str:
        return f"{cx + radius * fraction * math.cos(angle):.1f},{cy + radius * fraction * math.sin(angle):.1f}"

    rings = "".join(
        f'<polygon class="grid" points="{" ".join(point(a, level) for a in angles)}"/>'
        for level in (0.25, 0.5, 0.75, 1.0)
    )
    axes = "".join(f'<line class="axis" x1="{cx}" y1="{cy}" x2="{point(a, 1).split(",")[0]}" '
                   f'y2="{point(a, 1).split(",")[1]}"/>' for a in angles)
    values = [max(category_scores.get(key, 0), 3) / 100 for key in keys]  # floor keeps the shape visible
    shape = f'<polygon class="shape" points="{" ".join(point(a, v) for a, v in zip(angles, values))}"/>'
    labels = ""
    for key, angle in zip(keys, angles):
        x, y = (float(n) for n in point(angle, 1.22).split(","))
        anchor = "middle" if abs(math.cos(angle)) < 0.3 else ("start" if math.cos(angle) > 0 else "end")
        labels += (f'<text x="{x:.1f}" y="{y + 4:.1f}" text-anchor="{anchor}">'
                   f'{CATEGORY_LABELS[key]} {category_scores.get(key, 0)}</text>')
    return (f'<svg viewBox="0 0 460 320" role="img" aria-label="Risk by category">'
            f"{rings}{axes}{shape}{labels}</svg>")


def _finding(finding: dict) -> str:
    severity = finding["severity"] if finding["severity"] in SEVERITY_LABELS else "info"
    items = "".join(f"<div>{escape(item)}</div>" for item in finding.get("evidence", []))
    evidence = f'<div class="evidence">{items}</div>' if items else ""
    tip = f'<div class="tip">💡 <b>How to spot it:</b> {escape(finding["tip"])}</div>' if finding.get("tip") else ""
    return (
        f'<div class="finding {severity}">'
        f'<span class="pill">{SEVERITY_LABELS[severity]}</span>'
        f'<div class="f-title">{escape(finding["title"])}</div>'
        f'<p class="f-text">{escape(finding["explanation"])}</p>'
        f"{evidence}{tip}</div>"
    )


CHECK_LABELS = {
    "ok": "✓ checked", "unavailable": "⚠ unavailable",
    "not_configured": "— not enabled in this deployment", "skipped": "— not enabled in this deployment",
}


def _checks(checks: list[dict]) -> str:
    if not checks:
        return ""
    rows = "".join(
        f"<li><span>{escape(c['name'])}</span><span class=\"status\">"
        f"{CHECK_LABELS.get(c['status'], escape(c['status']))}"
        f"{' · ' + escape(c['detail']) if c.get('detail') else ''}</span></li>"
        for c in checks
    )
    return f'<section class="card"><h2>Threat intelligence checks</h2><ul class="checks">{rows}</ul></section>'


def render_report(report: dict) -> str:
    findings = [f for f in report["findings"] if f["severity"] != "info"]
    findings_html = "".join(_finding(f) for f in findings) or "<p>No warning signs were found.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mail Scorer report</title>
<style>{STYLE}</style></head>
<body><main>
<section class="card">
  <h1>Mail Scorer report</h1>
  <div class="meta">Subject: {escape(report["subject"] or "(no subject)")}</div>
  <div class="meta">From: {escape(report["sender"] or "(unknown sender)")}</div>
</section>
<section class="card hero">
  <img src="/gauge/{int(report["score"])}.gif" alt="Risk score {int(report["score"])} out of 100: {escape(report["verdict"])}">
  <div><h2>{escape(report["verdict"])}</h2><p class="summary">{escape(report["summary"])}</p></div>
</section>
<section class="card radar"><h2>Risk by category</h2>{_radar(report["category_scores"])}</section>
<section class="card"><h2>What we found</h2>{findings_html}</section>
{_checks(report.get("checks", []))}
<section class="card"><details><summary>How the score works</summary>
  <ul>
    <li>Each warning sign has a weight from its severity (low 10%, medium 25%, high 45%, critical 80%).</li>
    <li>Signs combine like independent evidence, so two strong signals reinforce each other, but the score never passes 100.</li>
    <li>Each additional sign counts a little less, so many weak signs cannot add up to "malicious" alone.</li>
    <li>A verified sender lowers the score, but only when nothing serious was found.</li>
    <li>A critical sign, like a program attachment or a link on Google's dangerous-sites list, sets a minimum score of 80.</li>
    <li>The AI assessment can only raise the score, never lower it, so text written to fool AI cannot hide other warnings.</li>
  </ul></details></section>
<footer>This report expires 30 minutes after the scan and is never stored on disk.
Links are shown defanged ([.]) so they cannot be clicked.</footer>
</main></body></html>"""


def render_expired() -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Report expired</title>
<style>{STYLE}</style></head><body><main><section class="card">
<h1>This report has expired</h1>
<p class="meta">Reports are kept for 30 minutes only. Open the email in Gmail and scan it again.</p>
</section></main></body></html>"""
