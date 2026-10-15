"""Turns the raw, untrusted payload into a structured ParsedEmail.

Parsing happens once, here, with robust standard parsers (email.parser,
BeautifulSoup's pure-Python html.parser). Analyzers then only read the
structured result and never touch raw input themselves.
"""

import re
from dataclasses import dataclass, field
from email import policy
from email.message import Message
from email.parser import HeaderParser
from email.utils import parseaddr
from urllib.parse import urlsplit

from bs4 import BeautifulSoup, Comment

from app.models import EmailPayload

_URL_IN_TEXT = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.IGNORECASE)
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|"
    r"font-size\s*:\s*0+(\.0+)?(px|pt|em|rem|%)?\s*(;|$)|opacity\s*:\s*0+(\.0+)?\s*(;|$)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Address:
    display_name: str
    email: str

    @property
    def domain(self) -> str:
        return self.email.rsplit("@", 1)[-1].lower() if "@" in self.email else ""


@dataclass(frozen=True)
class Link:
    href: str
    text: str
    host: str
    scheme: str


@dataclass
class ParsedEmail:
    headers: Message
    subject: str
    from_addr: Address | None
    reply_to: Address | None
    return_path: Address | None
    links: list[Link]
    visible_text: str
    hidden_text: str
    attachments: list = field(default_factory=list)


def _first_address(headers: Message, name: str) -> Address | None:
    try:
        value = headers.get(name)
    except Exception:  # malformed header: treat as absent
        return None
    if value is None:
        return None
    addresses = getattr(value, "addresses", None)
    if addresses:
        addr = addresses[0]
        return Address(str(addr.display_name or ""), str(addr.addr_spec or "").lower())
    display_name, email = parseaddr(str(value))
    return Address(display_name, email.lower()) if email else None


def _make_link(href: str, text: str) -> Link | None:
    href = (href or "").strip()
    if not href:
        return None
    try:
        parts = urlsplit(href)
        host = parts.hostname or ""
    except ValueError:  # e.g. invalid IPv6 literal
        return None
    return Link(href=href[:2048], text=" ".join(text.split())[:300], host=host, scheme=parts.scheme.lower())


def _is_hidden(tag) -> bool:
    """True if this element itself is styled to be invisible."""
    style = tag.get("style") or ""
    return bool(_HIDDEN_STYLE.search(style)) or tag.get("hidden") is not None


def _parse_html(html: str) -> tuple[list[Link], str, str]:
    soup = BeautifulSoup(html, "html.parser")
    for node in soup(["script", "style", "head", "title", "meta"]):
        node.decompose()
    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        comment.extract()

    links = [link for a in soup.find_all("a", href=True) if (link := _make_link(a["href"], a.get_text(" ")))]

    # Collect only the outermost hidden elements, then remove them, so the
    # visible text is what the user actually sees.
    hidden_tags = [tag for tag in soup.find_all(True) if _is_hidden(tag)]
    hidden_ids = {id(tag) for tag in hidden_tags}  # identity, not Tag equality
    outermost = [tag for tag in hidden_tags if not any(id(p) in hidden_ids for p in tag.parents)]
    hidden_parts = [tag.get_text(" ", strip=True) for tag in outermost]
    for tag in outermost:
        tag.decompose()
    visible = soup.get_text(" ", strip=True)
    return links, " ".join(visible.split()), " ".join(" ".join(hidden_parts).split())


def parse_email(payload: EmailPayload) -> ParsedEmail:
    headers = HeaderParser(policy=policy.default).parsestr(payload.raw_headers)

    links: list[Link] = []
    hidden_text = ""
    visible_text = payload.body_text
    if payload.body_html:
        links, html_visible, hidden_text = _parse_html(payload.body_html)
        visible_text = payload.body_text or html_visible

    # URLs written as plain text (not inside <a>) are clickable in Gmail too.
    known = {link.href for link in links}
    for match in _URL_IN_TEXT.findall(payload.body_text):
        if match not in known and (link := _make_link(match, match)):
            links.append(link)
            known.add(match)

    subject = payload.subject
    if not subject:
        try:
            subject = str(headers.get("Subject") or "")
        except Exception:
            subject = ""

    return ParsedEmail(
        headers=headers,
        subject=subject,
        from_addr=_first_address(headers, "From"),
        reply_to=_first_address(headers, "Reply-To"),
        return_path=_first_address(headers, "Return-Path"),
        links=links[:300],
        visible_text=visible_text,
        hidden_text=hidden_text,
        attachments=list(payload.attachments),
    )
