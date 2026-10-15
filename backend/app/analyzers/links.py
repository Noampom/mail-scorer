"""Links in the email: where they really lead versus what they show.

We never visit any link. Fetching attacker-controlled URLs from our server
would expose it to SSRF and tell the attacker the email was opened.
"""

import re

from app.analyzers.base import Category, Finding, Severity, make_evidence
from app.data.brands import SUSPICIOUS_TLDS, URL_SHORTENERS, brand_label
from app.domains import decode_idn, find_impersonated_brand, has_non_ascii, is_ip_address, registrable_domain, tld
from app.parsing import ParsedEmail

_DOMAIN_IN_TEXT = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE)
_DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file"}


def defang(url: str, limit: int = 80) -> str:
    """Make a URL unclickable for display: https://evil.com -> hxxps://evil[.]com"""
    url = url[:limit] + ("…" if len(url) > limit else "")
    return re.sub(r"^http", "hxxp", url, flags=re.IGNORECASE).replace(".", "[.]")


def analyze(email: ParsedEmail) -> list[Finding]:
    hits: dict[str, list[str]] = {}
    imitated_brands: set[str] = set()

    def hit(kind: str, evidence: str) -> None:
        hits.setdefault(kind, []).append(evidence)

    for link in email.links:
        if link.scheme in _DANGEROUS_SCHEMES:
            hit("script", f"{link.scheme}: link")
            continue
        if link.scheme not in {"http", "https"} or not link.host:
            continue  # mailto:, tel:, anchors

        host = link.host.lower()
        if is_ip_address(host):
            hit("ip", defang(link.href))
        if "@" in link.href.split("//", 1)[-1].split("/", 1)[0]:
            hit("userinfo", defang(link.href))

        shown = _DOMAIN_IN_TEXT.search(link.text or "")
        if shown and "." in shown.group(1):
            shown_domain = registrable_domain(shown.group(1))
            real_domain = registrable_domain(host)
            if shown_domain and real_domain and shown_domain != real_domain and tld(shown.group(1)):
                hit("mismatch", f"Shows {shown.group(1)} → goes to {defang(host)}")

        brand = find_impersonated_brand(host)
        if brand:
            imitated_brands.add(brand_label(brand))
            hit("lookalike", defang(host))
        elif has_non_ascii(host):
            hit("idn", f"{defang(host)} ({decode_idn(host)})")

        if registrable_domain(host) in URL_SHORTENERS:
            hit("shortener", defang(link.href))
        if tld(host) in SUSPICIOUS_TLDS:
            hit("tld", defang(host))

    findings: list[Finding] = []

    def add(kind: str, severity: Severity, title: str, explanation: str) -> None:
        if kind in hits:
            findings.append(Finding(f"links.{kind}", Category.LINKS, severity, title, explanation, make_evidence(hits[kind])))

    add("mismatch", Severity.HIGH, "Link text hides its real destination",
        "A link displays one website but actually takes you to a different one.")
    add("lookalike", Severity.HIGH, f"Link imitates {', '.join(sorted(imitated_brands)) or 'a known brand'}",
        "A link points to a domain made to look like a well-known company's website.")
    add("script", Severity.HIGH, "Link runs code instead of opening a page",
        "The email contains a javascript:/data: link, which legitimate emails do not use.")
    add("ip", Severity.HIGH, "Link points to a raw IP address",
        "Real companies link to named websites, not to numeric server addresses.")
    add("userinfo", Severity.HIGH, "Link uses an '@' trick",
        "Everything before '@' in a web address is ignored, so the link goes somewhere other than it seems.")
    add("idn", Severity.MEDIUM, "Link uses international look-alike characters",
        "The web address contains non-Latin letters that can imitate a familiar site.")
    add("shortener", Severity.LOW, "Link uses a URL shortener",
        "Shortened links hide the final destination until you click.")
    add("tld", Severity.LOW, "Link uses a domain ending often abused by scammers",
        "Cheap domain endings like .xyz or .top are common in phishing campaigns.")
    return findings
