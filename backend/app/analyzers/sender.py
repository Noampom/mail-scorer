"""Who the email claims to be from, and whether that claim holds up."""

import re

from app.analyzers.base import Category, Finding, Severity, make_evidence
from app.data.brands import BRANDS, FREE_MAIL_DOMAINS, brand_label
from app.domains import decode_idn, find_impersonated_brand, has_non_ascii, registrable_domain
from app.parsing import ParsedEmail

_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+\.)+[\w-]{2,}", re.UNICODE)


def _brand_in_display_name(display_name: str) -> str | None:
    name = re.sub(r"[^a-z0-9]+", " ", display_name.lower())
    compact = name.replace(" ", "")
    for brand in BRANDS:
        if re.search(rf"\b{re.escape(brand)}\b", name) or (len(brand) >= 6 and brand in compact):
            return brand
    return None


def analyze(email: ParsedEmail) -> list[Finding]:
    sender = email.from_addr
    if sender is None or not sender.domain:
        return [Finding(
            "sender.missing", Category.SENDER, Severity.MEDIUM,
            "No valid sender address",
            "The From header is missing or malformed, which legitimate mail systems rarely produce.",
        )]

    findings: list[Finding] = []
    sender_domain = registrable_domain(sender.domain)

    # "security@paypal.com" <attacker@evil.com>
    embedded = _EMAIL_IN_TEXT.search(sender.display_name)
    if embedded and registrable_domain(embedded.group(0).rsplit("@", 1)[-1]) != sender_domain:
        findings.append(Finding(
            "sender.display_name_address", Category.SENDER, Severity.HIGH,
            "Display name shows a different email address",
            "The sender's name contains an email address that is not the real sending address, "
            "a trick to make you trust a fake sender.",
            make_evidence([f"Shown: {embedded.group(0)}", f"Actual: {sender.email}"]),
        ))

    brand = _brand_in_display_name(sender.display_name)
    official = brand and (sender_domain in BRANDS[brand] or sender_domain.split(".", 1)[0] == brand)
    if brand and not official:
        where = "a free mailbox anyone can create" if sender_domain in FREE_MAIL_DOMAINS else sender_domain
        findings.append(Finding(
            "sender.brand_display_name", Category.SENDER, Severity.HIGH,
            f"Sender name impersonates {brand_label(brand)}",
            f"The sender calls itself '{sender.display_name}', but the email comes from {where}, "
            f"not from an official {brand_label(brand)} domain.",
            make_evidence([f"Name: {sender.display_name}", f"Address: {sender.email}"]),
        ))

    imitated = find_impersonated_brand(sender.domain)
    if imitated:
        findings.append(Finding(
            "sender.lookalike_domain", Category.SENDER, Severity.HIGH,
            f"Sender domain imitates {brand_label(imitated)}",
            f"'{decode_idn(sender.domain)}' is designed to look like an official {brand_label(imitated)} domain.",
            make_evidence([sender.email]),
        ))
    elif has_non_ascii(sender.domain):
        findings.append(Finding(
            "sender.idn_domain", Category.SENDER, Severity.MEDIUM,
            "Sender domain uses international characters",
            "Domains with non-Latin letters can imitate familiar names using look-alike characters.",
            make_evidence([f"{sender.domain} -> {decode_idn(sender.domain)}"]),
        ))

    reply_to = email.reply_to
    if reply_to and reply_to.domain and registrable_domain(reply_to.domain) != sender_domain:
        severity = Severity.HIGH if registrable_domain(reply_to.domain) in FREE_MAIL_DOMAINS else Severity.MEDIUM
        findings.append(Finding(
            "sender.reply_to_mismatch", Category.SENDER, severity,
            "Replies go to a different address",
            "If you reply, your answer goes to a different domain than the one the email came from. "
            "Scammers use this to receive your response while hiding behind a familiar sender.",
            make_evidence([f"From: {sender.email}", f"Reply-To: {reply_to.email}"]),
        ))

    return findings
