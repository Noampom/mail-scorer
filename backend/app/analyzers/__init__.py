"""Runs every analyzer over a parsed email.

Analyzers are isolated: if one crashes on a weird email, the others still
run and the user still gets a result (with a note that one check failed).
"""

import logging

from app.analyzers import attachments, auth, content, links, sender
from app.analyzers.base import Category, Finding, Severity
from app.parsing import ParsedEmail

logger = logging.getLogger(__name__)

ANALYZERS = (
    (Category.AUTH, auth.analyze),
    (Category.SENDER, sender.analyze),
    (Category.LINKS, links.analyze),
    (Category.CONTENT, content.analyze),
    (Category.ATTACHMENTS, attachments.analyze),
)


def run_all(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    for category, analyze in ANALYZERS:
        try:
            findings.extend(analyze(email))
        except Exception:
            # Log the failure type only; never log email content.
            logger.exception("Analyzer %s failed", category.value)
            findings.append(Finding(
                f"{category.value}.error", category, Severity.INFO,
                f"{category.value.title()} check could not run",
                "This part of the analysis failed, so the score may be incomplete.",
            ))
    return findings
