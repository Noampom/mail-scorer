"""SPF, DKIM and DMARC results, as recorded by Gmail's own mail servers.

Security note: anyone can write an "Authentication-Results" header into the
email they send. We only trust the TOPMOST such header, and only if it was
written by mx.google.com, because Gmail adds its own on arrival, above
anything the sender wrote.
"""

import re

from app.analyzers.base import Category, Finding, Severity
from app.domains import registrable_domain
from app.parsing import ParsedEmail

TRUSTED_AUTHSERV_ID = "mx.google.com"
_RESULT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_HEADER_FROM = re.compile(r"header\.from\s*=\s*([^\s;()]+)", re.IGNORECASE)


def _trusted_results(email: ParsedEmail) -> str | None:
    try:
        values = email.headers.get_all("Authentication-Results") or []
    except Exception:
        return None
    if not values:
        return None
    top = str(values[0])
    authserv_id = top.split(";", 1)[0].strip().lower()
    return top if authserv_id == TRUSTED_AUTHSERV_ID else None


def analyze(email: ParsedEmail) -> list[Finding]:
    header = _trusted_results(email)
    if header is None:
        return [Finding(
            "auth.unavailable", Category.AUTH, Severity.INFO,
            "Authentication results not available",
            "Gmail's sender verification results were not found for this message.",
        )]

    results: dict[str, set[str]] = {"spf": set(), "dkim": set(), "dmarc": set()}
    for method, result in _RESULT.findall(header):
        results[method.lower()].add(result.lower())

    spf, dkim, dmarc = results["spf"], results["dkim"], results["dmarc"]
    findings: list[Finding] = []
    from_domain = email.from_addr.domain if email.from_addr else ""

    if "fail" in dmarc:
        findings.append(Finding(
            "auth.dmarc_fail", Category.AUTH, Severity.HIGH,
            "Sender failed DMARC verification",
            f"The email claims to come from {from_domain or 'a domain'}, but that domain's own "
            "policy says this message was not sent by them. This is a classic sign of spoofing.",
            (f"dmarc={'/'.join(sorted(dmarc))}",),
        ))

    if "fail" in spf:
        findings.append(Finding(
            "auth.spf_fail", Category.AUTH, Severity.MEDIUM,
            "Sending server is not authorized (SPF fail)",
            "The server that delivered this email is not on the sender domain's list of allowed servers.",
            ("spf=fail",),
        ))
    elif "softfail" in spf:
        findings.append(Finding(
            "auth.spf_softfail", Category.AUTH, Severity.LOW,
            "Sending server is not clearly authorized (SPF softfail)",
            "The sender domain does not fully vouch for the server that delivered this email.",
            ("spf=softfail",),
        ))

    if dkim and "pass" not in dkim and dkim & {"fail", "permerror", "neutral"}:
        findings.append(Finding(
            "auth.dkim_fail", Category.AUTH, Severity.MEDIUM,
            "Email signature is invalid (DKIM fail)",
            "The message's cryptographic signature does not check out, so it may have been forged or altered.",
            (f"dkim={'/'.join(sorted(dkim))}",),
        ))

    nothing_passed = "pass" not in spf and "pass" not in dkim and "pass" not in dmarc
    if nothing_passed and "fail" not in dmarc:
        findings.append(Finding(
            "auth.unverified", Category.AUTH, Severity.MEDIUM,
            "Sender identity could not be verified",
            "None of the standard checks (SPF, DKIM, DMARC) confirmed who sent this email.",
        ))

    if "pass" in dmarc:
        match = _HEADER_FROM.search(header)
        aligned_domain = match.group(1).lower() if match else ""
        if from_domain and registrable_domain(aligned_domain) == registrable_domain(from_domain):
            findings.append(Finding(
                "auth.verified", Category.AUTH, Severity.TRUST,
                f"Sender verified as {registrable_domain(from_domain)}",
                "The email really comes from the domain shown in the From address (DMARC pass). "
                "This lowers the risk, but does not prove the domain itself is trustworthy.",
                ("dmarc=pass",),
                trust_weight=0.35,
            ))

    return findings
