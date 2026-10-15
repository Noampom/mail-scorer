"""Combines findings into a 0-100 score and a verdict.

The model, in four rules (also documented in the README):

1. Each finding has a weight from its severity (low 0.10 ... critical 0.80),
   read as "how likely this signal alone means the email is malicious".
2. Findings combine like independent pieces of evidence (noisy-OR):
   risk = 1 - Π(1 - wᵢ). Two strong signals reinforce each other, but the
   score can never exceed 100.
3. Diminishing returns: the i-th strongest finding is damped by 0.75^i,
   so ten weak signals cannot add up to "malicious" on their own.
4. Trust and overrides: verified-sender findings lower the risk, but only
   when nothing serious was found (attackers can verify their own look-alike
   domains). A single critical finding sets a floor of 80.
"""

from app.analyzers.base import Category, Finding, Severity

DECAY = 0.75
CRITICAL_FLOOR = 0.80
SEVERITY_RANK = {
    Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
    Severity.LOW: 2, Severity.INFO: 1, Severity.TRUST: 0,
}
VERDICTS = (  # (minimum score, level, label)
    (80, "malicious", "Malicious"),
    (50, "likely_malicious", "Likely malicious"),
    (20, "suspicious", "Suspicious"),
    (0, "safe", "Looks safe"),
)


def combine(weights: list[float]) -> float:
    remaining = 1.0
    for i, weight in enumerate(sorted(weights, reverse=True)):
        remaining *= 1.0 - weight * (DECAY ** i)
    return 1.0 - remaining


def compute_score(findings: list[Finding]) -> int:
    risk = combine([f.weight for f in findings if f.weight > 0])

    serious = any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)
    if not serious:
        for finding in findings:
            if finding.severity is Severity.TRUST:
                risk *= 1.0 - finding.trust_weight

    if any(f.severity is Severity.CRITICAL for f in findings):
        risk = max(risk, CRITICAL_FLOOR)
    return round(risk * 100)


def category_scores(findings: list[Finding]) -> dict[str, int]:
    return {
        category.value: round(combine([f.weight for f in findings if f.category is category and f.weight > 0]) * 100)
        for category in Category
    }


def verdict_for(score: int) -> tuple[str, str]:
    for minimum, level, label in VERDICTS:
        if score >= minimum:
            return level, label
    return VERDICTS[-1][1], VERDICTS[-1][2]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_RANK[f.severity], reverse=True)


def summarize(level: str, findings: list[Finding]) -> str:
    risky = [f for f in findings if f.weight > 0]
    if not risky:
        return "No warning signs were found in this email."
    top = sort_findings(risky)[0]
    others = len(risky) - 1
    tail = f" and {others} other warning sign{'s' if others != 1 else ''}" if others else ""
    if level == "safe":
        return f"Only minor signals found: {top.title.lower()}{tail}."
    return f"{top.title}{tail}."
