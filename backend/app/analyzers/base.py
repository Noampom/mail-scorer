"""Shared types for all analyzers.

Every analyzer returns a list of Finding objects in the same shape, so the
scoring engine and the UI never need to know which analyzer produced what.
"""

from dataclasses import dataclass, field
from enum import Enum


class Category(str, Enum):
    AUTH = "authentication"
    SENDER = "sender"
    LINKS = "links"
    CONTENT = "content"
    ATTACHMENTS = "attachments"


class Severity(str, Enum):
    TRUST = "trust"  # a mitigating signal: lowers the score
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# How strongly each severity pushes the score up (0..1, probability-like).
SEVERITY_WEIGHT = {
    Severity.INFO: 0.0,
    Severity.LOW: 0.10,
    Severity.MEDIUM: 0.25,
    Severity.HIGH: 0.45,
    Severity.CRITICAL: 0.80,
}

MAX_EVIDENCE = 3


@dataclass(frozen=True)
class Finding:
    id: str
    category: Category
    severity: Severity
    title: str
    explanation: str
    evidence: tuple[str, ...] = field(default_factory=tuple)
    # Only used for TRUST findings: how much they reduce the risk (0..1).
    trust_weight: float = 0.0

    @property
    def weight(self) -> float:
        return SEVERITY_WEIGHT.get(self.severity, 0.0)


def make_evidence(items) -> tuple[str, ...]:
    """Deduplicate, cap and length-limit evidence strings for display."""
    seen: list[str] = []
    for item in items:
        text = str(item)[:120]
        if text and text not in seen:
            seen.append(text)
        if len(seen) == MAX_EVIDENCE:
            break
    return tuple(seen)
