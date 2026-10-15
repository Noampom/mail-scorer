"""Request and response schemas.

Everything in the request is attacker-controlled (it comes from an email),
so every field has a hard size limit and a strict type.
"""

from pydantic import BaseModel, Field

MAX_HEADERS_CHARS = 64_000
MAX_TEXT_CHARS = 100_000
MAX_HTML_CHARS = 300_000
MAX_ATTACHMENTS = 30


class AttachmentIn(BaseModel):
    name: str = Field(default="", max_length=300)
    content_type: str = Field(default="", max_length=200)
    size: int = Field(default=0, ge=0)
    # Hash only: file contents never leave the user's mailbox.
    sha256: str = Field(default="", pattern=r"^([a-f0-9]{64})?$")


class EmailPayload(BaseModel):
    raw_headers: str = Field(default="", max_length=MAX_HEADERS_CHARS)
    subject: str = Field(default="", max_length=2_000)
    body_text: str = Field(default="", max_length=MAX_TEXT_CHARS)
    body_html: str = Field(default="", max_length=MAX_HTML_CHARS)
    attachments: list[AttachmentIn] = Field(default_factory=list, max_length=MAX_ATTACHMENTS)


class FindingOut(BaseModel):
    id: str
    category: str
    severity: str
    title: str
    explanation: str
    evidence: list[str]
    tip: str = ""


class CheckOut(BaseModel):
    name: str
    status: str  # ok | unavailable | not_configured | skipped
    detail: str = ""


class AnalyzeResponse(BaseModel):
    score: int
    verdict: str
    level: str  # safe | suspicious | likely_malicious | malicious
    summary: str
    findings: list[FindingOut]
    category_scores: dict[str, int]
    gauge_path: str  # relative to the backend URL; contains only the score
    report_path: str  # unguessable, expires after 30 minutes
    checks: list[CheckOut]  # status of each external threat-intel check
