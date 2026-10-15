"""Mail Scorer backend - phase 1 skeleton.

Every request except /health must carry the shared API key in the
X-Api-Key header. The key lives only in Secret Manager (prod) or an
environment variable (local dev), never in source control.
"""

import hmac
import os

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

# Docs endpoints are disabled: the API is private to the add-on.
app = FastAPI(title="Mail Scorer API", docs_url=None, redoc_url=None, openapi_url=None)


def require_api_key(x_api_key: str = Header(default="")) -> None:
    expected = os.environ.get("API_KEY", "")
    # Fail closed if the server is misconfigured; compare in constant time.
    if not expected or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


class AnalyzeRequest(BaseModel):
    # Hard size limits: email content is untrusted input.
    subject: str = Field(default="", max_length=1_000)
    sender: str = Field(default="", max_length=500)


class AnalyzeResponse(BaseModel):
    score: int
    verdict: str
    reasons: list[str]


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(require_api_key)])
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    # Placeholder until the analyzers exist (phase 3).
    return AnalyzeResponse(
        score=0,
        verdict="Not analyzed yet",
        reasons=["Backend connection works. Analyzers come in phase 3."],
    )
