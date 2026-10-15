"""Mail Scorer backend API.

Every request except /health must carry the shared API key in the
X-Api-Key header. The key lives only in Secret Manager (prod) or an
environment variable (local dev), never in source control.
"""

import hmac
import logging
import os

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.analyzers import run_all
from app.models import AnalyzeResponse, EmailPayload, FindingOut
from app.parsing import parse_email
from app.scoring import category_scores, compute_score, sort_findings, summarize, verdict_for

logging.basicConfig(level=logging.INFO)

MAX_REQUEST_BYTES = 2_000_000  # Hebrew text is 2 bytes per character in UTF-8

# Docs endpoints are disabled: the API is private to the add-on.
app = FastAPI(title="Mail Scorer API", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    # Reject oversized bodies before parsing them.
    length = request.headers.get("content-length")
    if length is None and request.method == "POST":
        return JSONResponse({"detail": "Content-Length required"}, status_code=411)
    if length is not None and (not length.isdigit() or int(length) > MAX_REQUEST_BYTES):
        return JSONResponse({"detail": "Request too large"}, status_code=413)
    return await call_next(request)


def require_api_key(x_api_key: str = Header(default="")) -> None:
    expected = os.environ.get("API_KEY", "")
    # Fail closed if the server is misconfigured; compare in constant time.
    if not expected or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(require_api_key)])
def analyze(payload: EmailPayload) -> AnalyzeResponse:
    email = parse_email(payload)
    findings = sort_findings(run_all(email))
    score = compute_score(findings)
    level, verdict = verdict_for(score)
    return AnalyzeResponse(
        score=score,
        verdict=verdict,
        level=level,
        summary=summarize(level, findings),
        findings=[
            FindingOut(
                id=f.id, category=f.category.value, severity=f.severity.value,
                title=f.title, explanation=f.explanation, evidence=list(f.evidence),
            )
            for f in findings
        ],
        category_scores=category_scores(findings),
    )
