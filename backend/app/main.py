"""Mail Scorer backend API.

Routes:
  GET  /health              liveness check (public)
  POST /analyze             score an email (requires X-Api-Key)
  GET  /gauge/{score}.gif   animated gauge image (public; depends only on the score)
  GET  /report/{token}      full report page (public; unguessable token, 30-minute expiry)

The API key lives only in Secret Manager (prod) or an environment
variable (local dev), never in source control.
"""

import hmac
import logging
import os
import re
from collections.abc import AsyncIterator

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response

from app.analyzers import run_all
from app.data.tips import TIPS
from app.config import get_settings
from app.gauge import render_gauge
from app.intel import USER_AGENT, run_intel
from app.models import AnalyzeResponse, CheckOut, EmailPayload, FindingOut
from app.parsing import parse_email
from app.report_page import SECURITY_HEADERS, render_expired, render_report
from app.report_store import reports
from app.scoring import category_scores, compute_score, sort_findings, summarize, verdict_for

logging.basicConfig(level=logging.INFO)

MAX_REQUEST_BYTES = 2_000_000  # Hebrew text is 2 bytes per character in UTF-8
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{32}$")

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


async def http_client() -> AsyncIterator[httpx.AsyncClient]:
    """Outbound client for threat-intel calls (overridden with a fake in tests)."""
    async with httpx.AsyncClient(timeout=get_settings().intel_timeout, follow_redirects=False,
                                 headers={"User-Agent": USER_AGENT}) as client:
        yield client


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(require_api_key)])
async def analyze(payload: EmailPayload, client: httpx.AsyncClient = Depends(http_client)) -> AnalyzeResponse:
    email = parse_email(payload)
    intel_findings, checks = await run_intel(email, client)
    findings = sort_findings(run_all(email) + intel_findings)
    score = compute_score(findings)
    level, verdict = verdict_for(score)
    findings_out = [
        FindingOut(
            id=f.id, category=f.category.value, severity=f.severity.value,
            title=f.title, explanation=f.explanation, evidence=list(f.evidence), tip=TIPS.get(f.id, ""),
        )
        for f in findings
    ]
    summary = summarize(level, findings)
    categories = category_scores(findings)
    checks_out = [CheckOut(name=c.name, status=c.status, detail=c.detail) for c in checks]

    token = reports.put({
        "subject": email.subject[:300],
        "sender": email.from_addr.email if email.from_addr else "",
        "score": score, "verdict": verdict, "level": level, "summary": summary,
        "findings": [f.model_dump() for f in findings_out], "category_scores": categories,
        "checks": [c.model_dump() for c in checks_out],
    })
    return AnalyzeResponse(
        score=score, verdict=verdict, level=level, summary=summary,
        findings=findings_out, category_scores=categories,
        gauge_path=f"/gauge/{score}.gif", report_path=f"/report/{token}", checks=checks_out,
    )


@app.get("/gauge/{score}.gif")
def gauge(score: int, static: bool = False) -> Response:
    if not 0 <= score <= 100:
        raise HTTPException(status_code=404)
    return Response(
        render_gauge(score, animated=not static), media_type="image/gif",
        headers={"Cache-Control": "public, max-age=86400", "X-Content-Type-Options": "nosniff"},
    )


@app.get("/report/{token}", response_class=HTMLResponse)
def report(token: str) -> HTMLResponse:
    data = reports.get(token) if _TOKEN.match(token) else None
    if data is None:
        return HTMLResponse(render_expired(), status_code=404, headers=SECURITY_HEADERS)
    return HTMLResponse(render_report(data), headers=SECURITY_HEADERS)
