"""End-to-end tests through the HTTP API, including the security controls."""

import httpx
from fastapi.testclient import TestClient

from app.main import app, http_client
from tests.conftest import make_headers


async def offline_client():
    """Every outbound call gets a 404, so API tests never touch the network."""
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(404))) as c:
        yield c


app.dependency_overrides[http_client] = offline_client
client = TestClient(app)
AUTH = {"X-Api-Key": "test-key"}


def analyze(**body):
    response = client.post("/analyze", json=body, headers=AUTH)
    assert response.status_code == 200, response.text
    return response.json()


def test_health_is_public():
    assert client.get("/health").json() == {"status": "ok"}


def test_requires_api_key():
    assert client.post("/analyze", json={}).status_code == 401
    assert client.post("/analyze", json={}, headers={"X-Api-Key": "wrong"}).status_code == 401


def test_rejects_oversized_request():
    response = client.post("/analyze", content=b"x" * 2_000_001, headers={**AUTH, "Content-Type": "application/json"})
    assert response.status_code == 413


def test_rejects_invalid_fields():
    response = client.post("/analyze", json={"attachments": [{"sha256": "not-a-hash"}]}, headers=AUTH)
    assert response.status_code == 422


def test_legit_verified_email_is_safe():
    result = analyze(
        raw_headers=make_headers(from_="Google <no-reply@accounts.google.com>"),
        subject="Security alert",
        body_text="clasp was granted access to your Google Account. If you did not grant access, check this activity.",
    )
    assert result["level"] == "safe"
    assert result["score"] < 20


def test_classic_phishing_is_malicious():
    result = analyze(
        raw_headers=make_headers(from_='"PayPal Security" <alerts@paypa1-support.com>', spf="softfail", dmarc="none"),
        subject="Urgent: your account has been suspended",
        body_html=('<p>We noticed unusual sign-in activity. Verify your account immediately '
                   'or your account will be closed.</p>'
                   '<a href="http://paypa1-support.com/login">https://www.paypal.com/signin</a>'),
    )
    assert result["level"] == "malicious", result
    assert result["findings"][0]["severity"] == "high"


def test_executable_attachment_forces_high_score():
    result = analyze(raw_headers=make_headers(), attachments=[{"name": "scan.exe", "content_type": "application/x-msdownload"}])
    assert result["score"] >= 80


def test_many_weak_signals_stay_below_malicious():
    result = analyze(
        raw_headers=make_headers(),
        body_text="Act now! Last chance! https://bit.ly/x https://tinyurl.com/y great-deals.xyz",
        body_html='<a href="https://deals.xyz/a">deals</a>',
    )
    assert result["score"] < 50


def test_response_shape():
    result = analyze(raw_headers=make_headers())
    assert set(result) == {"score", "verdict", "level", "summary", "findings", "category_scores",
                           "gauge_path", "report_path", "checks"}
    statuses = {c["name"]: c["status"] for c in result["checks"]}
    assert statuses["VirusTotal"] == "not_configured"  # no key in tests
    assert set(result["category_scores"]) == {"authentication", "sender", "links", "content", "attachments"}
    assert result["gauge_path"] == f"/gauge/{result['score']}.gif"


def test_findings_include_tips():
    result = analyze(raw_headers=make_headers(), attachments=[{"name": "scan.exe"}])
    assert result["findings"][0]["tip"]


# --- gauge image ------------------------------------------------------------

def test_gauge_is_a_public_gif():
    response = client.get("/gauge/42.gif")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/gif"
    assert response.content[:6] == b"GIF89a"


def test_gauge_rejects_out_of_range_scores():
    assert client.get("/gauge/101.gif").status_code == 404
    assert client.get("/gauge/-1.gif").status_code in (404, 422)
    assert client.get("/gauge/abc.gif").status_code in (404, 422)


# --- report page ------------------------------------------------------------

def test_report_page_and_security_headers():
    result = analyze(raw_headers=make_headers(), subject="Quarterly report")
    response = client.get(result["report_path"])
    assert response.status_code == 200
    assert "Quarterly report" in response.text
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "script" not in csp
    assert response.headers["cache-control"] == "no-store"
    assert "<script" not in response.text


def test_report_escapes_email_content():
    attack = '<script>alert(1)</script><img src=x onerror=alert(2)>'
    result = analyze(raw_headers=make_headers(), subject=attack)
    page = client.get(result["report_path"]).text
    assert "<script>alert" not in page and "<img src=x" not in page
    assert "&lt;script&gt;" in page


def test_unknown_or_malformed_report_token():
    assert client.get("/report/" + "a" * 32).status_code == 404
    assert client.get("/report/../../etc/passwd").status_code == 404
    assert "expired" in client.get("/report/short").text


def test_report_expires():
    from app.report_store import ReportStore
    store = ReportStore(ttl=0)
    token = store.put({"x": 1})
    assert store.get(token) is None
