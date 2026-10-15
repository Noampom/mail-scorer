"""End-to-end tests through the HTTP API, including the security controls."""

from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import make_headers

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
    assert set(result) == {"score", "verdict", "level", "summary", "findings", "category_scores"}
    assert set(result["category_scores"]) == {"authentication", "sender", "links", "content", "attachments"}
