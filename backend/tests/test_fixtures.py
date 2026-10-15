"""Regression tests on complete .eml files (the same 7 emails the demo seeder inserts).

Each file is converted the way the Gmail add-on extracts a message, scored
end to end through the API, and checked against its expected verdict.
"""

import email
import hashlib
from email import policy
from pathlib import Path

import pytest

from tests.test_api import client

FIXTURES = Path(__file__).parent / "fixtures" / "emails"
EXPECTED = {
    "01_paypal_lookalike.eml": "malicious",
    "02_ceo_gift_cards.eml": "likely_malicious",
    "03_sextortion_bitcoin.eml": "malicious",
    "04_dhl_attachments.eml": "malicious",
    "05_microsoft_prompt_injection.eml": "likely_malicious",
    "06_hebrew_bank_leumi.eml": "likely_malicious",
    "07_legit_meeting_notes.eml": "safe",
}


def to_payload(path: Path) -> dict:
    """Mirror the add-on: raw header block, plain and HTML bodies, attachment metadata."""
    raw = path.read_text(encoding="utf-8")
    message = email.message_from_string(raw, policy=policy.default)
    plain, html = message.get_body(("plain",)), message.get_body(("html",))
    attachments = []
    for part in message.iter_attachments():
        content = part.get_content()
        data = content if isinstance(content, bytes) else content.encode()
        attachments.append({"name": part.get_filename(), "content_type": part.get_content_type(),
                            "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return {
        "raw_headers": raw.replace("\r\n", "\n").split("\n\n", 1)[0],
        "subject": str(message["Subject"]),
        "body_text": plain.get_content() if plain else "",
        "body_html": html.get_content() if html else "",
        "attachments": attachments,
    }


@pytest.mark.parametrize("name,level", sorted(EXPECTED.items()))
def test_fixture_verdict(name, level):
    response = client.post("/analyze", json=to_payload(FIXTURES / name), headers={"X-Api-Key": "test-key"})
    assert response.status_code == 200
    result = response.json()
    assert result["level"] == level, (name, result["score"], result["summary"])


def test_every_fixture_has_an_expectation():
    assert {p.name for p in FIXTURES.glob("*.eml")} == set(EXPECTED)
