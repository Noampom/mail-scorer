import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("API_KEY", "test-key")
# Tests never use real threat-intel keys or the network.
for _name in ("SAFE_BROWSING_API_KEY", "VIRUSTOTAL_API_KEY", "URLHAUS_API_KEY", "GEMINI_API_KEY"):
    os.environ.pop(_name, None)

from app.models import AttachmentIn, EmailPayload  # noqa: E402


def make_headers(
    from_="Alice <alice@example.com>",
    reply_to=None,
    spf="pass",
    dkim="pass",
    dmarc="pass",
    dmarc_domain=None,
    extra="",
    authserv="mx.google.com",
) -> str:
    domain = dmarc_domain or from_.rsplit("@", 1)[-1].rstrip(">")
    lines = [
        f"Authentication-Results: {authserv};\r\n"
        f"       dkim={dkim} header.i=@{domain};\r\n"
        f"       spf={spf} smtp.mailfrom={domain};\r\n"
        f"       dmarc={dmarc} (p=REJECT) header.from={domain}",
        f"From: {from_}",
        "To: noam@example.com",
        "Subject: Test",
    ]
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    if extra:
        lines.append(extra)
    return "\r\n".join(lines)


@pytest.fixture
def payload():
    def build(headers=None, text="", html="", attachments=(), subject="Hello"):
        return EmailPayload(
            raw_headers=headers if headers is not None else make_headers(),
            subject=subject,
            body_text=text,
            body_html=html,
            attachments=[AttachmentIn(name=a) if isinstance(a, str) else a for a in attachments],
        )
    return build


@pytest.fixture(autouse=True)
def clear_intel_caches():
    from app.intel import llm, rdap, safebrowsing, urlhaus, virustotal
    for module in (llm, rdap, safebrowsing, urlhaus, virustotal):
        module._cache._items.clear()
    rdap._bootstrap_cache._items.clear()
    yield
