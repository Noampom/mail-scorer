"""VirusTotal: is an attachment known malware?

Only the SHA-256 hash is sent. The file itself never leaves the mailbox,
so private documents are never uploaded to a third party.
"""

import asyncio

import httpx

from app.analyzers.base import Category, Finding, Severity, make_evidence
from app.config import Settings
from app.intel.base import IntelError, IntelResult, NotConfigured, TTLCache, read_json
from app.parsing import ParsedEmail

NAME = "VirusTotal"
ENDPOINT = "https://www.virustotal.com/api/v3/files/{}"
MAX_LOOKUPS = 4  # the free API allows 4 requests per minute
MALICIOUS_THRESHOLD = 3  # engines; one or two detections are often false positives
_cache = TTLCache(ttl_seconds=6 * 60 * 60)  # sha256 -> (malicious, total) or None


async def _lookup(client: httpx.AsyncClient, key: str, sha256: str):
    hit, value = _cache.get(sha256)
    if hit:
        return value
    response = await client.get(ENDPOINT.format(sha256), headers={"x-apikey": key})
    if response.status_code == 404:
        value = None  # never seen by VirusTotal
    elif response.status_code == 200:
        data = read_json(response)
        try:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            total = sum(int(v) for v in stats.values() if isinstance(v, int))
        except (KeyError, TypeError, ValueError) as exc:
            raise IntelError("unexpected response") from exc
        value = (malicious, total)
    else:
        raise IntelError(f"HTTP {response.status_code}")  # 429 = quota exhausted
    _cache.set(sha256, value)
    return value


async def check(email: ParsedEmail, client: httpx.AsyncClient, settings: Settings) -> IntelResult:
    if not settings.virustotal_key:
        raise NotConfigured
    files = [a for a in email.attachments if a.sha256][:MAX_LOOKUPS]
    if not files:
        return IntelResult(detail="no attachments")
    results = await asyncio.gather(*(_lookup(client, settings.virustotal_key, f.sha256) for f in files))

    findings = []
    known_bad = [(f.name, r) for f, r in zip(files, results) if r and r[0] >= MALICIOUS_THRESHOLD]
    some_hits = [(f.name, r) for f, r in zip(files, results) if r and 0 < r[0] < MALICIOUS_THRESHOLD]
    if known_bad:
        findings.append(Finding(
            "attachments.virustotal_malware", Category.ATTACHMENTS, Severity.CRITICAL,
            "Attachment is known malware",
            "Antivirus engines on VirusTotal have identified this exact file as malicious.",
            make_evidence(f"{name}: flagged by {m} of {t} engines" for name, (m, t) in known_bad),
        ))
    if some_hits:
        findings.append(Finding(
            "attachments.virustotal_flagged", Category.ATTACHMENTS, Severity.MEDIUM,
            "Attachment flagged by a few antivirus engines",
            "A small number of antivirus engines on VirusTotal consider this file suspicious.",
            make_evidence(f"{name}: flagged by {m} of {t} engines" for name, (m, t) in some_hits),
        ))
    unseen = sum(1 for r in results if r is None)
    return IntelResult(findings, detail=f"{len(files)} checked, {unseen} never seen before")
