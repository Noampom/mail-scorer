"""Google Safe Browsing (Lookup API v4): is a link on Google's list of dangerous sites?

Privacy note: the Lookup API sends full URLs to Google. The Update API
(local hash-prefix lists) would avoid that; it is listed as future work.
"""

import httpx

from app.analyzers.base import Category, Finding, Severity, make_evidence
from app.analyzers.links import defang
from app.config import Settings
from app.intel.base import IntelError, IntelResult, NotConfigured, TTLCache, email_urls, read_json
from app.parsing import ParsedEmail

NAME = "Google Safe Browsing"
ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
THREAT_LABELS = {
    "MALWARE": "malware", "SOCIAL_ENGINEERING": "phishing",
    "UNWANTED_SOFTWARE": "unwanted software", "POTENTIALLY_HARMFUL_APPLICATION": "harmful app",
}
_cache = TTLCache(ttl_seconds=30 * 60)  # url -> threat type or None


async def check(email: ParsedEmail, client: httpx.AsyncClient, settings: Settings) -> IntelResult:
    if not settings.safe_browsing_key:
        raise NotConfigured
    urls = email_urls(email)
    if not urls:
        return IntelResult(detail="no links")

    verdicts: dict[str, str | None] = {}
    unknown = []
    for url in urls:
        hit, value = _cache.get(url)
        if hit:
            verdicts[url] = value
        else:
            unknown.append(url)

    if unknown:
        response = await client.post(
            ENDPOINT,
            # Key in a header, not the URL, so it never appears in request logs.
            headers={"x-goog-api-key": settings.safe_browsing_key},
            json={
                "client": {"clientId": "mail-scorer", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": THREAT_TYPES,
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url} for url in unknown],
                },
            },
        )
        if response.status_code != 200:
            raise IntelError(f"HTTP {response.status_code}")
        data = read_json(response)
        matches = data.get("matches", []) if isinstance(data, dict) else []
        found = {}
        for match in matches if isinstance(matches, list) else []:
            url = (match.get("threat") or {}).get("url") if isinstance(match, dict) else None
            if url in unknown:
                found[url] = str(match.get("threatType", "MALWARE"))
        for url in unknown:
            verdicts[url] = found.get(url)
            _cache.set(url, verdicts[url])

    bad = [(url, threat) for url, threat in verdicts.items() if threat]
    if not bad:
        return IntelResult(detail=f"{len(urls)} link{'s' if len(urls) != 1 else ''} clean")
    return IntelResult([Finding(
        "links.safe_browsing", Category.LINKS, Severity.CRITICAL,
        "Link is on Google's list of dangerous sites",
        "Google Safe Browsing has flagged a link in this email as dangerous. Do not open it.",
        make_evidence(f"{defang(url)} ({THREAT_LABELS.get(threat, threat.lower())})" for url, threat in bad),
    )], detail=f"{len(bad)} dangerous link(s)")
