"""URLhaus (abuse.ch): is a link a known malware distribution URL?"""

import asyncio

import httpx

from app.analyzers.base import Category, Finding, Severity, make_evidence
from app.analyzers.links import defang
from app.config import Settings
from app.intel.base import IntelError, IntelResult, NotConfigured, TTLCache, email_urls, read_json
from app.parsing import ParsedEmail

NAME = "URLhaus"
ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
MAX_LOOKUPS = 10
_cache = TTLCache(ttl_seconds=30 * 60)  # url -> (url_status, threat) or None


async def _lookup(client: httpx.AsyncClient, key: str, url: str):
    hit, value = _cache.get(url)
    if hit:
        return value
    response = await client.post(ENDPOINT, data={"url": url}, headers={"Auth-Key": key})
    if response.status_code != 200:
        raise IntelError(f"HTTP {response.status_code}")
    data = read_json(response)
    if not isinstance(data, dict):
        raise IntelError("unexpected response")
    value = None
    if data.get("query_status") == "ok":
        value = (str(data.get("url_status", "unknown")), str(data.get("threat", "malware")))
    elif data.get("query_status") != "no_results":
        raise IntelError("query failed")
    _cache.set(url, value)
    return value


async def check(email: ParsedEmail, client: httpx.AsyncClient, settings: Settings) -> IntelResult:
    if not settings.urlhaus_key:
        raise NotConfigured
    urls = email_urls(email, limit=MAX_LOOKUPS)
    if not urls:
        return IntelResult(detail="no links")
    results = await asyncio.gather(*(_lookup(client, settings.urlhaus_key, url) for url in urls))
    bad = [(url, value) for url, value in zip(urls, results) if value]
    if not bad:
        return IntelResult(detail=f"{len(urls)} link{'s' if len(urls) != 1 else ''} clean")

    online = any(status == "online" for _, (status, _) in bad)
    return IntelResult([Finding(
        "links.urlhaus", Category.LINKS, Severity.CRITICAL if online else Severity.HIGH,
        "Link is a known malware download site",
        "URLhaus, a public database of malware distribution sites, lists a link in this email"
        + (" and reports it is still active." if online else "."),
        make_evidence(f"{defang(url)} ({status}, {threat.replace('_', ' ')})" for url, (status, threat) in bad),
    )], detail=f"{len(bad)} malware link(s)")
