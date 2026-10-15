"""Domain age via RDAP, the modern replacement for WHOIS.

Phishing domains are usually registered days before an attack. No API key
needed. We use IANA's official bootstrap file to find which registry serves
each domain ending, then ask that registry directly (no third-party relay).
Some country endings (e.g. .il) have no RDAP service; those are skipped.
"""

import asyncio
import re
from datetime import datetime, timezone

import httpx

from app.analyzers.base import Category, Finding, Severity, make_evidence
from app.config import Settings
from app.data.brands import BRANDS, FREE_MAIL_DOMAINS, URL_SHORTENERS
from app.domains import is_ip_address, registrable_domain
from app.intel.base import IntelError, IntelResult, TTLCache, read_json
from app.parsing import ParsedEmail

NAME = "Domain age (RDAP)"
BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
MAX_LOOKUPS = 5
VERY_NEW_DAYS = 7
NEW_DAYS = 30
# Strict check before a domain from the email is placed into a request URL.
_SAFE_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")
_WELL_KNOWN = frozenset().union(*BRANDS.values(), FREE_MAIL_DOMAINS, URL_SHORTENERS)
_cache = TTLCache(ttl_seconds=24 * 60 * 60)  # domain -> registration datetime or None
_bootstrap_cache = TTLCache(ttl_seconds=24 * 60 * 60)  # "map" -> {tld: base_url}


def _domains(email: ParsedEmail) -> list[tuple[str, bool]]:
    """(domain, is_sender) pairs worth checking, sender first."""
    candidates = []
    if email.from_addr and email.from_addr.domain:
        candidates.append((registrable_domain(email.from_addr.domain), True))
    for link in email.links:
        if link.host and not is_ip_address(link.host):
            candidates.append((registrable_domain(link.host), False))
    result, seen = [], set()
    for domain, is_sender in candidates:
        try:
            domain = domain.encode("idna").decode("ascii").lower()
        except UnicodeError:
            continue
        if domain in seen or domain in _WELL_KNOWN or not _SAFE_DOMAIN.match(domain):
            continue
        seen.add(domain)
        result.append((domain, is_sender))
    return result[:MAX_LOOKUPS]


async def _registry_map(client: httpx.AsyncClient) -> dict[str, str]:
    """{tld: registry RDAP base URL} from IANA's bootstrap file (cached for a day)."""
    hit, value = _bootstrap_cache.get("map")
    if hit:
        return value
    response = await client.get(BOOTSTRAP_URL, follow_redirects=True)
    if response.status_code != 200:
        raise IntelError(f"IANA bootstrap HTTP {response.status_code}")
    data = read_json(response)
    mapping: dict[str, str] = {}
    for service in data.get("services", []) if isinstance(data, dict) else []:
        if not (isinstance(service, list) and len(service) == 2):
            continue
        tlds, urls = service
        https_urls = [u for u in urls if isinstance(u, str) and u.startswith("https://")]
        if https_urls:
            base = https_urls[0] if https_urls[0].endswith("/") else https_urls[0] + "/"
            for tld in tlds:
                if isinstance(tld, str):
                    mapping[tld.lower()] = base
    if not mapping:
        raise IntelError("empty IANA bootstrap")
    _bootstrap_cache.set("map", mapping)
    return mapping


def _registration_date(data) -> datetime | None:
    events = data.get("events", []) if isinstance(data, dict) else []
    for event in events if isinstance(events, list) else []:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            try:
                return datetime.fromisoformat(str(event.get("eventDate", "")).replace("Z", "+00:00"))
            except ValueError:
                return None
    return None


async def _lookup(client: httpx.AsyncClient, base_url: str, domain: str) -> datetime | None:
    hit, value = _cache.get(domain)
    if hit:
        return value
    response = await client.get(f"{base_url}domain/{domain}", follow_redirects=True,
                                headers={"Accept": "application/rdap+json"})
    if response.status_code == 404:
        value = None  # not registered (or unknown to the registry)
    elif response.status_code == 200:
        value = _registration_date(read_json(response))
    else:
        raise IntelError(f"HTTP {response.status_code}")
    _cache.set(domain, value)
    return value


async def check(email: ParsedEmail, client: httpx.AsyncClient, settings: Settings) -> IntelResult:
    domains = _domains(email)
    if not domains:
        return IntelResult(detail="no unfamiliar domains")
    registries = await _registry_map(client)
    supported = [(d, s, registries[d.rsplit(".", 1)[-1]]) for d, s in domains if d.rsplit(".", 1)[-1] in registries]
    if not supported:
        return IntelResult(detail="domain ending has no RDAP service")

    results = await asyncio.gather(*(_lookup(client, base, d) for d, _, base in supported), return_exceptions=True)
    errors = [r for r in results if isinstance(r, Exception)]
    if len(errors) == len(results):
        first = errors[0]
        raise first if isinstance(first, IntelError) else IntelError(type(first).__name__)

    now = datetime.now(timezone.utc)
    young = {True: [], False: []}  # is_sender -> [(domain, days)]
    for (domain, is_sender, _), registered in zip(supported, results):
        if isinstance(registered, datetime):
            if registered.tzinfo is None:
                registered = registered.replace(tzinfo=timezone.utc)
            days = (now - registered).days
            if days <= NEW_DAYS:
                young[is_sender].append((domain, days))

    findings = []
    for is_sender, entries in young.items():
        if not entries:
            continue
        newest = min(days for _, days in entries)
        severity = Severity.HIGH if newest <= VERY_NEW_DAYS else Severity.MEDIUM
        where = "sender's domain" if is_sender else "domain a link points to"
        findings.append(Finding(
            "sender.new_domain" if is_sender else "links.new_domain",
            Category.SENDER if is_sender else Category.LINKS, severity,
            f"The {where} was registered very recently",
            "Phishing domains are typically registered just days before an attack. "
            "Established companies use domains that are years old.",
            make_evidence(f"{d}: registered {n} day{'s' if n != 1 else ''} ago" for d, n in entries),
        ))
    return IntelResult(findings, detail=f"{len(supported)} domain{'s' if len(supported) != 1 else ''} checked")
