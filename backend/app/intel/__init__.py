"""Runs all external threat-intelligence checks in parallel.

Each check has its own timeout and failure handling: if VirusTotal is down
or a key is missing, that check reports "unavailable" or "not configured"
and the rest of the analysis is unaffected.
"""

import asyncio
import logging

import httpx

from app.analyzers.base import Finding
from app.config import Settings, get_settings
from app.intel import llm, rdap, safebrowsing, urlhaus, virustotal
from app.intel.base import CheckStatus, IntelError, NotConfigured, Skipped
from app.parsing import ParsedEmail

logger = logging.getLogger(__name__)

PROVIDERS = (safebrowsing, urlhaus, virustotal, rdap, llm)
# Identify ourselves honestly; some services reject anonymous default clients.
USER_AGENT = "mail-scorer/1.0 (Gmail add-on security analysis)"


async def _run_one(provider, email: ParsedEmail, client: httpx.AsyncClient, settings: Settings):
    timeout = settings.llm_timeout if provider is llm else settings.intel_timeout
    try:
        result = await asyncio.wait_for(provider.check(email, client, settings), timeout=timeout + 1)
        return result.findings, CheckStatus(provider.NAME, "ok", result.detail)
    except NotConfigured:
        return [], CheckStatus(provider.NAME, "not_configured")
    except Skipped:
        return [], CheckStatus(provider.NAME, "skipped")
    except asyncio.TimeoutError:
        return [], CheckStatus(provider.NAME, "unavailable", "timed out")
    except IntelError as exc:
        # IntelError messages are written by us ("HTTP 403") and never contain
        # email data, so they are safe to log and to show.
        logger.warning("%s check failed: %s", provider.NAME, exc)
        return [], CheckStatus(provider.NAME, "unavailable", str(exc))
    except httpx.HTTPError as exc:
        # httpx messages can include the URL; log and show the error type only.
        logger.warning("%s check failed: %s", provider.NAME, type(exc).__name__)
        return [], CheckStatus(provider.NAME, "unavailable", type(exc).__name__)
    except Exception:
        logger.exception("%s check crashed", provider.NAME)
        return [], CheckStatus(provider.NAME, "unavailable", "internal error")


async def run_intel(
    email: ParsedEmail, client: httpx.AsyncClient | None = None, settings: Settings | None = None
) -> tuple[list[Finding], list[CheckStatus]]:
    settings = settings or get_settings()
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=settings.intel_timeout, follow_redirects=False,
                                         headers={"User-Agent": USER_AGENT})
    try:
        results = await asyncio.gather(*(_run_one(p, email, client, settings) for p in PROVIDERS))
    finally:
        if own_client:
            await client.aclose()
    findings = [f for found, _ in results for f in found]
    return findings, [status for _, status in results]
