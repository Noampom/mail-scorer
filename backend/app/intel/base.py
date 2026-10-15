"""Shared plumbing for external threat-intelligence checks.

External services are untrusted too: their responses are size-limited,
parsed defensively and validated before anything reaches the user.
"""

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from app.analyzers.base import Finding
from app.parsing import ParsedEmail

MAX_RESPONSE_BYTES = 1_000_000
MAX_URLS = 50


class IntelError(Exception):
    """A check could not complete (network, quota, bad response)."""


class NotConfigured(Exception):
    """The check's API key is not set."""


class Skipped(Exception):
    """The check was turned off by configuration."""


@dataclass(frozen=True)
class CheckStatus:
    name: str
    status: str  # ok | unavailable | not_configured | skipped
    detail: str = ""


@dataclass
class IntelResult:
    findings: list[Finding] = field(default_factory=list)
    detail: str = ""


class TTLCache:
    """Tiny thread-safe in-memory cache, so reopening an email costs no quota."""

    def __init__(self, ttl_seconds: float, max_items: int = 5_000):
        self._ttl = ttl_seconds
        self._max = max_items
        self._items: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> tuple[bool, Any]:
        with self._lock:
            item = self._items.get(key)
            if item is None or item[0] <= time.monotonic():
                self._items.pop(key, None)
                return False, None
            return True, item[1]

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if len(self._items) >= self._max:
                self._items.pop(next(iter(self._items)))  # drop the oldest
            self._items[key] = (time.monotonic() + self._ttl, value)


def read_json(response: httpx.Response) -> Any:
    """Parse a response body as JSON, refusing oversized or malformed data."""
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise IntelError("response too large")
    try:
        return json.loads(response.content)
    except ValueError as exc:
        raise IntelError("invalid JSON") from exc


def email_urls(email: ParsedEmail, limit: int = MAX_URLS) -> list[str]:
    """Unique http(s) URLs from the email, in order of appearance."""
    seen: list[str] = []
    for link in email.links:
        if link.scheme in {"http", "https"} and link.host and link.href not in seen:
            seen.append(link.href)
        if len(seen) == limit:
            break
    return seen
