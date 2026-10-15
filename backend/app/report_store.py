"""Short-lived storage for full reports, addressed by unguessable tokens.

Kept in memory on purpose: reports contain short excerpts of the email
(addresses, phrases, defanged links), so they expire after 30 minutes and
are never written to disk. Trade-off: reports are lost when the Cloud Run
instance restarts or scales out. In production this would be a managed
store with TTL (e.g. Firestore or Redis), still with short expiry.
"""

import secrets
import threading
import time
from collections import OrderedDict

TTL_SECONDS = 30 * 60
MAX_REPORTS = 500


class ReportStore:
    def __init__(self, ttl: int = TTL_SECONDS, max_items: int = MAX_REPORTS):
        self._ttl = ttl
        self._max = max_items
        self._items: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._lock = threading.Lock()

    def put(self, report: dict) -> str:
        token = secrets.token_urlsafe(24)  # 192 bits: cannot be guessed
        with self._lock:
            self._purge()
            self._items[token] = (time.monotonic() + self._ttl, report)
            while len(self._items) > self._max:
                self._items.popitem(last=False)  # evict the oldest
        return token

    def get(self, token: str) -> dict | None:
        with self._lock:
            self._purge()
            item = self._items.get(token)
            return item[1] if item else None

    def _purge(self) -> None:
        now = time.monotonic()
        expired = [token for token, (expires, _) in self._items.items() if expires <= now]
        for token in expired:
            del self._items[token]


reports = ReportStore()
