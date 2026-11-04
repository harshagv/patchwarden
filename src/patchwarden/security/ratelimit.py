"""In-memory sliding-window rate limits (per process).

Used for the free scanner and for failed logins. With several app processes behind a load balancer
each keeps its own counts, so the effective limit is per process; a shared store (Redis) is listed
under Future ideas.
"""

from __future__ import annotations

import math
import threading
import time
from collections import deque

from fastapi import Request

from ..config import Settings
from ..errors import AppError


class SlidingWindow:
    def __init__(self, limit: int, window_seconds: int):
        self.limit, self.window = limit, window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        hits = self._hits.setdefault(key, deque())
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        return hits

    def retry_after(self, key: str, cost: int = 1, now: float | None = None) -> int:
        """0 if `cost` more hits fit in the window now, else the seconds to wait."""
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._prune(key, now)
            if len(hits) + cost <= self.limit:
                return 0
            if cost > self.limit:
                return self.window
            # Wait until enough old hits have left the window.
            oldest_needed = hits[len(hits) + cost - self.limit - 1]
            return max(1, math.ceil(oldest_needed + self.window - now))

    def hit(self, key: str, cost: int = 1, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = self._prune(key, now)
            hits.extend([now] * cost)
            if len(self._hits) > 100_000:  # bound memory: forget idle keys
                for k in [k for k, v in self._hits.items() if not v][:50_000]:
                    del self._hits[k]


def client_ip(request: Request, settings: Settings) -> str:
    """The caller's address. X-Forwarded-For is trusted only from configured proxies."""
    peer = request.client.host if request.client else "unknown"
    if peer in settings.trusted_proxies:
        forwarded = [h.strip() for h in request.headers.get("x-forwarded-for", "").split(",") if h.strip()]
        # Walk from the right: the first address that is not one of our proxies is the client.
        for hop in reversed(forwarded):
            if hop not in settings.trusted_proxies:
                return hop
    return peer


def too_many(message: str, retry_after: int) -> AppError:
    return AppError(429, "rate_limited", message, headers={"Retry-After": str(retry_after)})


class Limits:
    def __init__(self, settings: Settings):
        self.scan_ip = SlidingWindow(settings.scan_rate_limit, settings.scan_rate_window)
        self.scan_user = SlidingWindow(settings.scan_rate_limit_user, settings.scan_rate_window)
        self.login = SlidingWindow(settings.login_failure_limit, settings.login_failure_window)
        self.signup = SlidingWindow(settings.signup_limit, 3600)
