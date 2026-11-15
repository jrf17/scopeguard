"""A thread-safe interval limiter. One wait per network action."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable


class RateLimiter:
    def __init__(
        self,
        requests_per_second: float,
        *,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if requests_per_second <= 0:
            raise ValueError("rate must be positive")
        self._interval = 1.0 / requests_per_second
        self._sleep = sleep
        self._monotonic = monotonic
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        with self._lock:
            now = self._monotonic()
            delay = self._next - now
            if delay > 0:
                self._sleep(delay)
                now = self._monotonic()
            self._next = max(self._next, now) + self._interval
