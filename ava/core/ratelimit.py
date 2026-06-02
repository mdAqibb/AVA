"""Thread-safe token-bucket rate limiter and a global request cap.

Both live behind the single HTTP client so politeness limits cannot be
bypassed by any individual check module.
"""

from __future__ import annotations

import threading
import time


class TokenBucket:
    """Classic token bucket. `rate` tokens/sec, burst up to `capacity`."""

    def __init__(self, rate: float, capacity: float | None = None):
        self.rate = float(rate)
        self.capacity = float(capacity if capacity is not None else max(1.0, rate))
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> None:
        """Block until `tokens` are available, then consume them."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                deficit = tokens - self._tokens
                wait = deficit / self.rate
            time.sleep(wait)


class GlobalCap:
    """Hard ceiling on total requests for a run. Raises when exceeded."""

    def __init__(self, max_requests: int):
        self.max_requests = max_requests
        self._count = 0
        self._lock = threading.Lock()

    def increment(self) -> int:
        with self._lock:
            if self._count >= self.max_requests:
                raise GlobalCapReached(self.max_requests)
            self._count += 1
            return self._count

    @property
    def count(self) -> int:
        with self._lock:
            return self._count


class GlobalCapReached(RuntimeError):
    def __init__(self, cap: int):
        super().__init__(f"Global request cap reached ({cap}); halting to stay polite.")
        self.cap = cap
