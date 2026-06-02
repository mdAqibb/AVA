"""Small thread-pool helper for the phases that fan out over many requests.

The shared HttpClient (httpx-backed) is thread-safe, and the rate limiter /
global cap are synchronized, so concurrency here only bounds how many requests
are in flight at once — politeness limits are still enforced centrally.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, TypeVar

from .http_client import GlobalCapReached
from .logging import log

T = TypeVar("T")


def parallel_collect(fn: Callable[[T], list], items: Iterable[T], concurrency: int,
                     logger: logging.Logger, label: str = "task") -> list:
    """Run `fn` over `items` across a thread pool; flatten the returned lists.

    Stops scheduling further work if the global request cap is reached. Errors
    in a single item are logged and skipped, never aborting the whole batch.
    """
    items = list(items)
    if concurrency <= 1 or len(items) <= 1:
        out = []
        for it in items:
            try:
                out += fn(it) or []
            except GlobalCapReached:
                log(logger, logging.WARNING, "global cap reached", phase=label)
                break
            except Exception as e:
                log(logger, logging.WARNING, f"{label} error", error=str(e))
        return out

    results: list = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(fn, it): it for it in items}
        capped = False
        for fut in as_completed(futures):
            try:
                results += fut.result() or []
            except GlobalCapReached:
                capped = True
            except Exception as e:
                log(logger, logging.WARNING, f"{label} error", error=str(e))
        if capped:
            log(logger, logging.WARNING, "global cap reached during phase", phase=label)
    return results
