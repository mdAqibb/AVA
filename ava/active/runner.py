"""Active phase runner.

Coordinates the active checks across discovered endpoints. To stay polite and
bounded it:
  * tests only endpoints that have parameters (for injection/XSS),
  * collapses endpoints to distinct *shapes* (method + path + param names) so
    the same template isn't fuzzed dozens of times,
  * caps the number of shapes tested per run,
  * establishes one baseline per endpoint and reuses it across checks.

Every request still flows through the central HttpClient (scope, rate limit,
global cap, destructive guard). Time-based probes run only under heavy fuzzing.
"""

from __future__ import annotations

import logging
from urllib.parse import urlsplit

from ..core.concurrency import parallel_collect
from ..core.http_client import HttpClient, OutOfScopeError
from ..core.logging import log
from ..core.models import Endpoint
from . import (checks_access, checks_cors, checks_injection, checks_redirect_ssrf,
               checks_sqli, checks_xss, injector)

_MAX_SHAPES = 150


def run_active(client: HttpClient, endpoints: list[Endpoint], technologies: dict,
               logger: logging.Logger, heavy_fuzzing: bool, concurrency: int = 1) -> list:
    shapes = _distinct_shapes(endpoints)
    log(logger, logging.INFO, "active phase starting",
        endpoints=len(endpoints), shapes=len(shapes),
        heavy_fuzzing=heavy_fuzzing, concurrency=concurrency)

    def work(ep: Endpoint) -> list:
        try:
            return _run_endpoint(client, ep, logger, heavy_fuzzing)
        except OutOfScopeError:
            return []

    findings = parallel_collect(work, shapes, concurrency, logger, label="active")
    log(logger, logging.INFO, "active phase produced findings", count=len(findings))
    return findings


def _run_endpoint(client, ep: Endpoint, logger, heavy_fuzzing) -> list:
    out: list = []
    targets = injector.param_targets(ep)

    # Static (no-request) candidate flagging — always cheap.
    out += checks_redirect_ssrf.flag_ssrf_candidates(ep, logger)
    out += checks_access.flag_idor_candidates(ep, logger)
    out += checks_access.check_csrf(ep, logger)

    # CORS: one extra GET with an Origin header.
    out += checks_cors.check_cors(client, ep, logger)

    if not targets:
        return out

    # Reflection / evaluation based (no baseline needed).
    out += checks_xss.check_reflected_xss(client, ep, logger)
    out += checks_injection.check_template_injection(client, ep, logger)
    out += checks_redirect_ssrf.check_open_redirect(client, ep, logger)
    if heavy_fuzzing:
        out += checks_xss.check_stored_xss(client, ep, logger)

    # Baseline-dependent (SQLi boolean/time, command injection).
    baseline = injector.send_baseline(client, ep)
    out += checks_sqli.check_sqli(client, ep, baseline, logger, heavy_fuzzing)
    out += checks_injection.check_command_injection(client, ep, baseline, logger, heavy_fuzzing)
    return out


def _distinct_shapes(endpoints: list[Endpoint]) -> list[Endpoint]:
    """One representative endpoint per (method, path, sorted-param-names)."""
    seen: dict[tuple, Endpoint] = {}
    for ep in endpoints:
        path = urlsplit(ep.url).path
        names = tuple(sorted(t.name for t in injector.param_targets(ep)))
        key = (ep.method.upper(), path, names)
        if key not in seen:
            seen[key] = ep
        if len(seen) >= _MAX_SHAPES:
            break
    return list(seen.values())
