"""Passive phase runner.

Coordinates the passive checks over a representative sample of in-scope
endpoints (plus dedicated disclosure/TLS probes), returning Findings for
triage. Header/cookie findings dedup to one-per-origin downstream, so we only
need a sample of pages rather than every endpoint.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from ..core.http_client import HttpClient, OutOfScopeError
from ..core.logging import log
from ..core.models import Endpoint
from . import checks, disclosure, tls

# How many distinct pages to inspect for header/cookie/error signals.
_PAGE_SAMPLE = 25


def run_passive(client: HttpClient, target: str, endpoints: list[Endpoint],
                logger: logging.Logger) -> list:
    findings: list = []

    # 1. Sample distinct GET URLs (seed first), inspect already-cheap signals.
    seen_origins = set()
    sample = _sample_urls(target, endpoints)
    for url in sample:
        try:
            resp = client.get(url)
        except OutOfScopeError:
            continue
        except Exception as e:
            log(logger, logging.DEBUG, "passive fetch failed", url=url, error=str(e))
            continue

        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        # Header/cookie checks are origin-scoped; run once per origin.
        if origin not in seen_origins:
            seen_origins.add(origin)
            findings += checks.check_headers(resp)
            findings += checks.check_cookies(resp)
        findings += checks.check_error_disclosure(resp)
        findings += disclosure.check_directory_listing(resp, logger)

    # 2. Dedicated probes per in-scope origin.
    for origin in sorted(seen_origins) or [_origin_of(target)]:
        findings += disclosure.probe_disclosure(client, origin, logger)
        findings += tls.analyze_tls(origin, logger)

    log(logger, logging.INFO, "passive checks produced findings",
        count=len(findings), pages=len(sample), origins=len(seen_origins))
    return findings


def _sample_urls(target: str, endpoints: list[Endpoint]) -> list[str]:
    urls = [target]
    for ep in endpoints:
        if ep.method == "GET" and ep.url not in urls:
            urls.append(ep.url)
        if len(urls) >= _PAGE_SAMPLE:
            break
    return urls


def _origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
