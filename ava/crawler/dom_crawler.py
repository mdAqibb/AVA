"""Headless-browser crawl (wraps Playwright) for JS-rendered routes + DOM sinks.

Playwright is an optional, heavy dependency. If it is not installed this module
degrades gracefully (logs a note, returns nothing) so the run still completes.

Scope is preserved at the browser layer: a request-router aborts any request
whose URL is out of scope, so the headless browser cannot wander off-scope even
though it does not use the central HttpClient. A small inter-navigation delay
keeps it polite.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urldefrag, urljoin, urlparse

from ..core.logging import log
from ..core.models import Endpoint
from ..intake.scope import Scope
from ..active.checks_dom import scan_scripts


def dom_scan(target: str, scope: Scope, logger: logging.Logger,
             max_pages: int = 15, nav_delay: float = 0.3) -> tuple[list, list]:
    """Render in-scope pages; return (discovered_endpoints, dom_findings)."""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        log(logger, logging.WARNING,
            "playwright not installed — skipping DOM crawl "
            "(pip install playwright && playwright install chromium)")
        return [], []

    endpoints: dict[str, Endpoint] = {}
    findings: list = []
    visited: set[str] = set()
    queue = [target]

    def _route(route):
        url = route.request.url
        allowed, _ = scope.url_in_scope(url)
        # Allow navigations/subresources only when in scope; abort otherwise.
        if allowed:
            route.continue_()
        else:
            route.abort()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context()
            context.route("**/*", _route)
            page = context.new_page()

            while queue and len(visited) < max_pages:
                url = urldefrag(queue.pop(0))[0]
                if url in visited:
                    continue
                allowed, _ = scope.url_in_scope(url)
                if not allowed:
                    continue
                visited.add(url)
                try:
                    page.goto(url, wait_until="networkidle", timeout=15000)
                except Exception as e:
                    log(logger, logging.DEBUG, "DOM nav failed", url=url, error=str(e))
                    continue

                endpoints[url] = Endpoint(url=url, method="GET",
                                          discovered_from="dom-crawl",
                                          title=(page.title() or ""))
                # DOM-sink analysis over rendered inline + linked scripts.
                scripts = _page_scripts(page)
                findings += scan_scripts(url, scripts, logger)

                # Enqueue same-origin links rendered by JS.
                base_host = urlparse(url).hostname
                for href in _page_links(page):
                    nxt = urldefrag(urljoin(url, href))[0]
                    if urlparse(nxt).hostname == base_host and nxt not in visited:
                        queue.append(nxt)

                time.sleep(nav_delay)
            browser.close()
    except Exception as e:
        log(logger, logging.WARNING, "DOM crawl error", error=str(e))

    log(logger, logging.INFO, "DOM crawl complete",
        pages=len(visited), endpoints=len(endpoints), dom_findings=len(findings))
    return list(endpoints.values()), findings


def _page_scripts(page) -> list:
    try:
        return page.eval_on_selector_all(
            "script", "els => els.map(e => e.textContent || '')") or []
    except Exception:
        return []


def _page_links(page) -> list:
    try:
        return page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.getAttribute('href'))") or []
    except Exception:
        return []
