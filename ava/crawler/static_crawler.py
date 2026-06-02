"""Breadth-first, in-scope static crawler.

Discovers endpoints, query parameters, forms (with inputs and CSRF-token
presence), and accumulates technology fingerprints. JS-rendered routes are
handled separately by dom_crawler (Playwright); this module covers the
server-rendered surface and is the dependency-light default.

All requests go through the shared HttpClient, so scope, rate limits, and the
global cap are enforced centrally — the crawler itself never touches the
network directly.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from ..core.http_client import GlobalCapReached, HttpClient, OutOfScopeError
from ..core.logging import log
from ..core.models import Endpoint, Form, HttpParam
from .fingerprint import fingerprint


class Crawler:
    def __init__(self, client: HttpClient, logger: logging.Logger, max_depth: int = 4,
                 max_pages: int = 500, concurrency: int = 1):
        self.client = client
        self.logger = logger
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = max(1, concurrency)
        self.endpoints: dict[str, Endpoint] = {}
        self.technologies: dict[str, str] = {}

    def _canonical(self, url: str) -> str:
        url, _ = urldefrag(url)            # strip #fragment
        return url

    def _fetch(self, item):
        """Network only (runs in worker threads). Returns (item, resp|None)."""
        url, depth, origin = item
        try:
            return item, self.client.get(url)
        except (OutOfScopeError, GlobalCapReached):
            return item, None
        except Exception as e:
            log(self.logger, logging.WARNING, "fetch failed", url=url, error=str(e))
            return item, None

    def crawl(self, seed: str) -> list[Endpoint]:
        seed = self._canonical(seed)
        frontier: list[tuple[str, int, str]] = [(seed, 0, "seed")]
        visited: set[str] = set()

        # BFS level by level: fetch a level's URLs concurrently, then process
        # responses single-threaded (parsing mutates shared crawler state).
        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            while frontier and len(visited) < self.max_pages:
                batch = []
                for item in frontier:
                    url, depth, _ = item
                    if url in visited or depth > self.max_depth:
                        continue
                    if len(visited) + len(batch) >= self.max_pages:
                        break
                    visited.add(url)
                    batch.append(item)
                frontier = []
                if not batch:
                    continue

                fetcher = pool.map if self.concurrency > 1 else map
                next_frontier: list = []
                for item, resp in fetcher(self._fetch, batch):
                    if resp is None:
                        continue
                    next_frontier += self._process(item, resp, visited)
                frontier = next_frontier

        log(self.logger, logging.INFO, "crawl complete",
            pages=len(visited), endpoints=len(self.endpoints),
            technologies=list(self.technologies.keys()))
        return list(self.endpoints.values())

    def _process(self, item, resp, visited) -> list:
        """Single-threaded: record endpoint, parse, return newly-found links."""
        url, depth, origin = item
        self.technologies.update(fingerprint(resp))
        ep = self._record_endpoint(url, resp, origin, depth)

        if "html" not in resp.headers.get("content-type", "").lower():
            return []
        soup = BeautifulSoup(resp.text, "lxml")
        ep.title = (soup.title.string or "").strip() if soup.title else ""
        self._extract_forms(url, soup, ep)
        return [(link, depth + 1, url) for link in self._extract_links(url, soup)
                if link not in visited]

    # ---- recording -----------------------------------------------------

    def _record_endpoint(self, url, resp, origin, depth) -> Endpoint:
        parsed = urlparse(url)
        params = [
            HttpParam(name=k, location="query", example=(v[0] if v else ""))
            for k, v in parse_qs(parsed.query).items()
        ]
        ep = Endpoint(
            url=url, method="GET", params=params,
            status=resp.status, content_type=resp.headers.get("content-type", ""),
            discovered_from=origin, depth=depth,
        )
        self.endpoints[ep.key()] = ep
        return ep

    def _extract_links(self, base: str, soup: BeautifulSoup) -> list[str]:
        out = []
        base_host = urlparse(base).hostname
        for a in soup.find_all("a", href=True):
            target = self._canonical(urljoin(base, a["href"]))
            p = urlparse(target)
            if p.scheme not in ("http", "https"):
                continue
            # Only enqueue same-host links; scope is still re-checked per request.
            if p.hostname == base_host:
                out.append(target)
        return out

    def _extract_forms(self, base: str, soup: BeautifulSoup, page_ep: Endpoint) -> None:
        for form in soup.find_all("form"):
            action = self._canonical(urljoin(base, form.get("action") or base))
            method = (form.get("method") or "GET").upper()
            inputs: list[HttpParam] = []
            has_csrf = False
            for field_el in form.find_all(["input", "textarea", "select"]):
                name = field_el.get("name")
                if not name:
                    continue
                loc = "body" if method == "POST" else "query"
                inputs.append(HttpParam(name=name, location=loc,
                                        example=field_el.get("value", "") or ""))
                if self._looks_like_csrf(name, field_el):
                    has_csrf = True
            f = Form(action=action, method=method, inputs=inputs, has_csrf_token=has_csrf)
            page_ep.forms.append(f)

            # A form action is itself a (likely parameterized) endpoint.
            form_ep = Endpoint(
                url=action, method=method, params=list(inputs),
                discovered_from=base, depth=page_ep.depth,
            )
            self.endpoints.setdefault(form_ep.key(), form_ep)

    @staticmethod
    def _looks_like_csrf(name: str, field_el) -> bool:
        n = name.lower()
        if any(tok in n for tok in ("csrf", "xsrf", "authenticity_token", "__requestverificationtoken")):
            return True
        return (field_el.get("type") or "").lower() == "hidden" and "token" in n
