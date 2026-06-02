"""The single choke point for ALL outbound requests.

Every module — crawler, passive checks, active checks — must use this client.
It is the one place that enforces:

  * scope (re-checked on every request AND on every redirect hop)
  * rate limiting (token bucket) and per-run global request cap
  * a destructive-payload guard (defence in depth against accidental misuse)
  * uniform timeouts, retries, and structured request logging

Because redirects can lead off-scope, automatic redirect following is
DISABLED. Redirects are surfaced and only followed manually after a fresh
scope check.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

from .logging import log
from .ratelimit import GlobalCap, GlobalCapReached, TokenBucket  # re-exported
from ..intake.scope import Scope


class OutOfScopeError(RuntimeError):
    def __init__(self, url: str, reason: str):
        super().__init__(f"Refused out-of-scope request to {url}: {reason}")
        self.url = url
        self.reason = reason


class DestructivePayloadError(RuntimeError):
    """Tripwire: a check tried to send a payload matching a destructive
    pattern. Active checks must use confirmation-grade payloads, never
    data-destroying or DoS payloads."""


# Conservative deny-list of clearly destructive intents. This is a safety net,
# not the primary control — checks are written to be non-destructive by design.
_DESTRUCTIVE_PATTERNS = [
    re.compile(r"\bDROP\s+TABLE\b", re.I),
    re.compile(r"\bDROP\s+DATABASE\b", re.I),
    re.compile(r"\bTRUNCATE\s+TABLE\b", re.I),
    re.compile(r"\bDELETE\s+FROM\b", re.I),
    re.compile(r"\bUPDATE\b.+\bSET\b", re.I),
    re.compile(r"\bINSERT\s+INTO\b", re.I),
    re.compile(r"\bSHUTDOWN\b", re.I),
    re.compile(r";\s*rm\s+-rf", re.I),
    re.compile(r"\bmkfs\b|\bdd\s+if=", re.I),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:"),  # fork bomb
]


@dataclass
class Response:
    """Lightweight, serialization-friendly view of an HTTP response."""

    url: str
    status: int
    headers: dict[str, str]
    text: str
    elapsed_ms: float
    redirect_location: Optional[str] = None
    # Raw Set-Cookie header values, preserved individually (a dict collapses
    # repeats). Needed for per-cookie attribute analysis.
    set_cookies: list = field(default_factory=list)


class HttpClient:
    def __init__(
        self,
        scope: Scope,
        rate: float,
        concurrency: int,
        global_cap: int,
        logger: logging.Logger,
        timeout: float = 15.0,
        user_agent: str = "AVA/0.1 (+authorized-assessment)",
        max_body_chars: int = 500_000,
        allow_destructive: bool = False,
        retries: int = 2,
    ):
        self.scope = scope
        self.bucket = TokenBucket(rate=rate, capacity=max(rate, concurrency))
        self.cap = GlobalCap(global_cap)
        self.logger = logger
        self.max_body_chars = max_body_chars
        self.allow_destructive = allow_destructive
        self.retries = max(0, retries)
        import httpx  # imported lazily so the module is usable without the dep
        # Transient transport errors worth a retry (not 4xx/5xx — those are
        # real responses we want to analyze).
        self._transient = (httpx.TransportError,)
        self._client = httpx.Client(
            follow_redirects=False,            # we follow manually, after scope check
            timeout=timeout,
            headers={"User-Agent": user_agent},
            verify=True,
        )

    def _send(self, req):
        """Send with bounded retry + backoff on transient transport errors.

        Each attempt consumes a rate-limit token and counts against the global
        cap, so retries stay polite and bounded.
        """
        import time
        last = None
        for attempt in range(self.retries + 1):
            self.bucket.acquire()
            self.cap.increment()
            try:
                return self._client.send(req)
            except self._transient as e:
                last = e
                if attempt < self.retries:
                    time.sleep(0.5 * (attempt + 1))
                    log(self.logger, logging.DEBUG, "transient error; retrying",
                        url=str(req.url), attempt=attempt + 1, error=str(e))
        raise last

    # ---- guards --------------------------------------------------------

    def _guard_destructive(self, url: str, params, data, content) -> None:
        if self.allow_destructive:
            return
        haystacks = [url]
        for blob in (params, data):
            if isinstance(blob, dict):
                haystacks.extend(str(v) for v in blob.values())
                haystacks.extend(str(k) for k in blob.keys())
        if content:
            haystacks.append(content if isinstance(content, str) else content.decode("utf-8", "ignore"))
        joined = " ".join(haystacks)
        for pat in _DESTRUCTIVE_PATTERNS:
            if pat.search(joined):
                raise DestructivePayloadError(
                    f"Blocked a request whose payload matched destructive pattern "
                    f"/{pat.pattern}/. Use confirmation-grade payloads instead."
                )

    def _guard_scope(self, url: str) -> None:
        allowed, reason = self.scope.url_in_scope(url)
        if not allowed:
            log(self.logger, logging.WARNING, "Out-of-scope request refused",
                url=url, reason=reason)
            raise OutOfScopeError(url, reason)

    # ---- core request --------------------------------------------------

    def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        content: Optional[bytes | str] = None,
        headers: Optional[dict] = None,
        max_redirects: int = 3,
    ) -> Response:
        """Perform one scope-checked, rate-limited request.

        Redirects are followed manually, re-checking scope on each hop and
        stopping (without error) at the first off-scope redirect.
        """
        self._guard_scope(url)
        self._guard_destructive(url, params, data, content)

        hops = 0
        current = url
        while True:
            req = self._client.build_request(
                method, current, params=params, data=data, content=content,
                headers=headers,
            )
            log(self.logger, logging.DEBUG, "request",
                method=method, url=str(req.url))
            resp = self._send(req)
            body = resp.text[: self.max_body_chars]
            location = resp.headers.get("location")
            set_cookies = list(resp.headers.get_list("set-cookie"))

            redirect_target = None
            if resp.is_redirect and location and hops < max_redirects:
                redirect_target = urljoin(str(resp.url), location)
                allowed, reason = self.scope.url_in_scope(redirect_target)
                if not allowed:
                    log(self.logger, logging.INFO,
                        "Stopping at off-scope redirect (not followed)",
                        from_url=str(resp.url), to=redirect_target, reason=reason)
                    redirect_target = None  # surface but do not follow
                else:
                    # Follow within scope; query/body only applied to first hop.
                    current = redirect_target
                    params = data = content = None
                    hops += 1
                    continue

            return Response(
                url=str(resp.url),
                status=resp.status_code,
                headers={k.lower(): v for k, v in resp.headers.items()},
                text=body,
                elapsed_ms=resp.elapsed.total_seconds() * 1000.0,
                redirect_location=location if resp.is_redirect else None,
                set_cookies=set_cookies,
            )

    def get(self, url: str, **kw) -> Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> Response:
        return self.request("POST", url, **kw)

    @property
    def request_count(self) -> int:
        return self.cap.count

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def same_host(a: str, b: str) -> bool:
    return (urlparse(a).hostname or "").lower() == (urlparse(b).hostname or "").lower()
