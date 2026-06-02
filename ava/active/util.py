"""Shared helpers for active checks: response similarity and evidence building."""

from __future__ import annotations

import re

from ..core.http_client import Response
from ..core.models import Endpoint, Evidence

_MAX_EXCERPT = 220


def body_similarity(a: str, b: str) -> float:
    """Cheap, length-normalized similarity in [0,1].

    Avoids O(n^2) difflib on large bodies: compares normalized lengths and a
    token-set overlap on a capped prefix. Good enough to separate
    "looks like the baseline" from "clearly different" for boolean-blind tests.
    """
    a = _normalize(a or "")
    b = _normalize(b or "")
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    # Length ratio component.
    len_ratio = min(len(a), len(b)) / max(len(a), len(b))
    # Token overlap on a capped prefix.
    ta = set(a[:4000].split())
    tb = set(b[:4000].split())
    if ta or tb:
        overlap = len(ta & tb) / max(1, len(ta | tb))
    else:
        overlap = 1.0
    return round(0.5 * len_ratio + 0.5 * overlap, 4)


def _normalize(s: str) -> str:
    # Drop volatile tokens (CSRF nonces, timestamps) that would otherwise add
    # noise to similarity comparisons.
    s = re.sub(r"\b[0-9a-f]{16,}\b", "", s, flags=re.I)
    s = re.sub(r"\d{10,}", "", s)
    return re.sub(r"\s+", " ", s).strip()


def evidence_for(endpoint: Endpoint, target, payload: str, resp: Response,
                 note: str = "") -> Evidence:
    """Build a redacted request/response evidence record for an injected param."""
    method = endpoint.method.upper()
    req_line = f"{method} {endpoint.url}  ({target.name}={_short(payload)})"
    body = ""
    if method == "POST" and getattr(target, "location", "") == "body":
        body = f"{target.name}={_short(payload)}"
    excerpt = (resp.text or "")[:_MAX_EXCERPT]
    return Evidence(
        request_line=req_line,
        request_body=body,
        response_status=resp.status,
        response_excerpt=excerpt,
        note=note,
    )


def _short(s: str, n: int = 120) -> str:
    return s if len(s) <= n else s[:n] + "…"
