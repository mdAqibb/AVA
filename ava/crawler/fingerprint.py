"""Lightweight technology/framework fingerprinting from headers + body.

Heuristic only — surfaces hints (used to tailor checks and remediation
examples), not authoritative version claims. Kept deliberately small and
data-driven so it is easy to extend.
"""

from __future__ import annotations

import re

from ..core.http_client import Response

# (label, where, regex). where: "header:<name>" or "body".
_SIGNATURES: list[tuple[str, str, re.Pattern]] = [
    ("nginx", "header:server", re.compile(r"nginx", re.I)),
    ("Apache", "header:server", re.compile(r"apache", re.I)),
    ("IIS", "header:server", re.compile(r"microsoft-iis", re.I)),
    ("Express", "header:x-powered-by", re.compile(r"express", re.I)),
    ("PHP", "header:x-powered-by", re.compile(r"php/?([\d.]+)?", re.I)),
    ("ASP.NET", "header:x-powered-by", re.compile(r"asp\.net", re.I)),
    ("Django", "header:set-cookie", re.compile(r"\bcsrftoken=|\bsessionid=", re.I)),
    ("Flask/Werkzeug", "header:server", re.compile(r"werkzeug", re.I)),
    ("Laravel", "header:set-cookie", re.compile(r"laravel_session", re.I)),
    ("Rails", "header:set-cookie", re.compile(r"_session_id|\b_rails", re.I)),
    ("WordPress", "body", re.compile(r"/wp-content/|/wp-includes/", re.I)),
    ("React", "body", re.compile(r"data-reactroot|__NEXT_DATA__|react", re.I)),
    ("Vue", "body", re.compile(r"data-v-[0-9a-f]{8}|__vue__", re.I)),
    ("jQuery", "body", re.compile(r"jquery[.-]([\d.]+)?(\.min)?\.js", re.I)),
]


def fingerprint(resp: Response) -> dict[str, str]:
    """Return {technology: matched_detail} for a response."""
    found: dict[str, str] = {}
    for label, where, rx in _SIGNATURES:
        if where == "body":
            m = rx.search(resp.text or "")
            if m:
                found[label] = m.group(0)[:80]
        elif where.startswith("header:"):
            hdr = where.split(":", 1)[1]
            val = resp.headers.get(hdr, "")
            m = rx.search(val)
            if m:
                found[label] = val[:120]
    return found
