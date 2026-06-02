"""Passive checks over an already-fetched response.

Each function inspects a Response (no extra requests) and returns Findings.
Header/cookie findings are anchored to the response *origin* (scheme://host)
so triage collapses them to one finding per site rather than per page.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core.http_client import Response
from ..core.models import Confidence, Evidence
from ..finding_factory import make_finding


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _evidence_from(resp: Response, note: str) -> Evidence:
    # Surface a small, redacted slice of the relevant response headers.
    interesting = {k: v for k, v in resp.headers.items()
                   if k in ("server", "x-powered-by", "content-security-policy",
                            "strict-transport-security", "x-frame-options",
                            "x-content-type-options", "referrer-policy")}
    return Evidence(
        request_line=f"GET {resp.url}",
        response_status=resp.status,
        response_headers=interesting,
        note=note,
    )


def check_headers(resp: Response) -> list:
    """Security-header presence checks."""
    findings = []
    h = resp.headers
    origin = _origin(resp.url)
    is_https = resp.url.lower().startswith("https://")

    if "content-security-policy" not in h:
        findings.append(make_finding("header.csp.missing", location_url=origin,
                                      confidence=Confidence.FIRM,
                                      evidence=[_evidence_from(resp, "No Content-Security-Policy header in response.")]))
    if is_https and "strict-transport-security" not in h:
        findings.append(make_finding("header.hsts.missing", location_url=origin,
                                      confidence=Confidence.FIRM,
                                      evidence=[_evidence_from(resp, "No Strict-Transport-Security header on HTTPS response.")]))
    if "x-content-type-options" not in h:
        findings.append(make_finding("header.xcto.missing", location_url=origin,
                                      confidence=Confidence.FIRM,
                                      evidence=[_evidence_from(resp, "No X-Content-Type-Options header.")]))

    csp = h.get("content-security-policy", "")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        findings.append(make_finding("header.xfo.missing", location_url=origin,
                                      confidence=Confidence.FIRM,
                                      evidence=[_evidence_from(resp, "No X-Frame-Options and no CSP frame-ancestors.")]))
    if "referrer-policy" not in h:
        findings.append(make_finding("header.referrer.missing", location_url=origin,
                                      confidence=Confidence.FIRM,
                                      evidence=[_evidence_from(resp, "No Referrer-Policy header.")]))

    # Version disclosure
    server = h.get("server", "")
    powered = h.get("x-powered-by", "")
    if re.search(r"\d", server) or powered:
        detail = f"Server: {server!r}  X-Powered-By: {powered!r}".strip()
        findings.append(make_finding("info.server.version", location_url=origin,
                                      confidence=Confidence.FIRM,
                                      extra_note=f"Disclosed: {detail}",
                                      evidence=[_evidence_from(resp, detail)]))
    return findings


def check_cookies(resp: Response) -> list:
    """Per-cookie attribute analysis from raw Set-Cookie headers."""
    findings = []
    origin = _origin(resp.url)
    for raw in resp.set_cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        flat = ";".join(attrs)
        redacted = _redact_cookie(raw)
        ev = [Evidence(request_line=f"GET {resp.url}",
                       response_status=resp.status,
                       response_headers={"set-cookie": redacted},
                       note=f"Cookie {name!r} attributes: {attrs}")]

        if "secure" not in attrs:
            findings.append(make_finding("cookie.secure.missing", location_url=origin,
                                         location_param=name, confidence=Confidence.FIRM, evidence=ev))
        if "httponly" not in attrs:
            findings.append(make_finding("cookie.httponly.missing", location_url=origin,
                                         location_param=name, confidence=Confidence.FIRM, evidence=ev))
        if "samesite" not in flat:
            findings.append(make_finding("cookie.samesite.missing", location_url=origin,
                                         location_param=name, confidence=Confidence.FIRM, evidence=ev))
    return findings


def _redact_cookie(raw: str) -> str:
    """Keep the cookie name + attributes, redact the value."""
    if "=" not in raw:
        return raw
    name, rest = raw.split("=", 1)
    tail = rest.split(";", 1)
    attrs = (";" + tail[1]) if len(tail) > 1 else ""
    return f"{name}=<redacted>{attrs}"


# Framework error / stack-trace signatures (kept conservative).
_STACK_SIGNATURES = [
    re.compile(r"Traceback \(most recent call last\)"),          # Python
    re.compile(r"at [\w.$]+\([\w.]+\.java:\d+\)"),               # Java
    re.compile(r"\bFatal error\b.*on line \d+", re.I),           # PHP
    re.compile(r"Exception in thread"),                          # JVM
    re.compile(r"System\.[\w.]+Exception"),                      # .NET
    re.compile(r"ORA-\d{5}"),                                    # Oracle
    re.compile(r"SQLSTATE\[\w+\]"),                              # PDO/SQL
    re.compile(r"Werkzeug Debugger"),                            # Flask debug
]


def check_error_disclosure(resp: Response) -> list:
    """Flag verbose stack traces / framework errors in the body."""
    body = resp.text or ""
    for rx in _STACK_SIGNATURES:
        m = rx.search(body)
        if m:
            snippet = body[max(0, m.start() - 40): m.start() + 160]
            return [make_finding(
                "disclosure.stack_trace", location_url=resp.url,
                confidence=Confidence.FIRM,
                evidence=[Evidence(request_line=f"GET {resp.url}",
                                   response_status=resp.status,
                                   response_excerpt=snippet,
                                   note=f"Matched error signature /{rx.pattern}/")],
            )]
    return []
