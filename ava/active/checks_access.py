"""Access-control candidate flagging (IDOR) and CSRF token-presence checks.

Both are conservative: confirming broken access control / CSRF exploitability
needs authenticated, multi-user context the tool does not assume. We surface
high-quality candidates for manual testing.
"""

from __future__ import annotations

import logging

from ..core.logging import log
from ..core.models import Confidence, Endpoint, Evidence
from ..finding_factory import make_finding
from . import injector, payloads


def flag_idor_candidates(endpoint: Endpoint, logger: logging.Logger) -> list:
    findings = []
    values = injector.baseline_values(endpoint)
    seen = set()
    for target in injector.param_targets(endpoint):
        name = target.name.lower()
        val = values.get(target.name, "")
        looks_id = name in payloads.IDOR_PARAM_HINTS or payloads.looks_like_identifier(val)
        if looks_id and target.name not in seen:
            seen.add(target.name)
            findings.append(make_finding(
                "access.idor_candidate", location_url=endpoint.url,
                method=endpoint.method, location_param=target.name,
                confidence=Confidence.TENTATIVE,
                extra_note=(f"Parameter {target.name!r} (example value {val!r}) looks "
                            "like a direct object reference. Test access control by "
                            "requesting another principal's identifier while "
                            "authenticated as a different user."),
                evidence=[Evidence(request_line=f"{endpoint.method} {endpoint.url}",
                                   note=f"Identifier-like parameter: {target.name}={val}")]))
    return findings


def check_csrf(endpoint: Endpoint, logger: logging.Logger) -> list:
    """Flag state-changing (POST) forms with no detectable anti-CSRF token."""
    if endpoint.method.upper() != "POST":
        return []
    # endpoint.forms is populated on page endpoints; the form-action endpoint
    # carries its inputs. Treat a POST endpoint with body params but no token as
    # a candidate.
    has_token = any(getattr(f, "has_csrf_token", False) for f in endpoint.forms) \
        or _params_include_token(endpoint)
    if has_token:
        return []
    log(logger, logging.INFO, "CSRF token absent", url=endpoint.url)
    return [make_finding(
        "csrf.missing_token", location_url=endpoint.url, method="POST",
        confidence=Confidence.FIRM,
        extra_note="No anti-CSRF token field detected on this POST form/endpoint.",
        evidence=[Evidence(request_line=f"POST {endpoint.url}",
                           note="POST form without a detectable CSRF token")])]


def _params_include_token(endpoint: Endpoint) -> bool:
    toks = ("csrf", "xsrf", "authenticity_token", "__requestverificationtoken")
    return any(any(t in p.name.lower() for t in toks) for p in endpoint.params)
