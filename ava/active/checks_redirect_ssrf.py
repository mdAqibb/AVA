"""Open redirect (confirmed) and SSRF (candidate flagging).

Open redirect: set a redirect-like parameter to an off-scope canary URL and
check whether the application tries to send the browser there (via the Location
header or a meta/JS redirect in the body). We never request the canary — the
central client would refuse it — we only observe the app's redirect intent.

SSRF: confirming SSRF safely needs an out-of-band interaction endpoint, which
this tool does not assume. We therefore flag URL-accepting parameters as
candidates for manual testing rather than asserting a vulnerability.
"""

from __future__ import annotations

import logging
import re

from ..core.logging import log
from ..core.models import Confidence, Endpoint, Evidence
from ..finding_factory import make_finding
from . import injector, payloads
from .util import evidence_for

_CANARY_HOST = "ava-redirect-canary.invalid"
_META_RX = re.compile(r"http-equiv=['\"]?refresh['\"]?[^>]*url=([^'\"> ]+)", re.I)
_JS_RX = re.compile(r"(?:location\.(?:href|replace)\s*=\s*|window\.location\s*=\s*)"
                    r"['\"]([^'\"]+)", re.I)


def check_open_redirect(client, endpoint: Endpoint, logger: logging.Logger) -> list:
    findings = []
    for target in injector.param_targets(endpoint):
        # Test redirect-like params, plus any param whose baseline looks URL-ish.
        if target.name.lower() not in payloads.REDIRECT_PARAM_HINTS:
            continue
        resp = injector.send(client, endpoint, target, payloads.REDIRECT_CANARY)
        dest = resp.redirect_location or ""
        body = resp.text or ""
        meta = _META_RX.search(body)
        js = _JS_RX.search(body)
        target_found = (_CANARY_HOST in dest
                        or (meta and _CANARY_HOST in meta.group(1))
                        or (js and _CANARY_HOST in js.group(1)))
        if target_found:
            how = ("Location header" if _CANARY_HOST in dest
                   else "meta refresh" if meta else "JavaScript redirect")
            log(logger, logging.INFO, "open redirect", url=endpoint.url,
                param=target.name, via=how)
            findings.append(make_finding(
                "redirect.open", location_url=endpoint.url, method=endpoint.method,
                location_param=target.name, confidence=Confidence.CONFIRMED,
                extra_note=f"Redirects to attacker-controlled host via {how}. "
                           f"Payload: {payloads.REDIRECT_CANARY!r}",
                evidence=[evidence_for(endpoint, target, payloads.REDIRECT_CANARY, resp,
                                       note=f"Redirect destination ({how}): {dest or (meta or js).group(1)}")]))
    return findings


def flag_ssrf_candidates(endpoint: Endpoint, logger: logging.Logger) -> list:
    findings = []
    seen = set()
    for target in injector.param_targets(endpoint):
        name = target.name.lower()
        if name in payloads.SSRF_PARAM_HINTS and name not in seen:
            seen.add(name)
            findings.append(make_finding(
                "ssrf.candidate", location_url=endpoint.url, method=endpoint.method,
                location_param=target.name, confidence=Confidence.TENTATIVE,
                extra_note=(f"Parameter {target.name!r} looks like it may carry a "
                            "URL/host the server fetches. Manually test for SSRF "
                            "(internal hosts, cloud metadata) under controlled OOB."),
                evidence=[Evidence(request_line=f"{endpoint.method} {endpoint.url}",
                                   note=f"URL-like parameter: {target.name}")]))
    return findings
