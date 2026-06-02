"""Reflected and stored XSS sink identification.

Detection is reflection-based (conservative): we inject a unique marker plus
HTML-breakout characters and check whether those characters survive *unencoded*
around the marker in the response. We report the exact reflecting payload and
the surrounding context; we do not rely on script execution.
"""

from __future__ import annotations

import logging
import re

from ..core.logging import log
from ..core.models import Confidence, Endpoint, Evidence
from ..finding_factory import make_finding
from . import injector, payloads
from .util import evidence_for


def check_reflected_xss(client, endpoint: Endpoint, logger: logging.Logger) -> list:
    findings = []
    for target in injector.param_targets(endpoint):
        tok = payloads.token("avx")
        probe = payloads.xss_probe(tok)
        resp = injector.send(client, endpoint, target, probe)
        body = resp.text or ""
        if tok not in body:
            continue  # not reflected at all

        unencoded = _unencoded_chars(body, tok)
        if not unencoded:
            continue  # reflected but encoded -> safe; skip

        confirmed = f"<svg/onload=alert({tok})>" in body
        conf = Confidence.CONFIRMED if confirmed else Confidence.FIRM
        ctx = _context_snippet(body, tok)
        log(logger, logging.INFO, "reflected XSS sink", url=endpoint.url,
            param=target.name, confirmed=confirmed)
        findings.append(make_finding(
            "xss.reflected", location_url=endpoint.url, method=endpoint.method,
            location_param=target.name, confidence=conf,
            extra_note=(f"Marker reflected with unencoded {unencoded}. "
                        f"{'Full breakout payload reflected verbatim. ' if confirmed else ''}"
                        f"Reflecting payload: {probe!r}"),
            evidence=[evidence_for(endpoint, target, probe, resp,
                                   note=f"Reflected context: …{ctx}…")],
        ))
    return findings


def check_stored_xss(client, endpoint: Endpoint, logger: logging.Logger) -> list:
    """Best-effort stored-XSS probe for POST forms: submit a unique marker, then
    re-fetch the form's page to see if it persists unencoded. Gated by the
    runner behind heavy fuzzing because it writes data."""
    if endpoint.method.upper() != "POST":
        return []
    findings = []
    body_targets = [t for t in injector.param_targets(endpoint) if t.location == "body"]
    for target in body_targets:
        tok = payloads.token("avs")
        probe = payloads.xss_probe(tok)
        injector.send(client, endpoint, target, probe)
        # Re-read the page the form lived on (discovered_from) and the action.
        for url in {endpoint.discovered_from, endpoint.url}:
            if not url:
                continue
            try:
                rr = client.get(url)
            except Exception:
                continue
            if tok in (rr.text or "") and _unencoded_chars(rr.text, tok):
                log(logger, logging.INFO, "stored XSS sink", form=endpoint.url,
                    param=target.name, shown_on=url)
                findings.append(make_finding(
                    "xss.stored", location_url=url, method="GET",
                    location_param=target.name, confidence=Confidence.FIRM,
                    extra_note=(f"Marker submitted to {endpoint.method} {endpoint.url} "
                                f"(field {target.name!r}) was reflected unencoded at {url}."),
                    evidence=[Evidence(request_line=f"GET {url}",
                                       response_status=rr.status,
                                       response_excerpt=_context_snippet(rr.text, tok),
                                       note="Persisted marker rendered unencoded")],
                ))
                break
    return findings


def _unencoded_chars(body: str, tok: str) -> list:
    """Which HTML-breakout chars from our payload survived UNENCODED.

    We inspect the tail immediately after the marker — that text is our own
    injected payload (`"'><svg/...`), so a literal '<'/'>'/'\"'/'\\'' there means
    it was not entity-encoded (the encoded forms &lt; &gt; &quot; &#39; contain
    none of those literal characters)."""
    i = body.find(tok)
    if i < 0:
        return []
    tail = body[i + len(tok): i + len(tok) + 40]
    return sorted({ch for ch in payloads.XSS_BREAKOUT_CHARS if ch in tail})


def _around(body: str, tok: str, radius: int) -> str:
    i = body.find(tok)
    if i < 0:
        return ""
    return body[max(0, i - radius): i + len(tok) + radius]


def _context_snippet(body: str, tok: str) -> str:
    return re.sub(r"\s+", " ", _around(body, tok, 50)).strip()
