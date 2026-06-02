"""CORS misconfiguration check.

Sends an Origin header with an arbitrary probe origin and inspects the
Access-Control-Allow-Origin / -Allow-Credentials response headers. Flags the
two classic dangerous configurations:
  * ACAO reflects our arbitrary origin (origin echoing), or
  * ACAO is '*' while Allow-Credentials is true.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from ..core.http_client import HttpClient, OutOfScopeError
from ..core.logging import log
from ..core.models import Confidence, Endpoint, Evidence
from ..finding_factory import make_finding
from . import payloads


def check_cors(client: HttpClient, endpoint: Endpoint, logger: logging.Logger) -> list:
    if endpoint.method.upper() != "GET":
        return []
    try:
        resp = client.get(endpoint.url, headers={"Origin": payloads.CORS_PROBE_ORIGIN})
    except OutOfScopeError:
        return []
    except Exception as e:
        log(logger, logging.DEBUG, "CORS probe failed", url=endpoint.url, error=str(e))
        return []

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()
    if not acao:
        return []

    reflected = acao.strip() == payloads.CORS_PROBE_ORIGIN
    wildcard_creds = acao.strip() == "*" and acac == "true"
    if not (reflected or wildcard_creds):
        return []

    detail = ("reflects an arbitrary request Origin" if reflected
              else "uses '*' with Access-Control-Allow-Credentials: true")
    conf = Confidence.CONFIRMED if reflected and acac == "true" else Confidence.FIRM
    log(logger, logging.INFO, "CORS misconfiguration", url=endpoint.url,
        acao=acao, acac=acac)
    return [make_finding(
        "cors.misconfig", location_url=_origin(endpoint.url), method="GET",
        confidence=conf,
        extra_note=f"Server {detail} (ACAO={acao!r}, Allow-Credentials={acac!r}).",
        evidence=[Evidence(
            request_line=f"GET {endpoint.url}",
            request_headers={"Origin": payloads.CORS_PROBE_ORIGIN},
            response_status=resp.status,
            response_headers={"access-control-allow-origin": acao,
                              "access-control-allow-credentials": acac or "(absent)"},
            note="Cross-origin response readable by an untrusted origin")])]


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
