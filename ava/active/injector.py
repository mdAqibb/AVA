"""Single-parameter mutation helper for active checks.

Given a discovered Endpoint, builds requests that hold every parameter at a
benign baseline value except one, which is set to a probe payload. All sends
go through the central HttpClient, so scope, rate limiting, the global cap and
the destructive-payload guard all still apply.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from ..core.http_client import HttpClient, Response
from ..core.models import Endpoint

_DEFAULT = "1"


@dataclass
class ParamTarget:
    name: str
    location: str            # "query" | "body"


def _base_url(endpoint: Endpoint) -> str:
    parts = urlsplit(endpoint.url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def baseline_values(endpoint: Endpoint) -> dict[str, str]:
    """Benign values for every parameter (existing query values preserved)."""
    values: dict[str, str] = {}
    # Query params encoded in the URL.
    for k, v in parse_qsl(urlsplit(endpoint.url).query):
        values[k] = v or _DEFAULT
    # Declared params (forms, detected query params).
    for p in endpoint.params:
        if p.name not in values:
            values[p.name] = p.example or _DEFAULT
    return values


def param_targets(endpoint: Endpoint) -> list[ParamTarget]:
    targets: list[ParamTarget] = []
    seen = set()
    is_post = endpoint.method.upper() == "POST"
    for k, _ in parse_qsl(urlsplit(endpoint.url).query):
        if k not in seen:
            targets.append(ParamTarget(k, "query")); seen.add(k)
    for p in endpoint.params:
        if p.name in seen:
            continue
        loc = "body" if (is_post and p.location == "body") else "query"
        targets.append(ParamTarget(p.name, loc)); seen.add(p.name)
    return targets


def send(client: HttpClient, endpoint: Endpoint, target: ParamTarget,
         payload: str, extra_headers: dict | None = None) -> Response:
    """Send a request with `target` set to `payload`, others at baseline."""
    values = baseline_values(endpoint)
    values[target.name] = payload
    method = endpoint.method.upper()
    url = _base_url(endpoint)

    if method == "POST":
        # Params not in the body go on the query string.
        body = {t.name: values[t.name] for t in param_targets(endpoint)
                if t.location == "body"}
        if target.location == "body":
            body[target.name] = payload
        query = {k: v for k, v in values.items() if k not in body}
        return client.request("POST", url, params=query or None,
                              data=body or None, headers=extra_headers)
    return client.request("GET", url, params=values, headers=extra_headers)


def send_baseline(client: HttpClient, endpoint: Endpoint) -> Response:
    values = baseline_values(endpoint)
    method = endpoint.method.upper()
    url = _base_url(endpoint)
    if method == "POST":
        body = {t.name: values[t.name] for t in param_targets(endpoint)
                if t.location == "body"}
        query = {k: v for k, v in values.items() if k not in body}
        return client.request("POST", url, params=query or None, data=body or None)
    return client.request("GET", url, params=values)
