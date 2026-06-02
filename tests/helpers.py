"""Shared test helpers: response builder, fake clients, finding factory.

These let the suite exercise detection/orchestration logic without any real
network dependency (httpx/playwright/sslyze are not required to run the tests).
"""

from __future__ import annotations

from ava.core.http_client import Response
from ava.core.models import Confidence, Finding, Severity
from ava.active import payloads


def R(url="http://t/", status=200, text="", headers=None, elapsed=50.0,
      redirect=None, cookies=None) -> Response:
    return Response(url=url, status=status, headers=headers or {}, text=text,
                    elapsed_ms=elapsed, redirect_location=redirect,
                    set_cookies=cookies or [])


class FakeVulnClient:
    """Simulates a deliberately vulnerable app to exercise every active check."""

    def request(self, method, url, params=None, data=None, content=None,
                headers=None, max_redirects=3):
        vals = {**(params or {}), **(data or {})}
        v = " ".join(str(x) for x in vals.values())
        # SQLi error-based: a lone quote provokes a DB parse error.
        if v.strip().endswith("'") and "AND" not in v and "SLEEP" not in v:
            return R(url=url, text="You have an error in your SQL syntax; near '''")
        # SSTI: evaluate the injected arithmetic expression.
        if any(f"{payloads.SSTI_A}*{payloads.SSTI_B}" in str(x) for x in vals.values()):
            return R(url=url, text=f"<p>result {payloads.SSTI_EXPECT}</p>")
        # Reflected XSS: echo the payload verbatim (unencoded).
        if "<svg/onload=alert(" in v:
            tok = [x for x in vals.values() if "<svg/onload" in str(x)][0]
            return R(url=url, text=f"<div>hello {tok} bye</div>")
        # Command injection: the echoed marker appears (command executed).
        if "echo ava" in v or "echo avc" in v:
            tok = v.split("echo ", 1)[1].split(")")[0].split("`")[0].split()[0]
            return R(url=url, text=f"PING output\n{tok}\n")
        # Open redirect: bounce to the off-scope canary.
        if payloads.REDIRECT_CANARY in v:
            return R(url=url, status=302, redirect=payloads.REDIRECT_CANARY,
                     headers={"location": payloads.REDIRECT_CANARY})
        return R(url=url, text="normal baseline page content here")

    def get(self, url, **kw):
        h = kw.get("headers") or {}
        if h.get("Origin") == payloads.CORS_PROBE_ORIGIN:
            return R(url=url, headers={
                "access-control-allow-origin": payloads.CORS_PROBE_ORIGIN,
                "access-control-allow-credentials": "true"})
        return R(url=url, text="page")

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


def make_finding(check_id="x.test", location_url="https://t/i", location_param="id"):
    return Finding(
        title=check_id, cwe="CWE-89", owasp="A03:2021 Injection",
        severity=Severity.HIGH, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.1, confidence=Confidence.CONFIRMED,
        location_url=location_url, location_param=location_param, check_id=check_id,
    )


SCOPE_YAML = """\
allowed_hosts:
  - example.com
  - www.example.com
  - "*.staging.example.com"
allowed_paths:
  - /
denied_paths:
  - /logout
hard_deny_hosts:
  - accounts.google.com
engagement:
  authorized_by: tester@example.com
"""
