"""Active-check detection logic against a simulated vulnerable app."""

import pytest

from ava.active import (checks_access, checks_cors, checks_injection,
                        checks_redirect_ssrf, checks_sqli, checks_xss, injector)
from ava.active.checks_dom import scan_scripts
from ava.core.models import Confidence, Endpoint, HttpParam
from tests.helpers import FakeVulnClient, R


@pytest.fixture
def client():
    return FakeVulnClient()


def _ep(url, method="GET", params=None):
    return Endpoint(url=url, method=method, params=params or [])


def test_sqli_error_based(client, quiet_logger):
    ep = _ep("http://x/item?id=1", params=[HttpParam("id", "query", "1")])
    base = injector.send_baseline(client, ep)
    f = checks_sqli.check_sqli(client, ep, base, quiet_logger, heavy_fuzzing=False)
    assert f and f[0].check_id == "injection.sqli"
    assert f[0].confidence is Confidence.CONFIRMED


def test_ssti(client, quiet_logger):
    ep = _ep("http://x/greet?name=bob", params=[HttpParam("name", "query", "bob")])
    f = checks_injection.check_template_injection(client, ep, quiet_logger)
    assert f and f[0].check_id == "injection.template"
    assert f[0].severity.value == "Critical"


def test_reflected_xss(client, quiet_logger):
    ep = _ep("http://x/greet?name=bob", params=[HttpParam("name", "query", "bob")])
    f = checks_xss.check_reflected_xss(client, ep, quiet_logger)
    assert f and f[0].check_id == "xss.reflected"


def test_reflected_xss_negative_when_encoded(quiet_logger):
    import html

    class SafeClient(FakeVulnClient):
        def request(self, method, url, params=None, data=None, content=None,
                    headers=None, max_redirects=3):
            vals = {**(params or {}), **(data or {})}
            v = " ".join(str(x) for x in vals.values())
            if "<svg/onload" in v:
                tok = [x for x in vals.values() if "<svg" in str(x)][0]
                return R(url=url, text=f"<div>{html.escape(tok)}</div>")
            return R(url=url, text="x")

    ep = _ep("http://x/g?n=b", params=[HttpParam("n", "query", "b")])
    assert checks_xss.check_reflected_xss(SafeClient(), ep, quiet_logger) == []


def test_command_injection_echo(client, quiet_logger):
    ep = _ep("http://x/ping?host=a", params=[HttpParam("host", "query", "a")])
    base = injector.send_baseline(client, ep)
    f = checks_injection.check_command_injection(client, ep, base, quiet_logger,
                                                 heavy_fuzzing=False)
    assert f and f[0].check_id == "injection.command"


def test_open_redirect(client, quiet_logger):
    ep = _ep("http://x/go?next=/home", params=[HttpParam("next", "query", "/home")])
    f = checks_redirect_ssrf.check_open_redirect(client, ep, quiet_logger)
    assert f and f[0].check_id == "redirect.open"


def test_cors_misconfig(client, quiet_logger):
    ep = _ep("http://x/api?id=1", params=[HttpParam("id", "query", "1")])
    f = checks_cors.check_cors(client, ep, quiet_logger)
    assert f and f[0].check_id == "cors.misconfig"


def test_ssrf_candidate_flagging(quiet_logger):
    ep = _ep("http://x/fetch?url=http://a", params=[HttpParam("url", "query", "http://a")])
    f = checks_redirect_ssrf.flag_ssrf_candidates(ep, quiet_logger)
    assert f and f[0].check_id == "ssrf.candidate"
    assert f[0].confidence is Confidence.TENTATIVE


def test_idor_candidate_flagging(quiet_logger):
    ep = _ep("http://x/doc?id=42", params=[HttpParam("id", "query", "42")])
    f = checks_access.flag_idor_candidates(ep, quiet_logger)
    assert f and f[0].check_id == "access.idor_candidate"


def test_csrf_missing_token(quiet_logger):
    ep = _ep("http://x/transfer", method="POST", params=[HttpParam("amount", "body", "10")])
    f = checks_access.check_csrf(ep, quiet_logger)
    assert f and f[0].check_id == "csrf.missing_token"


def test_csrf_present_token_not_flagged(quiet_logger):
    ep = _ep("http://x/transfer", method="POST",
             params=[HttpParam("amount", "body", "10"), HttpParam("csrf_token", "body", "x")])
    assert checks_access.check_csrf(ep, quiet_logger) == []


def test_dom_xss_sink(quiet_logger):
    scripts = ["var x = location.hash; el.innerHTML = x;"]
    f = scan_scripts("http://x/spa", scripts, quiet_logger)
    assert f and f[0].check_id == "xss.dom"


def test_dom_xss_no_sink_when_safe(quiet_logger):
    scripts = ["var x = location.hash; el.textContent = x;"]  # safe sink
    assert scan_scripts("http://x/spa", scripts, quiet_logger) == []
