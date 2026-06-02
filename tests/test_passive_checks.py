"""Passive checks over fixed responses."""

from ava.passive import checks
from tests.helpers import R


def test_missing_security_headers_flagged():
    resp = R(url="https://t/", headers={"content-type": "text/html"})
    ids = {f.check_id for f in checks.check_headers(resp)}
    assert "header.csp.missing" in ids
    assert "header.hsts.missing" in ids        # HTTPS without HSTS
    assert "header.xcto.missing" in ids
    assert "header.xfo.missing" in ids


def test_present_headers_not_flagged():
    resp = R(url="https://t/", headers={
        "content-type": "text/html",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
    })
    ids = {f.check_id for f in checks.check_headers(resp)}
    assert "header.csp.missing" not in ids
    assert "header.hsts.missing" not in ids
    assert "header.xfo.missing" not in ids      # CSP frame-ancestors counts


def test_server_version_disclosure():
    resp = R(url="https://t/", headers={"server": "nginx/1.18.0"})
    ids = {f.check_id for f in checks.check_headers(resp)}
    assert "info.server.version" in ids


def test_cookie_flag_analysis():
    resp = R(url="https://t/", cookies=["sid=abc; Path=/"])
    ids = {f.check_id for f in checks.check_cookies(resp)}
    assert ids == {"cookie.secure.missing", "cookie.httponly.missing",
                   "cookie.samesite.missing"}
    # value must be redacted in evidence
    ev = checks.check_cookies(resp)[0].evidence[0]
    assert "abc" not in ev.response_headers.get("set-cookie", "")


def test_secure_cookie_not_flagged():
    resp = R(url="https://t/", cookies=["sid=abc; Secure; HttpOnly; SameSite=Lax"])
    assert checks.check_cookies(resp) == []


def test_stack_trace_disclosure():
    resp = R(url="https://t/x", text="Traceback (most recent call last):\n  File ...")
    f = checks.check_error_disclosure(resp)
    assert f and f[0].check_id == "disclosure.stack_trace"
