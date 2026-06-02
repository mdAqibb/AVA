"""The central client's safety guards (destructive payloads + scope).

Constructed via __new__ so the guards can be tested without httpx installed
(HttpClient.__init__ builds an httpx.Client; the guards themselves do not need
it)."""

import logging

import pytest

from ava.core.http_client import (DestructivePayloadError, HttpClient,
                                   OutOfScopeError)


def _guarded_client(scope):
    c = HttpClient.__new__(HttpClient)
    c.scope = scope
    c.allow_destructive = False
    c.logger = logging.getLogger("ava.test")
    return c


@pytest.mark.parametrize("payload", [
    "1; DROP TABLE users",
    "'; DELETE FROM accounts --",
    "x' OR 1=1; UPDATE users SET admin=1 --",
    "; rm -rf /",
    ":(){ :|:& };:",
])
def test_destructive_payloads_blocked(scope, payload):
    c = _guarded_client(scope)
    with pytest.raises(DestructivePayloadError):
        c._guard_destructive("https://example.com/x", {"q": payload}, None, None)


@pytest.mark.parametrize("payload", [
    "1' AND '1'='1",          # SQLi boolean — confirmation, not destructive
    "' AND SLEEP(3)-- -",     # time-based — allowed
    "<svg/onload=alert(1)>",  # XSS probe
    "{{919*919}}",            # SSTI probe
])
def test_confirmation_payloads_allowed(scope, payload):
    c = _guarded_client(scope)
    c._guard_destructive("https://example.com/x", {"q": payload}, None, None)  # no raise


def test_scope_guard_refuses_off_scope(scope):
    c = _guarded_client(scope)
    with pytest.raises(OutOfScopeError):
        c._guard_scope("https://evil.com/")
    c._guard_scope("https://example.com/ok")  # in scope -> no raise


def test_destructive_allowed_when_opted_in(scope):
    c = _guarded_client(scope)
    c.allow_destructive = True
    c._guard_destructive("https://example.com/x", {"q": "DROP TABLE t"}, None, None)
