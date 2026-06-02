"""The authorization gate fails closed."""

import pytest

from ava.intake.authorization import AuthorizationError, authorize


def test_refuses_without_flag(scope_file):
    with pytest.raises(AuthorizationError):
        authorize("https://example.com", False, scope_file)


def test_refuses_off_scope_target(scope_file):
    with pytest.raises(AuthorizationError):
        authorize("https://evil.com", True, scope_file)


def test_refuses_missing_scope(tmp_path):
    with pytest.raises(AuthorizationError):
        authorize("https://example.com", True, str(tmp_path / "nope.yaml"))


def test_authorizes_valid_request(scope_file):
    scope, audit = authorize("https://example.com", True, scope_file, operator="me")
    assert audit["asserted_authorization"] is True
    assert audit["operator"] == "me"
    assert len(audit["scope_sha256"]) == 64
    assert "engagement" in audit
