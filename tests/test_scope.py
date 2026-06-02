"""Scope matching and fail-closed scope loading."""

import pytest

from ava.intake.scope import ScopeError, load_scope


@pytest.mark.parametrize("url,allowed", [
    ("https://example.com/app", True),
    ("https://www.example.com/", True),
    ("https://api.staging.example.com/x", True),   # *. wildcard
    ("https://evil.com/", False),                  # off-scope host
    ("https://example.com/logout", False),         # denied path
    ("https://accounts.google.com/", False),       # hard deny
    ("ftp://example.com/", False),                 # bad scheme
    ("https://staging.example.com/", False),       # wildcard excludes apex
])
def test_url_in_scope(scope, url, allowed):
    assert scope.url_in_scope(url)[0] is allowed


def test_missing_file_raises(tmp_path):
    with pytest.raises(ScopeError):
        load_scope(tmp_path / "nope.yaml")


def test_empty_allowed_hosts_raises(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("allowed_hosts: []\n", encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope(p)


def test_non_mapping_raises(tmp_path):
    p = tmp_path / "s.yaml"
    p.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ScopeError):
        load_scope(p)
