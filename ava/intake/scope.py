"""Scope parsing and the in-scope decision function.

This module is the authority on "may we contact this URL?". It is consulted
by the HTTP client on *every* request (including redirect targets), so the
decision logic is deliberately small, explicit, and fail-closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml


class ScopeError(ValueError):
    """Raised when scope.yaml is missing, malformed, or empty."""


@dataclass
class Scope:
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    denied_paths: list[str] = field(default_factory=list)
    hard_deny_hosts: list[str] = field(default_factory=list)
    engagement: dict = field(default_factory=dict)
    source_path: str = ""

    # ---- host matching -------------------------------------------------

    @staticmethod
    def _normalize_host(host: str) -> str:
        return (host or "").strip().lower().rstrip(".")

    def _host_matches(self, host: str, pattern: str) -> bool:
        host = self._normalize_host(host)
        pattern = self._normalize_host(pattern)
        if pattern.startswith("*."):
            suffix = pattern[1:]            # ".staging.example.com"
            return host.endswith(suffix) and host != suffix.lstrip(".")
        return host == pattern

    def host_in_scope(self, host: str) -> bool:
        host = self._normalize_host(host)
        if not host:
            return False
        if any(self._host_matches(host, p) for p in self.hard_deny_hosts):
            return False
        return any(self._host_matches(host, p) for p in self.allowed_hosts)

    # ---- path matching -------------------------------------------------

    def path_in_scope(self, path: str) -> bool:
        path = path or "/"
        if any(path.startswith(d) for d in self.denied_paths):
            return False
        if not self.allowed_paths:           # empty allow-list => all paths allowed
            return True
        return any(path.startswith(a) for a in self.allowed_paths)

    # ---- combined ------------------------------------------------------

    def url_in_scope(self, url: str) -> tuple[bool, str]:
        """Return (allowed, reason). Fail closed on parse problems."""
        try:
            parsed = urlparse(url)
        except Exception:
            return False, "unparseable URL"
        if parsed.scheme not in ("http", "https"):
            return False, f"disallowed scheme '{parsed.scheme}'"
        if not self.host_in_scope(parsed.hostname or ""):
            return False, f"host '{parsed.hostname}' not in allowed_hosts"
        if not self.path_in_scope(parsed.path or "/"):
            return False, f"path '{parsed.path}' outside allowed/denied paths"
        return True, "in scope"


def load_scope(path: str | Path) -> Scope:
    """Load and validate scope.yaml. Fail closed: any problem raises."""
    p = Path(path)
    if not p.is_file():
        raise ScopeError(f"Scope file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as e:
        raise ScopeError(f"Could not parse {p}: {e}") from e
    if not isinstance(data, dict):
        raise ScopeError(f"{p} must contain a YAML mapping at the top level.")

    allowed_hosts = data.get("allowed_hosts") or []
    if not isinstance(allowed_hosts, list) or not allowed_hosts:
        raise ScopeError(
            f"{p} must declare a non-empty 'allowed_hosts' list. "
            "Refusing to run without a declared scope."
        )

    return Scope(
        allowed_hosts=[str(h) for h in allowed_hosts],
        allowed_paths=[str(x) for x in (data.get("allowed_paths") or [])],
        denied_paths=[str(x) for x in (data.get("denied_paths") or [])],
        hard_deny_hosts=[str(x) for x in (data.get("hard_deny_hosts") or [])],
        engagement=dict(data.get("engagement") or {}),
        source_path=str(p.resolve()),
    )
