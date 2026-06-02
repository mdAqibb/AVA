"""The authorization gate. Fails CLOSED.

The tool refuses to run unless, at minimum:
  1. The operator passed --i-have-authorization (explicit assertion), and
  2. A scope.yaml exists, parses, and declares a non-empty allowed_hosts, and
  3. The --target matches an in-scope host/path.

It also records an audit assertion (who/what/when + a hash of the scope file)
into the run state so there is a durable trail of what was authorized.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .scope import Scope, ScopeError, load_scope


class AuthorizationError(RuntimeError):
    """Raised whenever the authorization preconditions are not met."""


def _scope_hash(scope_path: str) -> str:
    return hashlib.sha256(Path(scope_path).read_bytes()).hexdigest()


def authorize(
    target: str,
    i_have_authorization: bool,
    scope_path: str,
    operator: str = "",
) -> tuple[Scope, dict]:
    """Validate authorization preconditions and return (scope, audit_record).

    Raises AuthorizationError on any failure — the caller must not proceed.
    """
    if not i_have_authorization:
        raise AuthorizationError(
            "Refusing to run: --i-have-authorization was not provided. "
            "AVA only runs against targets you are explicitly authorized to test. "
            "See DISCLAIMER.md."
        )

    if not target:
        raise AuthorizationError("Refusing to run: no --target supplied.")

    try:
        scope = load_scope(scope_path)
    except ScopeError as e:
        raise AuthorizationError(
            f"Refusing to run: scope problem — {e}"
        ) from e

    allowed, reason = scope.url_in_scope(target)
    if not allowed:
        raise AuthorizationError(
            f"Refusing to run: --target {target!r} is not in scope ({reason}). "
            f"Add it to allowed_hosts/allowed_paths in {scope_path} if it is authorized."
        )

    # Optional: warn-but-allow if outside the declared engagement window.
    window_note = _check_window(scope)

    audit = {
        "asserted_authorization": True,
        "operator": operator or "(unspecified)",
        "target": target,
        "scope_file": scope.source_path,
        "scope_sha256": _scope_hash(scope.source_path),
        "engagement": scope.engagement,
        "window_note": window_note,
        "asserted_at": datetime.now(timezone.utc).isoformat(),
    }
    return scope, audit


def _check_window(scope: Scope) -> str:
    eng = scope.engagement or {}
    start, end = eng.get("window_start"), eng.get("window_end")
    if not (start and end):
        return "no engagement window declared"
    try:
        now = datetime.now(timezone.utc)
        s = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        e = datetime.fromisoformat(str(end).replace("Z", "+00:00"))
    except ValueError:
        return "engagement window unparseable"
    if now < s:
        return f"WARNING: before declared window start {start}"
    if now > e:
        return f"WARNING: after declared window end {end}"
    return "within declared engagement window"
