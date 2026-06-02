"""Pytest fixtures shared across the suite."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

# Make the repo root importable (assess.py + ava package) when running pytest.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.helpers import SCOPE_YAML  # noqa: E402


@pytest.fixture
def quiet_logger() -> logging.Logger:
    log = logging.getLogger("ava.test")
    log.handlers.clear()
    log.addHandler(logging.NullHandler())
    log.setLevel(logging.CRITICAL)
    return log


@pytest.fixture
def scope_file(tmp_path) -> str:
    p = tmp_path / "scope.yaml"
    p.write_text(SCOPE_YAML, encoding="utf-8")
    return str(p)


@pytest.fixture
def scope(scope_file):
    from ava.intake.scope import load_scope
    return load_scope(scope_file)
