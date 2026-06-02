"""CVSS v3.1 base-score calculator vs. known-good vectors."""

import pytest

from ava.core.models import Severity
from ava.triage.severity import base_score, score_and_band

CASES = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.CRITICAL),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, Severity.INFO),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, Severity.MEDIUM),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, Severity.MEDIUM),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7, Severity.LOW),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, Severity.HIGH),
]


@pytest.mark.parametrize("vector,score,band", CASES)
def test_base_score(vector, score, band):
    assert base_score(vector) == score
    assert score_and_band(vector) == (score, band)


def test_unparseable_vector_is_zero():
    assert base_score("not-a-vector") == 0.0
