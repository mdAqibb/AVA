"""CVSS v3.1 base-score computation.

Pure implementation of the CVSS v3.1 base-metric equations
(https://www.first.org/cvss/v3.1/specification-document) so findings carry a
defensible numeric score derived from their vector string, rather than a
hand-waved number.
"""

from __future__ import annotations

import math
from typing import Optional

from ..core.models import Severity

# Metric weights (CVSS v3.1 spec, section 7).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
# Privileges Required depends on Scope (changed gives higher weight for L/H).
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(x: float) -> float:
    """CVSS roundup: round up to one decimal place (spec Appendix A)."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    parts = {}
    for chunk in vector.split("/"):
        if ":" in chunk and not chunk.startswith("CVSS"):
            k, v = chunk.split(":", 1)
            parts[k.strip()] = v.strip()
    return parts


def base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score from a vector string. Returns 0.0 if
    the vector is incomplete/unparseable."""
    m = parse_vector(vector)
    try:
        scope_changed = m["S"] == "C"
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        av, ac, pr, ui = _AV[m["AV"]], _AC[m["AC"]], pr_table[m["PR"]], _UI[m["UI"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return 0.0

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def score_and_band(vector: str) -> tuple[float, Severity]:
    score = base_score(vector)
    return score, Severity.from_cvss(score)
