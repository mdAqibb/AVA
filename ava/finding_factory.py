"""Build fully-populated Finding objects from catalog entries.

Checks call `make_finding(...)` with the dynamic bits (location, evidence,
confidence) and optional per-instance overrides; the static report content and
CVSS score come from the catalog + the CVSS calculator.
"""

from __future__ import annotations

from typing import Optional

from .core.models import Confidence, Evidence, Finding
from .findings_catalog import get as catalog_get
from .triage.severity import score_and_band


def make_finding(
    check_id: str,
    *,
    location_url: str,
    location_param: str = "",
    method: str = "GET",
    confidence: Confidence = Confidence.FIRM,
    evidence: Optional[list[Evidence]] = None,
    title_suffix: str = "",
    extra_note: str = "",
    cvss_vector: Optional[str] = None,
) -> Finding:
    entry = catalog_get(check_id)
    vector = cvss_vector or entry.cvss_vector
    score, band = score_and_band(vector)

    title = entry.title + (f" — {title_suffix}" if title_suffix else "")
    description = entry.description + (f"\n\n{extra_note}" if extra_note else "")

    return Finding(
        title=title,
        cwe=entry.cwe,
        owasp=entry.owasp,
        severity=band,
        cvss_vector=vector,
        cvss_score=score,
        confidence=confidence,
        location_url=location_url,
        location_param=location_param,
        method=method,
        description=description,
        root_cause=entry.root_cause,
        impact=entry.impact,
        remediation=entry.remediation,
        remediation_code=dict(entry.remediation_code),
        references=list(entry.references),
        evidence=evidence or [],
        check_id=check_id,
    )
