"""Triage: deduplicate, filter likely false positives, and rank findings.

Severity/CVSS are assigned at finding-creation time (see finding_factory), so
triage here focuses on collapsing duplicates, applying conservative
false-positive heuristics, and ordering by impact for the report.
"""

from __future__ import annotations

import logging

from ..core.logging import log
from ..core.models import Confidence, Finding

# Cap evidence retained per merged finding to keep reports readable.
_MAX_EVIDENCE = 5


def dedup(findings: list[Finding]) -> list[Finding]:
    """Merge findings sharing a fingerprint (same bug, location, param).

    Keeps the higher confidence/severity instance and accumulates evidence.
    """
    merged: dict[str, Finding] = {}
    for f in findings:
        fp = f.fingerprint()
        if fp not in merged:
            merged[fp] = f
            continue
        cur = merged[fp]
        # Prefer the stronger confidence; keep the higher severity score.
        if _confidence_rank(f.confidence) > _confidence_rank(cur.confidence):
            cur.confidence = f.confidence
        if f.cvss_score > cur.cvss_score:
            cur.cvss_score, cur.severity = f.cvss_score, f.severity
        for ev in f.evidence:
            if len(cur.evidence) < _MAX_EVIDENCE:
                cur.evidence.append(ev)
    return list(merged.values())


def filter_false_positives(findings: list[Finding], logger: logging.Logger) -> list[Finding]:
    """Conservative FP heuristics. Drops only high-confidence noise; anything
    uncertain is kept and flagged for human review."""
    kept: list[Finding] = []
    dropped = 0
    for f in findings:
        if _is_false_positive(f):
            dropped += 1
            continue
        kept.append(f)
    if dropped:
        log(logger, logging.INFO, "false-positive filter dropped findings", count=dropped)
    return kept


def _is_false_positive(f: Finding) -> bool:
    # Example heuristic: a "missing header" finding on a non-2xx/3xx response is
    # less meaningful; we keep it but this is where stack-specific suppressions
    # would live. Currently no aggressive suppression — bias toward reporting.
    return False


def rank(findings: list[Finding]) -> list[Finding]:
    """Sort by severity (desc), then CVSS score (desc), then confidence (desc)."""
    return sorted(
        findings,
        key=lambda f: (f.severity.rank, f.cvss_score, _confidence_rank(f.confidence)),
        reverse=True,
    )


def triage(findings: list[Finding], logger: logging.Logger) -> list[Finding]:
    deduped = dedup(findings)
    filtered = filter_false_positives(deduped, logger)
    ranked = rank(filtered)
    log(logger, logging.INFO, "triage complete",
        input=len(findings), deduped=len(deduped), final=len(ranked))
    return ranked


def _confidence_rank(c: Confidence) -> int:
    return {Confidence.TENTATIVE: 0, Confidence.FIRM: 1, Confidence.CONFIRMED: 2}[c]
