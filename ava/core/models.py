"""Structured data models shared across phases.

Findings are persisted as JSON (see reporting.findings_store) so reports can
be regenerated without rescanning. Keep these dataclasses
serialization-friendly: primitives, lists, dicts, and other dataclasses only.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    """CVSS-style qualitative bands. Ordered for sorting via .rank."""

    INFO = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score == 0:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL


class Confidence(str, Enum):
    """How sure the engine is. Low-confidence findings are flagged for human
    review rather than reported as confirmed."""

    TENTATIVE = "Tentative"   # heuristic signal only
    FIRM = "Firm"             # behavior consistent with the vuln
    CONFIRMED = "Confirmed"   # reproduced with a deterministic marker


@dataclass
class HttpParam:
    name: str
    location: str            # "query" | "body" | "header" | "cookie" | "path"
    example: str = ""


@dataclass
class Form:
    action: str
    method: str
    inputs: list[HttpParam] = field(default_factory=list)
    has_csrf_token: bool = False


@dataclass
class Endpoint:
    """A discovered, in-scope request target produced by the crawler."""

    url: str
    method: str = "GET"
    params: list[HttpParam] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    status: Optional[int] = None
    content_type: str = ""
    title: str = ""
    discovered_from: str = ""
    depth: int = 0

    def key(self) -> str:
        return f"{self.method} {self.url}"

    @classmethod
    def from_dict(cls, d: dict) -> "Endpoint":
        params = [HttpParam(**p) for p in d.get("params", [])]
        forms = [Form(action=f.get("action", ""), method=f.get("method", "GET"),
                      inputs=[HttpParam(**i) for i in f.get("inputs", [])],
                      has_csrf_token=f.get("has_csrf_token", False))
                 for f in d.get("forms", [])]
        return cls(
            url=d["url"], method=d.get("method", "GET"), params=params, forms=forms,
            status=d.get("status"), content_type=d.get("content_type", ""),
            title=d.get("title", ""), discovered_from=d.get("discovered_from", ""),
            depth=d.get("depth", 0),
        )


@dataclass
class Evidence:
    """Redacted request/response pair supporting a finding."""

    request_line: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_status: Optional[int] = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_excerpt: str = ""
    note: str = ""


@dataclass
class Finding:
    title: str
    cwe: str                          # e.g. "CWE-89"
    owasp: str                        # e.g. "A03:2021 Injection"
    severity: Severity
    cvss_vector: str = ""
    cvss_score: float = 0.0
    confidence: Confidence = Confidence.TENTATIVE
    location_url: str = ""
    location_param: str = ""
    method: str = "GET"
    description: str = ""             # what it is
    root_cause: str = ""             # why it exists
    impact: str = ""                 # what an attacker achieves
    remediation: str = ""            # actionable fix (prose)
    remediation_code: dict[str, str] = field(default_factory=dict)  # lang -> snippet
    references: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    check_id: str = ""               # which active/passive module produced it
    created_at: str = field(default_factory=utcnow_iso)

    def fingerprint(self) -> str:
        """Stable identity for dedup: same bug at same location/param."""
        basis = f"{self.cwe}|{self.method}|{self.location_url}|{self.location_param}|{self.check_id}"
        return hashlib.sha256(basis.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["id"] = self.fingerprint()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            title=d["title"], cwe=d["cwe"], owasp=d["owasp"],
            severity=Severity(d["severity"]), cvss_vector=d.get("cvss_vector", ""),
            cvss_score=d.get("cvss_score", 0.0),
            confidence=Confidence(d.get("confidence", Confidence.TENTATIVE.value)),
            location_url=d.get("location_url", ""), location_param=d.get("location_param", ""),
            method=d.get("method", "GET"), description=d.get("description", ""),
            root_cause=d.get("root_cause", ""), impact=d.get("impact", ""),
            remediation=d.get("remediation", ""),
            remediation_code=dict(d.get("remediation_code", {})),
            references=list(d.get("references", [])),
            evidence=[Evidence(**ev) for ev in d.get("evidence", [])],
            check_id=d.get("check_id", ""),
            created_at=d.get("created_at", utcnow_iso()),
        )


@dataclass
class RunState:
    """Persisted run record — drives resume and the audit trail."""

    run_id: str
    target: str
    started_at: str = field(default_factory=utcnow_iso)
    completed_phases: list[str] = field(default_factory=list)
    authorization: dict[str, Any] = field(default_factory=dict)
    request_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
