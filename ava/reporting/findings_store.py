"""JSON-backed persistence — the source of truth for a run.

Layout (under output/<run_id>/):
  run.json            RunState (audit trail, completed phases, request count)
  endpoints.json      discovered endpoints + technologies
  raw_findings.json   accumulated pre-triage findings (enables resume)
  findings.json       triaged findings

Reports regenerate from these files without rescanning, and an interrupted run
resumes from the last completed phase by reloading these artifacts.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from ..core.models import Endpoint, Finding, RunState


class Store:
    def __init__(self, run_dir: str | Path):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)

    # ---- run discovery (resume) ---------------------------------------

    @classmethod
    def find_resumable(cls, output_dir: str | Path, target: str,
                       run_id: Optional[str] = None) -> Optional["Store"]:
        """Locate an existing run to resume.

        If `run_id` is given, use that directory. Otherwise pick the most
        recent run whose target matches and whose report phase is incomplete.
        Returns None if nothing suitable exists.
        """
        root = Path(output_dir)
        if run_id:
            d = root / run_id
            return cls(d) if (d / "run.json").is_file() else None
        if not root.is_dir():
            return None
        candidates = []
        for d in root.iterdir():
            run_file = d / "run.json"
            if not run_file.is_file():
                continue
            try:
                data = json.loads(run_file.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            if data.get("target") == target and "report" not in data.get("completed_phases", []):
                candidates.append((data.get("started_at", ""), d))
        if not candidates:
            return None
        candidates.sort()
        return cls(candidates[-1][1])

    @property
    def log_file(self) -> Path:
        return self.run_dir / "assess.log"

    def _write(self, name: str, obj: Any) -> None:
        path = self.run_dir / name
        path.write_text(json.dumps(obj, indent=2, default=str), encoding="utf-8")

    def _read(self, name: str) -> Any:
        path = self.run_dir / name
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    # ---- run state -----------------------------------------------------

    def save_run(self, state: RunState) -> None:
        self._write("run.json", state.to_dict())

    def load_run(self) -> dict | None:
        return self._read("run.json")

    # ---- endpoints -----------------------------------------------------

    def save_endpoints(self, endpoints: list[Endpoint], technologies: dict) -> None:
        self._write("endpoints.json", {
            "technologies": technologies,
            "endpoints": [asdict(e) for e in endpoints],
        })

    def load_endpoints(self) -> dict | None:
        return self._read("endpoints.json")

    def load_endpoint_objects(self) -> tuple[list[Endpoint], dict]:
        data = self._read("endpoints.json") or {}
        endpoints = [Endpoint.from_dict(e) for e in data.get("endpoints", [])]
        return endpoints, dict(data.get("technologies", {}))

    # ---- findings ------------------------------------------------------

    def save_raw_findings(self, findings: list[Finding]) -> None:
        """Persist accumulated pre-triage findings so resume can reload them."""
        self._write("raw_findings.json", [f.to_dict() for f in findings])

    def load_raw_findings(self) -> list[Finding]:
        return [Finding.from_dict(d) for d in (self._read("raw_findings.json") or [])]

    def save_findings(self, findings: list[Finding]) -> None:
        self._write("findings.json", [f.to_dict() for f in findings])

    def load_findings(self) -> list[dict]:
        return self._read("findings.json") or []
