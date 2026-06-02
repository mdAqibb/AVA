"""Phase coordinator.

Drives: intake/authorization -> recon/crawl -> passive -> active -> triage ->
report. Persists state and artifacts after each phase, so:
  * an interrupted run resumes from the last completed phase (reloading
    endpoints + accumulated findings instead of rescanning), and
  * reports regenerate from findings.json without rescanning.

Intake (authorization + client construction) always runs, even on resume, so
the authorization gate is re-validated every time and the (non-persisted)
HTTP client is rebuilt.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from .active.runner import run_active
from .core.http_client import HttpClient
from .core.logging import configure_logging, log
from .core.models import RunState
from .crawler.dom_crawler import dom_scan
from .crawler.static_crawler import Crawler
from .intake.authorization import authorize
from .intake.config import Config
from .passive.runner import run_passive
from .reporting import render
from .reporting.findings_store import Store
from .triage.triage import triage as run_triage

PHASES = ["intake", "recon", "passive", "active", "triage", "report"]


class Orchestrator:
    def __init__(self, config: Config):
        self.config = config
        self._existing: dict | None = None
        store = None

        if config.resume or config.resume_run_id:
            store = Store.find_resumable(config.output_dir, config.target,
                                         config.resume_run_id or None)
        if store is not None:
            self._existing = store.load_run()
            self.run_id = self._existing.get("run_id") if self._existing else None

        if store is None or not self.run_id:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            host = config.target.split("//")[-1].split("/")[0] or "run"
            self.run_id = f"{host}-{ts}"
            store = Store(f"{config.output_dir}/{self.run_id}")
            self._existing = None

        self.store = store
        self.logger = configure_logging(self.store.log_file, verbose=config.verbose)
        self.state: RunState | None = None
        self.client: HttpClient | None = None
        self.endpoints: list = []
        self.technologies: dict = {}
        self.findings: list = []
        self._completed: set = set()

    def run(self) -> None:
        try:
            self._intake()
            self._recon()
            self._passive()
            self._active()
            self._triage()
            self._report()
        finally:
            if self.client:
                self.client.close()
            if self.state:
                self.state.request_count = self.client.request_count if self.client else 0
                self.store.save_run(self.state)

    def _done(self, phase: str) -> None:
        if self.state and phase not in self.state.completed_phases:
            self.state.completed_phases.append(phase)
        self._completed.add(phase)
        if self.state:
            self.store.save_run(self.state)
        log(self.logger, logging.INFO, f"phase complete: {phase}")

    def _skip(self, phase: str) -> bool:
        if phase in self._completed:
            log(self.logger, logging.INFO, f"resume: skipping completed phase '{phase}'")
            return True
        return False

    # ---- phases --------------------------------------------------------

    def _intake(self) -> None:
        # Authorization gate ALWAYS runs (re-validate scope on every run).
        scope, audit = authorize(
            target=self.config.target,
            i_have_authorization=getattr(self.config, "_authorized", False),
            scope_path=self.config.scope_file,
            operator=self.config.operator,
        )
        self.scope = scope

        if self._existing:
            self.state = RunState(
                run_id=self.run_id, target=self.config.target,
                started_at=self._existing.get("started_at") or datetime.now(timezone.utc).isoformat(),
                completed_phases=list(self._existing.get("completed_phases", [])),
                authorization=audit,
                request_count=self._existing.get("request_count", 0),
            )
            self._completed = set(self.state.completed_phases)
            # Reload accumulated artifacts produced by earlier phases.
            self.endpoints, self.technologies = self.store.load_endpoint_objects()
            self.findings = self.store.load_raw_findings()
            log(self.logger, logging.INFO, "resuming run",
                run_id=self.run_id, completed=sorted(self._completed),
                endpoints=len(self.endpoints), findings=len(self.findings))
        else:
            self.state = RunState(run_id=self.run_id, target=self.config.target,
                                  authorization=audit)

        self.store.save_run(self.state)
        log(self.logger, logging.INFO, "authorization OK",
            target=self.config.target, scope=scope.source_path,
            window=audit.get("window_note"))

        self.client = HttpClient(
            scope=scope, rate=self.config.rate, concurrency=self.config.concurrency,
            global_cap=self.config.global_cap, logger=self.logger,
            timeout=self.config.timeout, allow_destructive=self.config.allow_destructive,
            retries=self.config.retries,
        )
        # intake is never "skipped"; mark complete (idempotent).
        if "intake" not in self._completed:
            self._done("intake")

    def _recon(self) -> None:
        if self._skip("recon"):
            return
        crawler = Crawler(self.client, self.logger, max_depth=self.config.max_depth,
                          concurrency=self.config.concurrency)
        endpoints = crawler.crawl(self.config.target)
        self.technologies = dict(crawler.technologies)

        if self.config.dom_crawl:
            dom_endpoints, dom_findings = dom_scan(self.config.target, self.scope,
                                                   self.logger)
            self.findings += dom_findings
            known = {e.key() for e in endpoints}
            endpoints += [e for e in dom_endpoints if e.key() not in known]

        self.endpoints = endpoints
        self.store.save_endpoints(endpoints, self.technologies)
        self.store.save_raw_findings(self.findings)
        log(self.logger, logging.INFO, "recon stored",
            endpoints=len(endpoints), requests=self.client.request_count)
        self._done("recon")

    def _passive(self) -> None:
        if self._skip("passive"):
            return
        if not self.config.passive:
            log(self.logger, logging.INFO, "passive checks disabled by config")
            self._done("passive")
            return
        self.findings += run_passive(self.client, self.config.target,
                                     self.endpoints, self.logger)
        self.store.save_raw_findings(self.findings)
        self._done("passive")

    def _active(self) -> None:
        if self._skip("active"):
            return
        if not self.config.active:
            log(self.logger, logging.INFO, "active checks disabled by config")
            self._done("active")
            return
        self.findings += run_active(self.client, self.endpoints, self.technologies,
                                    self.logger, self.config.heavy_fuzzing,
                                    concurrency=self.config.concurrency)
        self.store.save_raw_findings(self.findings)
        self._done("active")

    def _triage(self) -> None:
        if self._skip("triage") and self.store.load_findings():
            return
        self.findings = run_triage(self.findings, self.logger)
        self.store.save_findings(self.findings)
        self._done("triage")

    def _report(self) -> None:
        # Report always regenerates (cheap, no requests) from persisted findings.
        meta = {
            "target": self.config.target,
            "run_id": self.run_id,
            "request_count": self.client.request_count if self.client else 0,
            "authorized_by": (self.state.authorization.get("engagement", {})
                              .get("authorized_by") if self.state else None),
        }
        findings_dicts = self.store.load_findings()
        md = render.render_markdown(findings_dicts, meta, self.technologies)
        htm = render.render_html(findings_dicts, meta, self.technologies)
        (self.store.run_dir / "report.md").write_text(md, encoding="utf-8")
        (self.store.run_dir / "report.html").write_text(htm, encoding="utf-8")

        out_root = self.store.run_dir.parent
        (out_root / "report.md").write_text(md, encoding="utf-8")
        (out_root / "report.html").write_text(htm, encoding="utf-8")

        log(self.logger, logging.INFO, "report written",
            run_dir=str(self.store.run_dir), findings=len(findings_dicts))
        self._done("report")
