"""Resume semantics — the orchestrator with the network layer stubbed out."""

import glob
import json
import os

import pytest

import ava.orchestrator as O
from ava.core.models import Endpoint, HttpParam
from ava.intake.config import Config
from ava.triage.triage import triage as real_triage
from tests.helpers import make_finding


@pytest.fixture
def stubbed(monkeypatch):
    """Stub network + phase workers; count how often each phase runs."""
    calls = {"crawl": 0, "passive": 0, "active": 0}

    class DummyClient:
        def __init__(self, *a, **k):
            self.request_count = 7

        def close(self):
            pass

    class DummyCrawler:
        def __init__(self, *a, **k):
            self.technologies = {"nginx": "1.18"}

        def crawl(self, seed):
            calls["crawl"] += 1
            return [Endpoint(url="https://example.com/i?id=1", method="GET",
                             params=[HttpParam("id", "query", "1")])]

    def fake_passive(*a, **k):
        calls["passive"] += 1
        return [make_finding("passive.x", location_url="https://example.com/i")]

    def fake_active(*a, **k):
        calls["active"] += 1
        return [make_finding("active.x", location_url="https://example.com/i")]

    monkeypatch.setattr(O, "HttpClient", DummyClient)
    monkeypatch.setattr(O, "Crawler", DummyCrawler)
    monkeypatch.setattr(O, "dom_scan", lambda *a, **k: ([], []))
    monkeypatch.setattr(O, "run_passive", fake_passive)
    monkeypatch.setattr(O, "run_active", fake_active)
    monkeypatch.setattr(O, "run_triage", real_triage)   # keep real dedup
    return calls


def _config(scope_file, out_dir, **over):
    c = Config()
    c.target = "https://example.com"
    c.scope_file = scope_file
    c.output_dir = str(out_dir)
    c.dom_crawl = False
    c._authorized = True
    for k, v in over.items():
        setattr(c, k, v)
    return c


def test_fresh_run_completes_and_persists(stubbed, scope_file, tmp_path):
    out = tmp_path / "output"
    O.Orchestrator(_config(scope_file, out)).run()
    assert stubbed == {"crawl": 1, "passive": 1, "active": 1}
    rundir = glob.glob(str(out / "example.com-*"))[0]
    run = json.load(open(f"{rundir}/run.json"))
    assert run["completed_phases"] == ["intake", "recon", "passive", "active",
                                       "triage", "report"]
    assert len(json.load(open(f"{rundir}/findings.json"))) == 2
    assert os.path.exists(f"{out}/report.html")


def test_interrupted_run_resumes_remaining_phases(stubbed, scope_file, tmp_path):
    out = tmp_path / "output"
    O.Orchestrator(_config(scope_file, out)).run()
    rundir = glob.glob(str(out / "example.com-*"))[0]

    # Simulate interruption right after passive.
    run = json.load(open(f"{rundir}/run.json"))
    run["completed_phases"] = ["intake", "recon", "passive"]
    json.dump(run, open(f"{rundir}/run.json", "w"))
    json.dump([make_finding("passive.x", location_url="https://example.com/i").to_dict()],
              open(f"{rundir}/raw_findings.json", "w"))
    os.remove(f"{rundir}/findings.json")

    O.Orchestrator(_config(scope_file, out, resume=True)).run()
    # recon/passive skipped, active/triage/report re-run; dir reused.
    assert stubbed == {"crawl": 1, "passive": 1, "active": 2}
    assert len(glob.glob(str(out / "example.com-*"))) == 1
    final = {f["check_id"] for f in json.load(open(f"{rundir}/findings.json"))}
    assert final == {"passive.x", "active.x"}


def test_resume_with_nothing_to_resume_starts_fresh(stubbed, scope_file, tmp_path):
    out = tmp_path / "output"
    O.Orchestrator(_config(scope_file, out)).run()          # complete run
    O.Orchestrator(_config(scope_file, out, resume=True)).run()  # nothing incomplete
    # A second crawl happened (fresh run) since the prior run was complete.
    assert stubbed["crawl"] == 2


def test_resume_run_id_regenerates_report_without_rescanning(stubbed, scope_file, tmp_path):
    out = tmp_path / "output"
    O.Orchestrator(_config(scope_file, out)).run()
    rundir = glob.glob(str(out / "example.com-*"))[0]
    rid = os.path.basename(rundir)
    os.remove(f"{rundir}/report.html")

    O.Orchestrator(_config(scope_file, out, resume_run_id=rid)).run()
    # No phase worker re-ran; report regenerated.
    assert stubbed == {"crawl": 1, "passive": 1, "active": 1}
    assert os.path.exists(f"{rundir}/report.html")
