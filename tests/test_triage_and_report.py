"""Triage (dedup/rank) and report rendering."""

from ava.core.models import Confidence, Evidence, Severity
from ava.finding_factory import make_finding
from ava.reporting import render
from ava.triage.triage import dedup, rank, triage


def test_dedup_collapses_same_fingerprint(quiet_logger):
    a = make_finding("header.csp.missing", location_url="https://t")
    b = make_finding("header.csp.missing", location_url="https://t")
    out = dedup([a, b])
    assert len(out) == 1


def test_dedup_keeps_distinct(quiet_logger):
    a = make_finding("header.csp.missing", location_url="https://t")
    b = make_finding("header.hsts.missing", location_url="https://t")
    assert len(dedup([a, b])) == 2


def test_rank_orders_by_severity():
    low = make_finding("header.referrer.missing", location_url="https://t")
    high = make_finding("disclosure.exposed_file", location_url="https://t/.env")
    ordered = rank([low, high])
    assert ordered[0].severity.rank >= ordered[1].severity.rank
    assert ordered[0].check_id == "disclosure.exposed_file"


def test_full_triage_and_render(quiet_logger):
    ev = [Evidence(request_line="GET https://t/", response_status=200, note="x")]
    findings = [
        make_finding("header.csp.missing", location_url="https://t", evidence=ev),
        make_finding("header.csp.missing", location_url="https://t", evidence=ev),  # dup
        make_finding("disclosure.exposed_file", location_url="https://t/.env",
                     title_suffix=".env", confidence=Confidence.CONFIRMED, evidence=ev),
    ]
    triaged = triage(findings, quiet_logger)
    assert len(triaged) == 2                       # dup collapsed
    assert triaged[0].check_id == "disclosure.exposed_file"   # ranked first

    meta = {"target": "https://t", "run_id": "r1", "request_count": 5,
            "authorized_by": "me@t"}
    dicts = [f.to_dict() for f in triaged]
    md = render.render_markdown(dicts, meta, {"nginx": "1.18"})
    html = render.render_html(dicts, meta, {"nginx": "1.18"})
    assert "Executive summary" in md and "CVSS" in md
    assert "<!doctype html>" in html and "Executive summary" in html
    # severity counts present
    assert "High" in md and "Total findings" in md
