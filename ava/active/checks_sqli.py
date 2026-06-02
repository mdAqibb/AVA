"""SQL injection detection — error-based, boolean-blind, and time-blind.

All payloads are confirmation-grade and non-destructive (no data-modifying
statements; time probes use SLEEP/WAITFOR/pg_sleep only). Time-based probing
is gated behind heavy fuzzing because it deliberately delays responses.
"""

from __future__ import annotations

import logging

from ..core.logging import log
from ..core.models import Confidence, Endpoint, Evidence
from ..finding_factory import make_finding
from . import injector, payloads
from .util import body_similarity, evidence_for

# A response is "delayed" if it takes at least this fraction of the probe delay.
_DELAY_FACTOR = 0.85
# Boolean-blind thresholds: TRUE should look like baseline, FALSE should differ.
_SAME = 0.95
_DIFF = 0.90


def check_sqli(client, endpoint: Endpoint, baseline, logger: logging.Logger,
               heavy_fuzzing: bool) -> list:
    findings = []
    for target in injector.param_targets(endpoint):
        f = _test_param(client, endpoint, target, baseline, logger, heavy_fuzzing)
        if f:
            findings.append(f)
    return findings


def _test_param(client, endpoint, target, baseline, logger, heavy_fuzzing):
    # 1) Error-based -------------------------------------------------------
    for probe in payloads.SQLI_ERROR_PROBES:
        resp = injector.send(client, endpoint, target, probe)
        sig = _matched_sql_error(resp.text)
        if sig and not _matched_sql_error(baseline.text):
            log(logger, logging.INFO, "SQLi (error-based)", url=endpoint.url,
                param=target.name)
            return make_finding(
                "injection.sqli", location_url=endpoint.url, method=endpoint.method,
                location_param=target.name, confidence=Confidence.CONFIRMED,
                extra_note=f"DB error provoked by payload {probe!r} (signature: /{sig}/).",
                evidence=[evidence_for(endpoint, target, probe, resp,
                                       note=f"SQL error signature matched: /{sig}/")],
            )

    # 2) Boolean-blind -----------------------------------------------------
    base_val = (injector.baseline_values(endpoint).get(target.name) or "1")
    for true_p, false_p in payloads.sqli_boolean_pairs(base_val):
        rt = injector.send(client, endpoint, target, true_p)
        rf = injector.send(client, endpoint, target, false_p)
        sim_tb = body_similarity(rt.text, baseline.text)
        sim_tf = body_similarity(rt.text, rf.text)
        if rt.status == baseline.status and sim_tb >= _SAME and sim_tf < _DIFF:
            log(logger, logging.INFO, "SQLi (boolean-blind)", url=endpoint.url,
                param=target.name)
            return make_finding(
                "injection.sqli", location_url=endpoint.url, method=endpoint.method,
                location_param=target.name, confidence=Confidence.FIRM,
                extra_note=("Boolean-blind signal: TRUE condition matches the "
                            f"baseline ({sim_tb:.2f}) while FALSE differs "
                            f"({sim_tf:.2f}). Payloads: {true_p!r} vs {false_p!r}."),
                evidence=[evidence_for(endpoint, target, true_p, rt,
                                       note="TRUE-condition response (≈ baseline)"),
                          evidence_for(endpoint, target, false_p, rf,
                                       note="FALSE-condition response (differs)")],
            )

    # 3) Time-blind (heavy fuzzing only) -----------------------------------
    if heavy_fuzzing and baseline.elapsed_ms < payloads.TIME_DELAY * 1000 * _DELAY_FACTOR:
        threshold = payloads.TIME_DELAY * 1000 * _DELAY_FACTOR
        for probe in payloads.sqli_time_probes(base_val):
            r1 = injector.send(client, endpoint, target, probe)
            if r1.elapsed_ms < threshold:
                continue
            # Confirm reproducibility once before reporting.
            r2 = injector.send(client, endpoint, target, probe)
            if r2.elapsed_ms >= threshold:
                log(logger, logging.INFO, "SQLi (time-blind)", url=endpoint.url,
                    param=target.name)
                return make_finding(
                    "injection.sqli", location_url=endpoint.url, method=endpoint.method,
                    location_param=target.name, confidence=Confidence.CONFIRMED,
                    extra_note=(f"Time-based blind: payload {probe!r} delayed the "
                                f"response to {r1.elapsed_ms:.0f}ms and {r2.elapsed_ms:.0f}ms "
                                f"(baseline {baseline.elapsed_ms:.0f}ms)."),
                    evidence=[evidence_for(endpoint, target, probe, r1,
                                           note=f"Delayed {r1.elapsed_ms:.0f}ms vs baseline "
                                                f"{baseline.elapsed_ms:.0f}ms")],
                )
    return None


def _matched_sql_error(text: str):
    for rx in payloads.SQL_ERROR_SIGNATURES:
        if rx.search(text or ""):
            return rx.pattern
    return None
