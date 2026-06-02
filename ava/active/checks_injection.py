"""OS command injection and server-side template injection (SSTI).

Command injection: marker-echo (detect a unique token echoed back) and, under
heavy fuzzing, a time-based `sleep` probe. SSTI: inject an arithmetic
expression and detect its *evaluated* product in the response. All payloads
are non-destructive (echo/sleep/arithmetic only).
"""

from __future__ import annotations

import logging

from ..core.logging import log
from ..core.models import Confidence, Endpoint
from ..finding_factory import make_finding
from . import injector, payloads
from .util import evidence_for

_DELAY_FACTOR = 0.85


def check_command_injection(client, endpoint: Endpoint, baseline,
                            logger: logging.Logger, heavy_fuzzing: bool) -> list:
    findings = []
    for target in injector.param_targets(endpoint):
        # Marker-echo: unambiguous and side-effect-free.
        tok = payloads.token("avc")
        hit = None
        for probe in payloads.cmd_echo_probes(tok):
            resp = injector.send(client, endpoint, target, probe)
            # The token must appear without the surrounding command syntax,
            # i.e. the echo actually ran (not just reflected verbatim).
            if tok in (resp.text or "") and probe not in (resp.text or ""):
                hit = (probe, resp)
                break
        if hit:
            probe, resp = hit
            log(logger, logging.INFO, "command injection (echo)", url=endpoint.url,
                param=target.name)
            findings.append(make_finding(
                "injection.command", location_url=endpoint.url, method=endpoint.method,
                location_param=target.name, confidence=Confidence.CONFIRMED,
                extra_note=f"Injected command echoed unique marker. Payload: {probe!r}",
                evidence=[evidence_for(endpoint, target, probe, resp,
                                       note="Unique echo marker present in output")]))
            continue

        if heavy_fuzzing and baseline.elapsed_ms < payloads.TIME_DELAY * 1000 * _DELAY_FACTOR:
            threshold = payloads.TIME_DELAY * 1000 * _DELAY_FACTOR
            for probe in payloads.cmd_time_probes():
                r1 = injector.send(client, endpoint, target, probe)
                if r1.elapsed_ms < threshold:
                    continue
                r2 = injector.send(client, endpoint, target, probe)
                if r2.elapsed_ms >= threshold:
                    log(logger, logging.INFO, "command injection (time)",
                        url=endpoint.url, param=target.name)
                    findings.append(make_finding(
                        "injection.command", location_url=endpoint.url,
                        method=endpoint.method, location_param=target.name,
                        confidence=Confidence.CONFIRMED,
                        extra_note=(f"Time-based: {probe!r} delayed responses to "
                                    f"{r1.elapsed_ms:.0f}/{r2.elapsed_ms:.0f}ms "
                                    f"(baseline {baseline.elapsed_ms:.0f}ms)."),
                        evidence=[evidence_for(endpoint, target, probe, r1,
                                               note=f"Delayed {r1.elapsed_ms:.0f}ms")]))
                    break
    return findings


def check_template_injection(client, endpoint: Endpoint, logger: logging.Logger) -> list:
    findings = []
    for target in injector.param_targets(endpoint):
        for probe in payloads.ssti_probes():
            resp = injector.send(client, endpoint, target, probe)
            body = resp.text or ""
            # The evaluated product must appear while the literal expression
            # does not (i.e. the engine computed it).
            if payloads.SSTI_EXPECT in body and probe not in body:
                log(logger, logging.INFO, "SSTI", url=endpoint.url, param=target.name)
                findings.append(make_finding(
                    "injection.template", location_url=endpoint.url,
                    method=endpoint.method, location_param=target.name,
                    confidence=Confidence.CONFIRMED,
                    extra_note=(f"Template expression evaluated: {probe!r} produced "
                                f"{payloads.SSTI_EXPECT} in the response."),
                    evidence=[evidence_for(endpoint, target, probe, resp,
                                           note=f"Evaluated product {payloads.SSTI_EXPECT} present")]))
                break
    return findings
