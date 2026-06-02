"""TLS configuration analysis (wraps sslyze).

sslyze is an optional, heavier dependency. If it is not installed, this module
degrades gracefully: it logs a note and returns no findings rather than
failing the run.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..core.logging import log
from ..core.models import Confidence, Evidence
from ..finding_factory import make_finding

# Protocol versions we consider weak/deprecated.
_WEAK_PROTOCOLS = {"SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"}
_CERT_EXPIRY_WARN_DAYS = 21


def analyze_tls(target: str, logger: logging.Logger) -> list:
    parsed = urlparse(target)
    if parsed.scheme != "https":
        return []
    host = parsed.hostname
    port = parsed.port or 443

    try:
        from sslyze import (  # type: ignore
            Scanner, ServerScanRequest, ServerNetworkLocation, ScanCommand,
        )
    except ImportError:
        log(logger, logging.WARNING,
            "sslyze not installed — skipping TLS analysis (pip install sslyze)")
        return []

    findings: list = []
    try:
        scanner = Scanner()
        scanner.queue_scans([ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=host, port=port),
            scan_commands={
                ScanCommand.SSL_2_0_CIPHER_SUITES, ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES, ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.CERTIFICATE_INFO,
            },
        )])
        for result in scanner.get_results():
            findings += _evaluate_result(result, host, logger)
    except Exception as e:
        log(logger, logging.WARNING, "TLS analysis error", host=host, error=str(e))
    return findings


def _evaluate_result(result, host: str, logger: logging.Logger) -> list:
    findings = []
    attempts = getattr(result.scan_result, "__dict__", {})

    # Weak protocol support
    proto_map = {
        "ssl_2_0_cipher_suites": "SSL 2.0",
        "ssl_3_0_cipher_suites": "SSL 3.0",
        "tls_1_0_cipher_suites": "TLS 1.0",
        "tls_1_1_cipher_suites": "TLS 1.1",
    }
    weak_found = []
    for attr, label in proto_map.items():
        attempt = attempts.get(attr)
        suites = _accepted_cipher_suites(attempt)
        if suites:
            weak_found.append(label)
    if weak_found:
        findings.append(make_finding(
            "tls.weak_protocol", location_url=f"https://{host}",
            confidence=Confidence.CONFIRMED,
            extra_note=f"Server accepted: {', '.join(weak_found)}",
            evidence=[Evidence(note=f"Negotiable deprecated protocols: {weak_found}")],
        ))

    # Certificate expiry
    cert_attempt = attempts.get("certificate_info")
    not_after = _cert_not_after(cert_attempt)
    if not_after is not None:
        days = (not_after - datetime.now(timezone.utc)).days
        if days < _CERT_EXPIRY_WARN_DAYS:
            findings.append(make_finding(
                "tls.cert_expiring", location_url=f"https://{host}",
                confidence=Confidence.CONFIRMED,
                extra_note=f"Certificate notAfter={not_after.isoformat()} ({days} days).",
                evidence=[Evidence(note=f"Days to expiry: {days}")],
            ))
    return findings


def _accepted_cipher_suites(attempt):
    try:
        if attempt and getattr(attempt, "result", None):
            return attempt.result.accepted_cipher_suites
    except Exception:
        pass
    return None


def _cert_not_after(attempt):
    try:
        if attempt and getattr(attempt, "result", None):
            deployment = attempt.result.certificate_deployments[0]
            leaf = deployment.received_certificate_chain[0]
            na = leaf.not_valid_after_utc
            return na if na.tzinfo else na.replace(tzinfo=timezone.utc)
    except Exception:
        return None
    return None
