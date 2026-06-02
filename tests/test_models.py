"""Serialization round-trips — critical for resume integrity."""

import dataclasses

from ava.core.models import (Confidence, Endpoint, Evidence, Finding, Form,
                             HttpParam, Severity)


def test_finding_round_trip_preserves_fingerprint():
    f = Finding(
        title="t", cwe="CWE-89", owasp="A03", severity=Severity.HIGH,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", cvss_score=9.1,
        confidence=Confidence.CONFIRMED, location_url="http://x/i", location_param="id",
        remediation_code={"python": "x"}, references=["ref"],
        evidence=[Evidence(request_line="GET http://x/i", response_status=200, note="n")],
        check_id="injection.sqli",
    )
    f2 = Finding.from_dict(f.to_dict())
    assert f2.fingerprint() == f.fingerprint()
    assert f2.severity is Severity.HIGH
    assert f2.confidence is Confidence.CONFIRMED
    assert f2.evidence[0].response_status == 200
    assert f2.remediation_code == {"python": "x"}


def test_endpoint_round_trip():
    ep = Endpoint(
        url="http://x/i?id=1", method="POST",
        params=[HttpParam("id", "query", "1"), HttpParam("q", "body", "x")],
        forms=[Form(action="http://x/i", method="POST",
                    inputs=[HttpParam("id", "body", "1")], has_csrf_token=True)],
        status=200, title="T", depth=2,
    )
    ep2 = Endpoint.from_dict(dataclasses.asdict(ep))
    assert ep2.key() == ep.key()
    assert len(ep2.params) == 2
    assert ep2.forms[0].has_csrf_token is True
    assert ep2.forms[0].inputs[0].name == "id"
