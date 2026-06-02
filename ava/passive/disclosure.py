"""Exposed-file and directory-listing probes.

Sends a small, fixed list of read-only GETs for commonly-exposed sensitive
paths within the in-scope origin. Non-destructive by nature; still goes
through the central client, so scope and rate limits apply.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urljoin

from ..core.http_client import HttpClient, OutOfScopeError
from ..core.logging import log
from ..core.models import Confidence, Evidence
from ..finding_factory import make_finding

# (path, marker-regex-or-None, severity-vector-override-or-None, label)
# marker confirms the file is real content rather than a generic 200/SPA page.
_PROBES = [
    ("/.git/config", re.compile(r"\[core\]|\[remote", re.I), None, ".git repository config"),
    ("/.git/HEAD", re.compile(r"ref:\s*refs/"), None, ".git HEAD"),
    ("/.env", re.compile(r"^[A-Z0-9_]+=", re.M), None, ".env secrets file"),
    ("/.svn/entries", re.compile(r"\d+\s"), None, ".svn metadata"),
    ("/.DS_Store", re.compile(r"Bud1|\x00\x00\x00\x01"), None, ".DS_Store"),
    ("/server-status", re.compile(r"Apache Server Status|Server uptime", re.I), None,
     "Apache server-status"),
    ("/phpinfo.php", re.compile(r"phpinfo\(\)|PHP Version", re.I), None, "phpinfo()"),
    ("/.well-known/security.txt", None, None, "security.txt (informational)"),
]

_DIRLIST_RX = re.compile(r"<title>Index of /|Directory listing for ", re.I)


def probe_disclosure(client: HttpClient, origin: str, logger: logging.Logger) -> list:
    findings = []
    for path, marker, _vector, label in _PROBES:
        url = urljoin(origin + "/", path.lstrip("/"))
        try:
            resp = client.get(url)
        except OutOfScopeError:
            continue
        except Exception as e:
            log(logger, logging.DEBUG, "disclosure probe failed", url=url, error=str(e))
            continue

        if resp.status != 200 or not resp.text:
            continue
        if marker is not None and not marker.search(resp.text):
            continue  # 200 but not the real artefact (likely SPA/catch-all) — skip

        if path == "/.well-known/security.txt":
            continue  # presence is good practice, not a finding

        excerpt = resp.text[:200]
        findings.append(make_finding(
            "disclosure.exposed_file", location_url=url,
            confidence=Confidence.CONFIRMED if marker else Confidence.FIRM,
            title_suffix=label,
            extra_note=f"Reachable artefact: {label} at {url}",
            evidence=[Evidence(request_line=f"GET {url}", response_status=200,
                               response_excerpt=excerpt,
                               note=f"Detected {label}")],
        ))
        log(logger, logging.INFO, "exposed file detected", url=url, label=label)
    return findings


def check_directory_listing(resp, logger: logging.Logger) -> list:
    if resp.status == 200 and _DIRLIST_RX.search(resp.text or ""):
        return [make_finding(
            "disclosure.directory_listing", location_url=resp.url,
            confidence=Confidence.FIRM,
            evidence=[Evidence(request_line=f"GET {resp.url}", response_status=200,
                               response_excerpt=(resp.text or "")[:200],
                               note="Auto-generated directory index detected")],
        )]
    return []
