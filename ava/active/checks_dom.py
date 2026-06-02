"""DOM-based XSS sink identification (static analysis of rendered JavaScript).

Heuristic: a script that reads a controllable *source* (location.hash/search,
document.URL, referrer, window.name) and writes to a dangerous *sink*
(innerHTML, document.write, eval, insertAdjacentHTML, setTimeout-with-string)
is a likely DOM XSS site and is flagged for manual review. Pure function over
script text, so it is unit-testable without a browser.
"""

from __future__ import annotations

import logging
import re

from ..core.logging import log
from ..core.models import Confidence, Evidence
from ..finding_factory import make_finding

_SOURCES = re.compile(
    r"location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer)|"
    r"window\.name|location\b", re.I)
_SINKS = [
    ("innerHTML", re.compile(r"\.innerHTML\s*=")),
    ("outerHTML", re.compile(r"\.outerHTML\s*=")),
    ("document.write", re.compile(r"document\.write(?:ln)?\s*\(")),
    ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(")),
    ("eval", re.compile(r"\beval\s*\(")),
    ("Function", re.compile(r"\bnew\s+Function\s*\(")),
    ("setTimeout(string)", re.compile(r"\bsetTimeout\s*\(\s*['\"]")),
]


def scan_scripts(url: str, scripts: list[str], logger: logging.Logger) -> list:
    """Return DOM-XSS candidate findings for one page's script bodies."""
    findings = []
    reported_sinks = set()
    for script in scripts:
        if not script or not _SOURCES.search(script):
            continue
        for sink_name, sink_rx in _SINKS:
            m = sink_rx.search(script)
            if not m or sink_name in reported_sinks:
                continue
            reported_sinks.add(sink_name)
            snippet = _snippet(script, m.start())
            log(logger, logging.INFO, "DOM XSS sink candidate", url=url, sink=sink_name)
            findings.append(make_finding(
                "xss.dom", location_url=url, method="GET",
                confidence=Confidence.FIRM,
                title_suffix=sink_name,
                extra_note=(f"Client-side code reads a controllable source and writes "
                            f"to '{sink_name}'. Review the data flow for DOM XSS."),
                evidence=[Evidence(request_line=f"GET {url}",
                                   response_excerpt=snippet,
                                   note=f"Source + sink '{sink_name}' in page script")]))
    return findings


def _snippet(text: str, pos: int, radius: int = 90) -> str:
    seg = text[max(0, pos - radius): pos + radius]
    return re.sub(r"\s+", " ", seg).strip()
