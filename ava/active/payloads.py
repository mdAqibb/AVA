"""Probe payloads and detection signatures for active checks.

Design rules:
  * Confirmation-grade, NOT destructive. Payloads prove a class of bug is
    present (reflection, evaluation, time delay) without altering/destroying
    data or denying service.
  * Time-based payloads use `SLEEP`/`pg_sleep`/`WAITFOR`/`sleep` only — a brief
    pause, never resource exhaustion.
  * Every probe carries a per-run random marker so reflections are
    unambiguous and not confused with pre-existing page content.
"""

from __future__ import annotations

import re
import secrets

# A short delay used by all time-based confirmation probes (seconds).
TIME_DELAY = 3


def token(prefix: str = "ava") -> str:
    return f"{prefix}{secrets.token_hex(4)}"


# ---- SQL injection ------------------------------------------------------

# Error-based: a lone quote / paren tends to surface a DB parse error.
SQLI_ERROR_PROBES = ["'", "\"", "')", "'\"", "`"]

SQL_ERROR_SIGNATURES = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning:\s+mysqli?_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),    # Oracle
    re.compile(r"pg_query\(\)|PostgreSQL.*ERROR|unterminated quoted string", re.I),
    re.compile(r"SQLITE_ERROR|sqlite3?\.OperationalError", re.I),
    re.compile(r"SQLSTATE\[\w+\]", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"ODBC SQL Server Driver|Microsoft OLE DB Provider for SQL Server", re.I),
]

# Boolean-based blind: a TRUE vs FALSE condition pair (string + numeric forms).
def sqli_boolean_pairs(base: str) -> list[tuple[str, str]]:
    return [
        (f"{base}' AND '1'='1", f"{base}' AND '1'='2"),
        (f"{base}\" AND \"1\"=\"1", f"{base}\" AND \"1\"=\"2"),
        (f"{base} AND 1=1", f"{base} AND 1=2"),
    ]

# Time-based blind confirmation (gated behind heavy fuzzing).
def sqli_time_probes(base: str, delay: int = TIME_DELAY) -> list[str]:
    return [
        f"{base}' AND SLEEP({delay})-- -",
        f"{base}'; WAITFOR DELAY '0:0:{delay}'-- -",
        f"{base}' || pg_sleep({delay})-- -",
        f"{base} AND SLEEP({delay})",
    ]


# ---- Cross-site scripting ----------------------------------------------

def xss_probe(tok: str) -> str:
    # Includes the chars needed to break out of HTML/attr/JS contexts. We
    # detect whether they survive unencoded; we do not rely on execution.
    return f"{tok}\"'><svg/onload=alert({tok})>"

XSS_BREAKOUT_CHARS = ["<", ">", "\"", "'"]


# ---- OS command injection ----------------------------------------------

def cmd_echo_probes(tok: str) -> list[str]:
    # Echo a unique marker; detect it reflected in output.
    return [f"; echo {tok}", f"| echo {tok}", f"$(echo {tok})", f"`echo {tok}`",
            f"& echo {tok}"]

def cmd_time_probes(delay: int = TIME_DELAY) -> list[str]:
    return [f"; sleep {delay}", f"| sleep {delay}", f"$(sleep {delay})",
            f"& sleep {delay}"]


# ---- Server-side template injection ------------------------------------

# Use an uncommon product so a coincidental match is improbable.
SSTI_A, SSTI_B = 919, 919
SSTI_EXPECT = str(SSTI_A * SSTI_B)        # "844561"

def ssti_probes() -> list[str]:
    return [f"{{{{{SSTI_A}*{SSTI_B}}}}}",   # Jinja2 / Twig  {{919*919}}
            f"${{{SSTI_A}*{SSTI_B}}}",      # Freemarker / JSP EL
            f"#{{{SSTI_A}*{SSTI_B}}}",      # Ruby / Thymeleaf
            f"<%= {SSTI_A}*{SSTI_B} %>",   # ERB
            f"{{{SSTI_A}*{SSTI_B}}}"]       # generic


# ---- Open redirect ------------------------------------------------------

# Off-scope canary host. We never REQUEST it (the client would refuse); we only
# check whether the app tries to redirect us there.
REDIRECT_CANARY = "https://ava-redirect-canary.invalid/probe"
REDIRECT_PARAM_HINTS = {"next", "url", "redirect", "redirect_uri", "return",
                        "returnurl", "return_to", "dest", "destination",
                        "continue", "goto", "r", "u", "to", "out", "target"}


# ---- SSRF / IDOR hints --------------------------------------------------

SSRF_PARAM_HINTS = {"url", "uri", "link", "src", "source", "dest", "target",
                    "callback", "webhook", "feed", "host", "domain", "site",
                    "path", "file", "image", "img", "load", "fetch", "proxy"}

IDOR_PARAM_HINTS = {"id", "user", "user_id", "userid", "account", "account_id",
                    "uid", "pid", "oid", "doc", "document", "doc_id", "order",
                    "order_id", "invoice", "file_id", "object", "key", "ref"}

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

def looks_like_identifier(value: str) -> bool:
    return bool(value) and (bool(_NUMERIC.match(value)) or bool(_UUID.match(value)))


# ---- CORS ---------------------------------------------------------------

CORS_PROBE_ORIGIN = "https://ava-cors-probe.invalid"
