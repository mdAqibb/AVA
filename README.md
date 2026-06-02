# AVA — Authorized Vulnerability Assessor

A reproducible, **authorized-only** first-pass web vulnerability assessment
pipeline. AVA maps an in-scope target, runs passive and (non-destructive,
exploitability-confirming) active checks, triages the results with CVSS
scoring, and produces a professional Markdown + HTML report — so a human can
skip the repetitive first pass and focus on deep manual testing.

> ## ⚠️ AUTHORIZED USE ONLY
> Use AVA **only** against systems you own or have **explicit, written
> permission** to test. Unauthorized scanning is illegal in most
> jurisdictions. Read **[DISCLAIMER.md](DISCLAIMER.md)** before you run
> anything. AVA refuses to start without an explicit authorization assertion
> and a scope file, and it will not send destructive payloads — but the
> responsibility for having authorization is yours.

---

## Table of contents

- [What AVA is (and isn't)](#what-ava-is-and-isnt)
- [The safety & authorization model](#the-safety--authorization-model)
- [Quick start](#quick-start)
- [How it works: the pipeline](#how-it-works-the-pipeline)
- [The single HTTP choke point](#the-single-http-choke-point)
- [Detection coverage](#detection-coverage)
- [Severity, CVSS, and triage](#severity-cvss-and-triage)
- [Output artifacts](#output-artifacts)
- [Resumable runs](#resumable-runs)
- [Concurrency & rate limiting](#concurrency--rate-limiting)
- [Configuration reference](#configuration-reference)
- [`scope.yaml` reference](#scopeyaml-reference)
- [The `/ava` Claude Code skill](#the-ava-claude-code-skill)
- [Project layout](#project-layout)
- [Wrapped vs. custom](#wrapped-vs-custom)
- [Extending AVA](#extending-ava)
- [Testing](#testing)
- [Validation: an example run](#validation-an-example-run)
- [Limitations](#limitations)
- [License](#license)

---

## What AVA is (and isn't)

**AVA is** an orchestrated, auditable first-pass scanner. It is deliberately
conservative: it confirms that a class of bug is *present and exploitable* and
hands you a developer-ready writeup, rather than weaponizing the finding.

**AVA is not** an exploitation framework, a load/stress tester, or a
"point it at anything" scanner. It will not run outside a declared scope and it
will not send data-destroying or denial-of-service payloads.

Each finding in the report contains:

- **Title + severity** — CVSS v3.1 vector & score, CWE ID, OWASP Top 10 category
- **Location** — exact URL, parameter, and HTTP method
- **Reproduction** — the precise request(s), with sensitive data redacted
- **Root cause** — *why* the bug exists, not just that it does
- **Impact** — what an attacker could realistically achieve
- **Remediation** — an actionable fix with secure code examples (Python + Node)
- **References** — OWASP cheat sheets, CWE pages, vendor docs

…topped with an **executive summary**: risk overview and finding counts by
severity.

---

## The safety & authorization model

This is the part to understand before anything else. Four controls work
together, and all of them **fail closed**.

### 1. The authorization gate (`ava/intake/authorization.py`)

On startup AVA refuses to run unless **all** of these hold:

1. The operator passes `--i-have-authorization` (an explicit assertion).
2. A `scope.yaml` exists, parses, and declares a non-empty `allowed_hosts`.
3. The `--target` matches the declared scope.

It then records an **audit assertion** into the run record: operator, target,
the engagement metadata, a SHA-256 hash of the scope file, and a timestamp — a
durable trail of exactly what was authorized.

### 2. Scope enforcement on every request

Scope is not checked once at the start — it is re-validated **on every single
request and every redirect hop** at the HTTP layer. Automatic redirect
following is disabled; an off-scope redirect is surfaced in the logs but never
followed. The headless browser (DOM crawl) enforces the same scope by aborting
any off-scope request at the browser layer.

### 3. The destructive-payload guard

Independent of posture, the central client blocks any request whose payload
matches a destructive pattern (`DROP TABLE`, `DELETE FROM`, `UPDATE … SET`,
`; rm -rf`, fork bombs, `mkfs`/`dd`, …). Active checks are written to be
non-destructive by design; this guard is a backstop. There is a deliberately
verbose, discouraged override (`--allow-destructive-i-accept-risk`) for the
rare case where a human specifically decides a destructive PoC is warranted —
it is never used in unattended runs.

### 4. Confirmation-grade, non-destructive detection

Active checks prove exploitability without causing harm:

- SQL injection is confirmed via error signatures, boolean-blind differential
  responses, or a brief `SLEEP`/`pg_sleep`/`WAITFOR` time delay — never with
  data-modifying statements.
- Command injection uses a unique `echo` marker or a brief `sleep` — never
  destructive shell commands.
- XSS detection checks whether HTML-breakout characters survive **unencoded**;
  it does not depend on executing script.
- SSRF and IDOR are flagged as **candidates** for manual review, because safely
  *confirming* them needs out-of-band or authenticated multi-user context that
  an automated first pass should not assume.

---

## Quick start

### Install

```bash
git clone https://github.com/mdAqibb/AVA.git
cd ava
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium      # optional: enables the JS/DOM crawl phase
```

> AVA targets **Python 3.9+**. `sslyze` (TLS checks) and `playwright` (DOM
> crawl) are optional at runtime — if they aren't installed, those phases log a
> note and are skipped rather than failing the run.

### Define your scope

```bash
cp scope.yaml.example scope.yaml
$EDITOR scope.yaml        # list the hosts/paths you are authorized to test
```

`scope.yaml` is git-ignored on purpose — never commit a real engagement scope.

### Run

```bash
python assess.py --target https://example.com --i-have-authorization
```

When it finishes, open `output/report.html` (and `output/report.md`).

---

## How it works: the pipeline

An **orchestrator** (`ava/orchestrator.py`) drives six phases in order,
persisting state after each so runs are resumable and reports regenerate
without rescanning.

```
intake → recon → passive → active → triage → report
```

### 1. Intake
Loads config, parses `scope.yaml`, runs the **authorization gate**, writes the
audit record, and builds the single rate-limited HTTP client.

### 2. Recon / mapping
- **Static crawler** (`ava/crawler/static_crawler.py`): a breadth-first,
  in-scope crawl that discovers endpoints, query parameters, forms (with their
  inputs and whether a CSRF token is present), and fingerprints the technology
  stack from headers + body.
- **DOM crawler** (`ava/crawler/dom_crawler.py`, optional): renders pages with
  headless Chromium (Playwright) to discover JS-injected routes and analyze
  client-side scripts for DOM-XSS sinks. Scope is enforced at the browser layer.

### 3. Passive analysis (`ava/passive/`)
Inspects responses without attacking: security headers, cookie flags, server
version disclosure, verbose error/stack-trace leakage, exposed files
(`.git/config`, `.env`, …), directory listings, and TLS configuration (via
`sslyze`). Header/cookie findings are anchored to the origin so they collapse
to one finding per site, not per page.

### 4. Active checks (`ava/active/`)
Sends confirmation-grade probes one parameter at a time, through the central
client. To stay polite and bounded it collapses endpoints to distinct *shapes*
(method + path + parameter names), so a templated URL isn't fuzzed dozens of
times, and caps the number of shapes per run. (See [coverage](#detection-coverage).)

### 5. Triage (`ava/triage/`)
Deduplicates findings by a stable fingerprint, assigns a CVSS v3.1 base score
and severity band, filters likely false positives (conservatively — it biases
toward keeping findings), and ranks by impact.

### 6. Report (`ava/reporting/`)
Renders `report.md` and a styled, self-contained `report.html` from the triaged
findings, with an executive summary at the top. This phase makes no network
requests, so you can regenerate reports any time from the stored JSON.

---

## The single HTTP choke point

Every outbound request — crawler, passive, active, even the headless browser's
subresources — is funneled through one place: `ava/core/http_client.py`. This
is what makes the safety guarantees enforceable in a single, auditable module
rather than scattered across dozens of checks. In one place it:

- re-checks **scope** on every request and every redirect hop,
- enforces the **token-bucket rate limit** and the **global request cap**,
- applies the **destructive-payload guard**,
- retries transient transport errors with backoff (real 4xx/5xx are returned,
  not retried — they're data to analyze),
- and emits structured request logs.

Because this client is the only network path, concurrency (below) can never let
a check bypass the politeness limits.

---

## Detection coverage

All active checks are **confirmation-grade and non-destructive**. "Candidate"
means AVA flags it for manual review rather than asserting it.

| Class | Technique | Phase | Confidence | CWE / OWASP |
|-------|-----------|-------|-----------|-------------|
| Missing security headers (CSP, HSTS, X-CTO, frame-ancestors, Referrer-Policy) | Header inspection | passive | Firm | CWE-693 / A05 |
| Server/version disclosure | Banner inspection | passive | Firm | CWE-200 / A05 |
| Cookie flags (Secure / HttpOnly / SameSite) | `Set-Cookie` analysis | passive | Firm | CWE-614/1004/1275 / A05 |
| Weak TLS protocol / cert expiry | `sslyze` | passive | Confirmed | CWE-326/298 / A02 |
| Exposed files / dir listing / stack traces | Read-only probes + signatures | passive | Firm–Confirmed | CWE-538/548/209 / A05 |
| SQL injection | Error-based, boolean-blind, time-blind | active | Firm–Confirmed | CWE-89 / A03 |
| OS command injection | Marker-echo + time-based | active | Confirmed | CWE-78 / A03 |
| Server-side template injection | Arithmetic evaluation | active | Confirmed | CWE-1336 / A03 |
| Reflected XSS | Unencoded breakout reflection | active | Firm–Confirmed | CWE-79 / A03 |
| Stored XSS | Marker submit + re-read (heavy fuzzing) | active | Firm | CWE-79 / A03 |
| DOM XSS | Source→sink JS analysis | active | Firm | CWE-79 / A03 |
| Open redirect | Off-scope canary in redirect | active | Confirmed | CWE-601 / A01 |
| SSRF | URL-parameter candidate | active | Tentative | CWE-918 / A10 |
| IDOR / access control | Identifier-parameter candidate | active | Tentative | CWE-639 / A01 |
| CSRF | Missing anti-CSRF token on POST | active | Firm | CWE-352 / A01 |
| CORS misconfiguration | Reflected/`*`+credentials origin | active | Firm–Confirmed | CWE-942 / A05 |

> **Time-based** SQLi/command probes only run when **heavy fuzzing** is enabled
> (the default), confirm with a repeat request before reporting, and use a brief
> delay only — never resource exhaustion.

---

## Severity, CVSS, and triage

AVA ships a full **CVSS v3.1 base-score calculator** (`ava/triage/severity.py`)
implementing the official equations — every finding carries a defensible numeric
score derived from its vector string, not a hand-picked number. Bands map as:
0.0 = Informational, <4.0 Low, <7.0 Medium, <9.0 High, ≥9.0 Critical.

Triage then:
- **deduplicates** findings sharing a fingerprint
  (`CWE | method | URL | parameter | check_id`), merging evidence and keeping the
  strongest confidence/severity;
- **filters** likely false positives (currently conservative — it prefers to
  surface candidates for human review);
- **ranks** by severity → CVSS score → confidence.

Findings carry a **confidence**: `Tentative` (heuristic / needs manual
confirmation), `Firm` (behavior consistent with the bug), or `Confirmed`
(reproduced with a deterministic marker).

---

## Output artifacts

Each run writes to `output/<host>-<timestamp>/`:

| File | Purpose |
|------|---------|
| `run.json` | Run state + **audit trail** (who/what/when authorized, scope hash) |
| `endpoints.json` | Discovered endpoints, parameters, forms, detected technologies |
| `raw_findings.json` | Accumulated pre-triage findings (enables resume) |
| `findings.json` | Triaged findings — the source of truth for reports |
| `assess.log` | Structured JSON-lines log |
| `report.md` / `report.html` | The deliverable |

A copy of `report.md` / `report.html` is also dropped at the top of `output/`
for convenience ("latest report").

---

## Resumable runs

State is persisted after every phase, so an interrupted run can continue instead
of rescanning:

```bash
# resume the latest INCOMPLETE run for this target
python assess.py --target https://example.com --i-have-authorization --resume

# resume / regenerate a specific run by id
python assess.py --target https://example.com --i-have-authorization \
  --resume-run-id example.com-20260602-013705
```

- `--resume` reuses the latest incomplete run for the target, skips finished
  phases, reloads their artifacts, and continues from where it stopped.
- `--resume-run-id` on a **completed** run simply re-renders the report (no
  rescanning).
- If there's nothing to resume, AVA starts a fresh run.
- Intake (the authorization gate) **always** re-runs — scope is re-validated on
  every invocation.

---

## Concurrency & rate limiting

- `--concurrency` (or a rate preset) bounds how many requests are **in flight**.
  The static crawler fetches each BFS level concurrently (parsing stays
  single-threaded), and the active phase fans out across endpoint shapes.
- The **token-bucket rate limit** (`--rate`, requests/second) and the
  **global request cap** (`--global-cap`) are enforced inside the shared client,
  so they hold *across threads* — concurrency speeds things up without making
  AVA impolite.
- Presets: `gentle` (~2 req/s, 2 concurrent), `moderate` (~5 req/s, 5),
  `fast` (~15 req/s, 10).

---

## Configuration reference

CLI flags override a config file, which overrides built-in defaults.

| Flag | Default | Meaning |
|------|---------|---------|
| `--target URL` | — | Target base URL (required) |
| `--i-have-authorization` | off | **Required** authorization assertion |
| `--scope-file PATH` | `scope.yaml` | Path to the scope definition |
| `--config PATH` | — | Optional YAML config with defaults |
| `--output-dir PATH` | `output` | Where run artifacts are written |
| `--operator NAME` | — | Recorded in the audit trail |
| `--rate-preset {gentle,moderate,fast}` | — | Convenience preset for rate + concurrency |
| `--rate N` | `15` | Requests per second |
| `--concurrency N` | `10` | Max concurrent requests |
| `--global-cap N` | `10000` | Hard ceiling on total requests for the run |
| `--max-depth N` | `4` | Max crawl depth |
| `--timeout SEC` | `15` | Per-request timeout |
| `--retries N` | `2` | Retries on transient transport errors |
| `--no-active` | active on | Passive-only (disable all active checks) |
| `--no-heavy-fuzzing` | heavy on | Disable bounded heavy/time-based fuzzing |
| `--no-dom-crawl` | DOM on | Disable the headless-browser crawl |
| `--resume` | off | Resume the latest incomplete run for the target |
| `--resume-run-id ID` | — | Resume / regenerate a specific run |
| `--allow-destructive-i-accept-risk` | off | **Discouraged**; permit destructive PoC for one run |
| `--verbose` | off | Verbose console logging |

> **Default posture** is aggressive-but-safe: passive + active + bounded heavy
> fuzzing at the `fast` rate. Dial it back with `--rate-preset gentle`,
> `--no-heavy-fuzzing`, or `--no-active` for production targets.

A config file (`--config ava.yaml`) may set any of: `rate`, `concurrency`,
`global_cap`, `max_depth`, `timeout`, `retries`, `passive`, `active`,
`heavy_fuzzing`, `dom_crawl`, `remediation_langs`, `output_dir`, `operator`.

---

## `scope.yaml` reference

```yaml
# Hosts AVA may contact. Exact host match; a leading "*." permits subdomains.
allowed_hosts:
  - example.com
  - www.example.com
  - "*.staging.example.com"

# Optional: only scan paths starting with these prefixes (omit = all paths).
allowed_paths:
  - /

# Optional: never touch these paths (takes precedence over allowed_paths).
denied_paths:
  - /logout
  - /admin/delete

# Optional: hosts that must NEVER be requested, even if referenced.
hard_deny_hosts:
  - accounts.google.com

# Engagement metadata — recorded in the run's audit log.
engagement:
  name: "Example Corp Q2 assessment"
  authorized_by: "jane.doe@example.com"
  ticket: "SEC-1234"
  window_start: "2026-06-01T00:00:00Z"
  window_end: "2026-06-30T23:59:59Z"
```

If the current time is outside the declared `window_start`/`window_end`, AVA
logs a warning (it does not hard-stop on the window).

---

## The `/ava` Claude Code skill

If you use [Claude Code](https://claude.com/claude-code), the bundled skill at
`.claude/skills/ava/SKILL.md` lets you launch a scan by typing:

```
/ava example.com
```

The skill normalizes the target, **checks `scope.yaml` and refuses to expand
scope without your explicit per-host confirmation**, launches `assess.py` in the
background, monitors `assess.log`, and surfaces the report. It never passes the
destructive override unless you specifically ask. The skill is a convenience
wrapper — the authorization gate and scope checks in `assess.py` remain the
enforced controls.

---

## Project layout

```
assess.py                  # thin CLI entrypoint -> Config -> Orchestrator
ava/
├── orchestrator.py        # phase coordination, resume logic
├── findings_catalog.py    # knowledge base: per-finding CWE/OWASP/CVSS/remediation
├── finding_factory.py     # build scored Finding objects from catalog entries
├── intake/                # config, scope parsing, authorization gate
├── core/                  # HTTP choke point, rate limit, models, logging, concurrency
├── crawler/               # static crawler, DOM crawler, tech fingerprint
├── passive/               # headers, cookies, TLS, disclosure
├── active/                # sqli, xss, injection, redirect/ssrf, access, cors, dom + runner
├── triage/                # CVSS v3.1, dedup, ranking, FP filtering
└── reporting/             # JSON store (resume source of truth) + MD/HTML renderers
tests/                     # pytest suite (no network deps — uses fakes)
scope.yaml.example         # copy to scope.yaml and edit
```

---

## Wrapped vs. custom

AVA wraps mature engines where it adds value and keeps the security-critical
logic small and auditable.

| Concern | Approach |
|---------|----------|
| HTTP transport | **Wrapped** — `httpx` (behind the single client) |
| HTML parsing | **Wrapped** — `beautifulsoup4` + `lxml` |
| DOM render / JS crawl | **Wrapped** — `playwright` (headless Chromium) |
| TLS configuration | **Wrapped** — `sslyze` |
| Scope / authorization | **Custom** — small, auditable, fail-closed |
| Check orchestration | **Custom** |
| Detection payloads | **Custom**, conservative & confirmation-grade |
| CVSS scoring, triage, reporting | **Custom** |

---

## Extending AVA

Adding a check is three steps (plus a test):

1. **Catalog entry** in `ava/findings_catalog.py` — `check_id`, CWE, OWASP, a
   CVSS v3.1 vector, and the prose/remediation (Python + Node code where useful).
2. **Detection** in `ava/passive/` (response-only) or `ava/active/` (sends
   probes), building findings via
   `ava.finding_factory.make_finding(check_id, ...)`.
3. **Wire it** into the relevant runner.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide and the
non-negotiable safety rules.

---

## Testing

```bash
pip install -e ".[dev]"   # or: pip install pytest
pytest
```

The suite (66 tests) covers scope matching, the fail-closed authorization gate,
the CVSS calculator vs. known-good vectors, serialization round-trips (resume
integrity), passive + active detection logic (with negative controls), the
destructive-payload guard, triage/reporting, concurrency, and the four resume
paths. It runs **without** `httpx`/`playwright`/`sslyze` installed — checks are
exercised against mock clients and responses.

---

## Validation: an example run

AVA was run end-to-end (over real HTTP, via `httpx`) against a local,
deliberately-vulnerable DVWA-style test app to validate the full pipeline — not
just the unit-tested detection logic. The run produced **20 findings**,
correctly scored and ranked:

| Severity | Count | Examples |
|----------|-------|----------|
| Critical | 3 | SSTI (`{{919*919}}` → `844561`), OS command injection (echoed marker), SQL injection (error-based) — all **Confirmed** |
| Medium | 13 | Reflected XSS ×3 (Confirmed), SSRF candidates, IDOR candidates, open redirect (Confirmed), version disclosure, missing CSRF token, missing CSP / X-Frame-Options / SameSite |
| Low | 4 | Cookie `Secure`/`HttpOnly` missing, `X-Content-Type-Options`, `Referrer-Policy` |

Each finding rendered with its CVSS v3.1 vector/score, CWE, OWASP category,
exact location, a **redacted request/response reproduction**, root cause,
impact, and Python + Node remediation.

What the run demonstrated about the safety design:

- **Scope containment held live.** The open-redirect probe made the app return
  `302 → https://ava-redirect-canary.invalid/…`; AVA logged *"Stopping at
  off-scope redirect (not followed)"* — it flagged the vulnerability **without**
  ever requesting the off-scope host.
- **No false positives.** Stored XSS was not flagged (the app doesn't persist
  input), and HSTS was not flagged (correct — the target was plain HTTP).
- **Honest coverage boundary.** A CORS-misconfigured endpoint that wasn't linked
  from any page went undiscovered — AVA tests only what the crawler can reach
  (there is no forced-browse wordlist yet; see [Limitations](#limitations)).

---

## Limitations

- AVA is an automated **first pass**. Confirm every finding manually before
  acting; triage's false-positive filtering is intentionally conservative.
- SSRF and IDOR are flagged as **candidates** — safely confirming them needs
  out-of-band or authenticated multi-user context AVA doesn't assume.
- It does not authenticate by default; behind-login surfaces need manual setup.
- Boolean-blind SQLi uses a length+token-overlap similarity heuristic; tune the
  thresholds in `ava/active/util.py` if you see noise on a given app.
- Stored-XSS detection is best-effort and writes data, so it runs only under
  heavy fuzzing.

---

## License

[MIT](LICENSE) — with an additional **authorized-use-only** notice. See
[DISCLAIMER.md](DISCLAIMER.md). Update the copyright holder in `LICENSE` and the
repo URLs in `pyproject.toml` for your fork.
