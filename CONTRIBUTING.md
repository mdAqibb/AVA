# Contributing to AVA

Thanks for your interest! AVA is an **authorized-only** security assessment
tool, and contributions must preserve that posture.

## Non-negotiable safety rules

1. **Never weaken the authorization gate or scope enforcement.** Every outbound
   request must go through `ava/core/http_client.py`, which re-checks scope on
   every request and redirect hop.
2. **Detection payloads must be confirmation-grade and non-destructive.** They
   may prove a vulnerability is exploitable (reflection, evaluation, a timed
   delay) but must never delete/modify data or attempt denial of service. The
   destructive-payload guard in the client is a backstop, not a license.
3. **Bias toward flagging candidates for human review** over sending aggressive
   payloads. False positives cost a reviewer minutes; a destroyed target ends
   the engagement.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # runtime + pytest/ruff
playwright install chromium      # only needed for the DOM-crawl phase
```

## Running tests

```bash
pytest                # full suite (no network deps required — uses fakes)
ruff check .          # lint
```

The suite runs without `httpx`/`playwright`/`sslyze` installed because checks
are exercised against mock clients and responses (see `tests/helpers.py`).

## Adding a new check

1. **Add a catalog entry** in `ava/findings_catalog.py` with a `check_id`, CWE,
   OWASP category, a CVSS v3.1 vector, and the prose/remediation (Python + Node
   code where it helps).
2. **Write the detection** in the right module:
   - passive (response-only) → `ava/passive/`
   - active (sends probes) → `ava/active/`
   Build findings with `ava.finding_factory.make_finding(check_id, ...)`.
3. **Wire it** into the relevant runner (`ava/passive/runner.py` or
   `ava/active/runner.py`).
4. **Add a test** under `tests/` using a fake client/response. Include a
   *negative* case (the safe configuration must not be flagged).

## Style

- Match the surrounding code; keep modules small and single-purpose.
- Prefer wrapping a mature engine over re-implementing detection; note in the
  README's "wrapped vs. custom" table what you wrapped.
- Conventional commits are appreciated but not required.

By contributing you agree your work is licensed under the project's MIT license.
