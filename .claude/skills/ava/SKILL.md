---
name: ava
description: Run an authorized web vulnerability assessment with AVA against a target the operator supplies (e.g. "/ava example.com"). Use ONLY when the user explicitly invokes /ava with a site, to kick off assess.py, monitor progress, and surface the report.
---

# /ava — run an authorized assessment

The user invokes `/ava <site>` to start an AVA scan. `<site>` arrives as the
skill argument (a hostname or URL). Your job: validate authorization/scope,
launch `assess.py` in the background, monitor it, and surface the report.

This project lives at the repo root (where `assess.py` and `scope.yaml` are).
Read `DISCLAIMER.md` and `README.md` if you need a refresher on the model.

## Steps

1. **Normalize the target.** If `<site>` has no scheme, prepend `https://`.
   Extract the host. Call this `TARGET` and `HOST`.

2. **Check scope — this is the real authorization boundary; never bypass it.**
   Read `scope.yaml`.
   - If it does not exist: tell the user, show `scope.yaml.example`, and ask
     them to confirm they are authorized to test `HOST` before you create a
     `scope.yaml` with `HOST` under `allowed_hosts`. Do not create it silently.
   - If it exists but `HOST` is not covered by `allowed_hosts`: do **not** add
     it automatically. Ask the user to confirm, in this turn, that they are
     authorized to test `HOST`. Only after an explicit "yes" add `HOST` to
     `allowed_hosts` and proceed. If they decline, stop.
   - Expanding scope is always an explicit human decision. The `assess.py`
     gate will independently refuse anything off-scope regardless.

3. **Launch in the background.** Run, from the repo root, with `run_in_background: true`:

   ```
   python3 assess.py --target "TARGET" --i-have-authorization --operator "<user>"
   ```

   Invoking `/ava` is the user's deliberate authorization assertion, which is
   why `--i-have-authorization` is passed; the scope check above and the gate
   in `assess.py` remain the enforced controls. Pass extra flags the user
   asked for (e.g. `--rate-preset gentle`, `--no-active`). If `httpx` /
   dependencies are missing, run `pip install -r requirements.txt` first (and
   `playwright install chromium` once the DOM-crawl phase exists), telling the
   user what you're installing.

4. **Monitor.** The run writes to `output/<host>-<timestamp>/assess.log`
   (JSON-lines) and updates `run.json` after each phase. Tail the newest run
   directory's log and report phase transitions (intake → recon → passive →
   active → triage → report) and the running request count. Do not poll in a
   tight loop; check periodically.

5. **Report.** When the `report` phase completes, read
   `output/<run>/findings.json` and surface:
   - the severity counts (Critical/High/Medium/Low/Info),
   - the top findings by severity, each as a clickable link to its location,
   - the paths `output/report.md` and `output/report.html` (and the
     per-run copies under `output/<run>/`).

## Guardrails

- Never edit `scope.yaml` to add a host without the user's explicit, in-turn
  confirmation that they're authorized for that host.
- Never pass `--allow-destructive-i-accept-risk` unless the user explicitly
  and specifically asks for destructive PoC in this turn.
- If `assess.py` exits with the authorization-refused message, relay the exact
  reason — do not try to work around the gate.
- One target per invocation. If the user names several hosts, scan the first
  and ask before continuing to the next.
