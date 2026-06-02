"""Render findings to Markdown and styled, self-contained HTML.

Both renderers consume the persisted findings (list of Finding dicts) so a
report can be regenerated from findings.json without rescanning. Hand-rolled
(no template engine) to keep the dependency surface small.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from ..core.models import Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
              Severity.LOW, Severity.INFO]
_SEV_COLOR = {
    "Critical": "#7b1fa2", "High": "#c62828", "Medium": "#ef6c00",
    "Low": "#f9a825", "Informational": "#1565c0",
}


def _counts(findings: list[dict]) -> dict[str, int]:
    c = {s.value: 0 for s in _SEV_ORDER}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


# ---------------------------------------------------------------- Markdown

def render_markdown(findings: list[dict], meta: dict, technologies: dict) -> str:
    counts = _counts(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out: list[str] = []
    out.append(f"# Web Vulnerability Assessment — {meta.get('target','')}\n")
    out.append(f"*Generated {now} · run `{meta.get('run_id','')}`*\n")

    out.append("\n## Executive summary\n")
    out.append(f"- **Target:** {meta.get('target','')}")
    out.append(f"- **Authorized by:** {meta.get('authorized_by','(see scope.yaml)')}")
    out.append(f"- **Requests sent:** {meta.get('request_count','?')}")
    out.append(f"- **Total findings:** {len(findings)}\n")
    out.append("| Severity | Count |")
    out.append("|----------|-------|")
    for s in _SEV_ORDER:
        out.append(f"| {s.value} | {counts.get(s.value,0)} |")
    if technologies:
        techs = ", ".join(sorted(technologies.keys()))
        out.append(f"\n**Detected technologies:** {techs}\n")

    out.append("\n## Findings\n")
    if not findings:
        out.append("_No findings produced in this phase._\n")
    for i, f in enumerate(findings, 1):
        out.append(_finding_md(i, f))

    out.append("\n---\n*Authorized assessment. See DISCLAIMER.md. "
               "This is an automated first pass; confirm findings manually.*\n")
    return "\n".join(out)


def _finding_md(idx: int, f: dict) -> str:
    s = []
    s.append(f"\n### {idx}. {f['title']}  \n")
    s.append(f"**Severity:** {f['severity']} (CVSS {f['cvss_score']} "
             f"`{f['cvss_vector']}`) · **{f['cwe']}** · {f['owasp']} · "
             f"**Confidence:** {f['confidence']}\n")
    s.append(f"**Location:** `{f['method']} {f['location_url']}`"
             + (f" · parameter `{f['location_param']}`" if f.get('location_param') else "") + "\n")
    s.append(f"\n**Description.** {f['description']}\n")
    s.append(f"\n**Root cause.** {f['root_cause']}\n")
    s.append(f"\n**Impact.** {f['impact']}\n")

    if f.get("evidence"):
        s.append("\n**Reproduction / evidence.**\n")
        for ev in f["evidence"]:
            s.append(_evidence_md(ev))

    s.append(f"\n**Remediation.** {f['remediation']}\n")
    for lang, code in (f.get("remediation_code") or {}).items():
        s.append(f"\n_Example ({lang}):_\n\n```{_fence_lang(lang)}\n{code}\n```\n")

    if f.get("references"):
        s.append("\n**References.**\n")
        for ref in f["references"]:
            s.append(f"- {ref}")
    s.append("")
    return "\n".join(s)


def _evidence_md(ev: dict) -> str:
    lines = ["```http"]
    if ev.get("request_line"):
        lines.append(ev["request_line"])
    for k, v in (ev.get("request_headers") or {}).items():
        lines.append(f"{k}: {v}")
    if ev.get("request_body"):
        lines.append("")
        lines.append(ev["request_body"])
    if ev.get("response_status"):
        lines.append(f"\n--> HTTP {ev['response_status']}")
    for k, v in (ev.get("response_headers") or {}).items():
        lines.append(f"{k}: {v}")
    if ev.get("response_excerpt"):
        lines.append("")
        lines.append(ev["response_excerpt"].strip())
    lines.append("```")
    note = f"\n_{ev['note']}_\n" if ev.get("note") else ""
    return "\n".join(lines) + note


def _fence_lang(lang: str) -> str:
    return {"python": "python", "node": "javascript"}.get(lang, "")


# -------------------------------------------------------------------- HTML

def render_html(findings: list[dict], meta: dict, technologies: dict) -> str:
    counts = _counts(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    e = html.escape

    chips = "".join(
        f'<span class="chip" style="background:{_SEV_COLOR[s.value]}">'
        f'{s.value}: {counts.get(s.value,0)}</span>'
        for s in _SEV_ORDER
    )
    tech = ", ".join(sorted(e(t) for t in technologies)) or "—"

    body = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AVA Report — {e(meta.get('target',''))}</title>
<style>
  :root {{ --bg:#0f1419; --card:#1a2129; --fg:#e6edf3; --muted:#9aa7b4; --border:#2a333d; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
         font:15px/1.6 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif; }}
  .wrap {{ max-width:980px; margin:0 auto; padding:32px 20px 80px; }}
  h1 {{ font-size:26px; margin:0 0 4px; }}
  h2 {{ font-size:20px; border-bottom:1px solid var(--border); padding-bottom:6px; margin-top:40px; }}
  h3 {{ font-size:17px; margin:0 0 4px; }}
  .muted {{ color:var(--muted); font-size:13px; }}
  .chip {{ display:inline-block; color:#fff; padding:4px 10px; border-radius:14px;
           font-size:12px; font-weight:600; margin:4px 6px 4px 0; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-left-width:5px;
           border-radius:8px; padding:18px 20px; margin:18px 0; }}
  .meta {{ font-size:13px; color:var(--muted); margin:6px 0 14px; }}
  .lbl {{ font-weight:600; color:var(--fg); }}
  pre {{ background:#0b0f14; border:1px solid var(--border); border-radius:6px;
         padding:12px; overflow:auto; font-size:13px; }}
  code {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
  table {{ border-collapse:collapse; margin:10px 0; }}
  td,th {{ border:1px solid var(--border); padding:6px 14px; text-align:left; }}
  a {{ color:#58a6ff; }}
  .sev {{ font-weight:700; }}
</style></head><body><div class="wrap">
<h1>Web Vulnerability Assessment</h1>
<div class="muted">Target: {e(meta.get('target',''))} · Generated {now} · run {e(str(meta.get('run_id','')))}</div>

<h2>Executive summary</h2>
<p class="meta">Authorized by: {e(str(meta.get('authorized_by','(see scope.yaml)')))} ·
Requests sent: {e(str(meta.get('request_count','?')))} · Total findings: {len(findings)}</p>
<div>{chips}</div>
<p class="meta">Detected technologies: {tech}</p>
"""]

    body.append('<h2>Findings</h2>')
    if not findings:
        body.append('<p class="muted">No findings produced in this phase.</p>')
    for i, f in enumerate(findings, 1):
        body.append(_finding_html(i, f, e))

    body.append('<h2></h2><p class="muted">Authorized assessment — see DISCLAIMER.md. '
                'Automated first pass; confirm findings manually before acting.</p>')
    body.append("</div></body></html>")
    return "\n".join(body)


def _finding_html(idx: int, f: dict, e) -> str:
    color = _SEV_COLOR.get(f["severity"], "#888")
    parts = [f'<div class="card" style="border-left-color:{color}">']
    parts.append(f'<h3>{idx}. {e(f["title"])}</h3>')
    parts.append(
        f'<div class="meta"><span class="sev" style="color:{color}">{e(f["severity"])}</span> '
        f'· CVSS {f["cvss_score"]} <code>{e(f["cvss_vector"])}</code> · {e(f["cwe"])} '
        f'· {e(f["owasp"])} · Confidence: {e(f["confidence"])}</div>'
    )
    loc = f'<code>{e(f["method"])} {e(f["location_url"])}</code>'
    if f.get("location_param"):
        loc += f' · parameter <code>{e(f["location_param"])}</code>'
    parts.append(f'<p><span class="lbl">Location:</span> {loc}</p>')
    parts.append(f'<p><span class="lbl">Description.</span> {e(f["description"])}</p>')
    parts.append(f'<p><span class="lbl">Root cause.</span> {e(f["root_cause"])}</p>')
    parts.append(f'<p><span class="lbl">Impact.</span> {e(f["impact"])}</p>')

    if f.get("evidence"):
        parts.append('<p class="lbl">Reproduction / evidence.</p>')
        for ev in f["evidence"]:
            parts.append(f"<pre>{e(_evidence_text(ev))}</pre>")
            if ev.get("note"):
                parts.append(f'<p class="muted">{e(ev["note"])}</p>')

    parts.append(f'<p><span class="lbl">Remediation.</span> {e(f["remediation"])}</p>')
    for lang, code in (f.get("remediation_code") or {}).items():
        parts.append(f'<p class="muted">Example ({e(lang)}):</p><pre>{e(code)}</pre>')

    if f.get("references"):
        parts.append('<p class="lbl">References.</p><ul>')
        for ref in f["references"]:
            parts.append(f'<li><a href="{e(ref)}">{e(ref)}</a></li>')
        parts.append("</ul>")
    parts.append("</div>")
    return "\n".join(parts)


def _evidence_text(ev: dict) -> str:
    lines = []
    if ev.get("request_line"):
        lines.append(ev["request_line"])
    for k, v in (ev.get("request_headers") or {}).items():
        lines.append(f"{k}: {v}")
    if ev.get("request_body"):
        lines.append("")
        lines.append(ev["request_body"])
    if ev.get("response_status"):
        lines.append(f"--> HTTP {ev['response_status']}")
    for k, v in (ev.get("response_headers") or {}).items():
        lines.append(f"{k}: {v}")
    if ev.get("response_excerpt"):
        lines.append("")
        lines.append(ev["response_excerpt"].strip())
    return "\n".join(lines)
