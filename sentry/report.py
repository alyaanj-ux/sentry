"""Self-contained HTML report for scheduled scans."""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from . import config, store

SEV_COLORS = {
    "high": ("#7f1d1d", "#fecaca", "High"),
    "medium": ("#78350f", "#fed7aa", "Medium"),
    "low": ("#1e3a5f", "#bfdbfe", "Low"),
    "info": ("#334155", "#e2e8f0", "Info"),
}


def human_size(n: int | None) -> str:
    if not n:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} GB"


def _fmt_time(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso)
        return dt.astimezone().strftime("%a %d %b %Y, %H:%M")
    except ValueError:
        return iso


def _indicator_html(indicators: list[dict]) -> str:
    if not indicators:
        return ""
    blocks = []
    for ind in indicators:
        bg, fg, lbl = SEV_COLORS.get(ind.get("severity", "info"), SEV_COLORS["info"])
        ex = "".join(f"<li><code>{html.escape(str(e))}</code></li>"
                     for e in ind.get("examples", []))
        blocks.append(f"""
        <tr><td><span class="sev" style="background:{bg};color:{fg}">{lbl}</span></td>
        <td><div class="fname">{html.escape(ind.get('title', ''))}</div>
            <div class="meta">{html.escape(ind.get('detail', ''))}</div>
            <ul class="reasons" style="margin-top:7px">{ex}</ul></td></tr>""")
    return f"""
    <div class="card">
      <h2>System indicators ({len(indicators)})</h2>
      <table><tbody>{''.join(blocks)}</tbody></table>
    </div>"""


def build_report(scan_id: int, findings: list[dict], scan: dict,
                 notes: list[str] | None = None,
                 indicators: list[dict] | None = None) -> Path:
    config.ensure_dirs()
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    out = config.REPORTS_DIR / f"scan_{stamp}_id{scan_id}.html"
    port = config.load_config().get("web_port", 8787)

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    rows = []
    for f in findings:
        bg, fg, lbl = SEV_COLORS.get(f["severity"], SEV_COLORS["info"])
        reasons = "".join(
            f"<li>{html.escape(r)}</li>" for r in f.get("reasons", []))
        verdict = f.get("verdict") or "unreviewed"
        rows.append(f"""
        <tr>
          <td><span class="sev" style="background:{bg};color:{fg}">{lbl} · {f['score']}</span></td>
          <td>
            <div class="fname">{html.escape(f['filename'])}</div>
            <div class="fpath">{html.escape(f['directory'])}</div>
            <div class="meta">{human_size(f['size'])} · modified {_fmt_time(f.get('mtime'))}</div>
            <div class="hash">{html.escape(f['sha256'])}</div>
          </td>
          <td><ul class="reasons">{reasons}</ul></td>
          <td><span class="verdict v-{verdict}">{verdict}</span></td>
        </tr>""")

    if not rows:
        rows.append('<tr><td colspan="4" class="clean">Nothing flagged. '
                    'No files in the scanned locations exceeded the reporting '
                    'threshold.</td></tr>')

    notes_html = "".join(f"<li>{html.escape(n)}</li>" for n in (notes or []))
    paths_html = ""
    try:
        import json
        paths = json.loads(scan.get("paths") or "[]")
        paths_html = "".join(f"<li><code>{html.escape(p)}</code></li>" for p in paths)
    except Exception:  # noqa: BLE001
        pass

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentry scan report — {stamp}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",
         Roboto,sans-serif; background:#f6f7f9; color:#16181d; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background:#0f1115; color:#e6e8ec; }}
    .card,.hdr {{ background:#171a20 !important; border-color:#262b35 !important; }}
    th {{ background:#1d2129 !important; }}
    tr:nth-child(even) td {{ background:#14171d; }}
    .fpath,.meta,.hash {{ color:#9aa3b2 !important; }}
    code {{ background:#22272f; }}
  }}
  .wrap {{ max-width:1180px; margin:0 auto; padding:28px 20px 60px; }}
  .hdr {{ background:#fff; border:1px solid #e3e6eb; border-radius:12px;
          padding:22px 24px; margin-bottom:18px; }}
  h1 {{ margin:0 0 4px; font-size:21px; letter-spacing:-.01em; }}
  .sub {{ color:#6b7280; font-size:13.5px; }}
  .stats {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:16px; }}
  .stat {{ background:#f1f3f6; border-radius:9px; padding:10px 14px; min-width:104px; }}
  @media (prefers-color-scheme: dark) {{ .stat {{ background:#1d2129; }} }}
  .stat b {{ display:block; font-size:20px; line-height:1.2; }}
  .stat span {{ font-size:11.5px; text-transform:uppercase; letter-spacing:.05em;
                color:#6b7280; }}
  .card {{ background:#fff; border:1px solid #e3e6eb; border-radius:12px;
           overflow:hidden; margin-bottom:18px; }}
  .card h2 {{ margin:0; padding:14px 20px; font-size:14px; text-transform:uppercase;
              letter-spacing:.06em; color:#6b7280; border-bottom:1px solid #e3e6eb; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ background:#f1f3f6; text-align:left; font-size:11.5px; text-transform:uppercase;
        letter-spacing:.05em; color:#6b7280; padding:9px 14px; }}
  td {{ padding:13px 14px; border-top:1px solid #e9ecf1; vertical-align:top; }}
  @media (prefers-color-scheme: dark) {{ td {{ border-color:#22272f; }} }}
  .sev {{ display:inline-block; padding:3px 9px; border-radius:20px; font-size:11.5px;
          font-weight:650; white-space:nowrap; }}
  .fname {{ font-weight:600; word-break:break-all; }}
  .fpath {{ color:#6b7280; font-size:12.5px; word-break:break-all;
            font-family:ui-monospace,Consolas,monospace; margin-top:2px; }}
  .meta {{ color:#6b7280; font-size:12px; margin-top:3px; }}
  .hash {{ color:#9aa3b2; font-size:10.5px; font-family:ui-monospace,Consolas,monospace;
           margin-top:3px; word-break:break-all; }}
  ul.reasons {{ margin:0; padding-left:17px; font-size:13px; }}
  ul.reasons li {{ margin-bottom:3px; }}
  .verdict {{ font-size:12px; padding:2px 8px; border-radius:5px; background:#eef1f5;
              color:#4b5563; }}
  .v-malicious {{ background:#fee2e2; color:#991b1b; }}
  .v-unknown {{ background:#fef3c7; color:#92400e; }}
  .v-safe {{ background:#dcfce7; color:#166534; }}
  .clean {{ text-align:center; color:#6b7280; padding:34px 14px; }}
  code {{ background:#f1f3f6; padding:1px 5px; border-radius:4px; font-size:12.5px; }}
  .action {{ background:#eff6ff; border:1px solid #bfdbfe; color:#1e3a5f;
             border-radius:10px; padding:14px 18px; font-size:14px; }}
  @media (prefers-color-scheme: dark) {{
    .action {{ background:#132033; border-color:#1e3a5f; color:#bfdbfe; }}
  }}
  ul.plain {{ margin:0; padding:14px 20px 18px 38px; font-size:13.5px; color:#4b5563; }}
  @media (prefers-color-scheme: dark) {{ ul.plain {{ color:#9aa3b2; }} }}
</style></head><body><div class="wrap">

<div class="hdr">
  <h1>Sentry weekly scan report</h1>
  <div class="sub">Scan #{scan_id} · {scan.get('trigger', 'scheduled')} ·
    started {_fmt_time(scan.get('started_at'))} ·
    finished {_fmt_time(scan.get('finished_at'))}</div>
  <div class="stats">
    <div class="stat"><b>{scan.get('files_scanned', 0):,}</b><span>files scanned</span></div>
    <div class="stat"><b>{len(findings)}</b><span>flagged</span></div>
    <div class="stat"><b>{by_sev.get('high', 0)}</b><span>high</span></div>
    <div class="stat"><b>{by_sev.get('medium', 0)}</b><span>medium</span></div>
    <div class="stat"><b>{by_sev.get('low', 0)}</b><span>low</span></div>
    <div class="stat"><b>{scan.get('errors', 0)}</b><span>read errors</span></div>
  </div>
</div>

<div class="action">
  <strong>Nothing has been moved or deleted.</strong> This report is read-only.
  To act on anything below, open the Sentry dashboard
  (<code>python -m sentry serve</code>, then
  <code>http://127.0.0.1:{port}</code>) and mark each item
  <em>Malicious</em>, <em>Unknown</em>, or <em>Safe</em>.
</div>

{_indicator_html(indicators or [])}

<div class="card" style="margin-top:18px">
  <h2>Findings ({len(findings)})</h2>
  <table>
    <thead><tr><th style="width:112px">Severity</th><th style="width:34%">File &amp; location</th>
    <th>Why it was flagged</th><th style="width:96px">Verdict</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</div>

<div class="card">
  <h2>Locations scanned</h2>
  <ul class="plain">{paths_html or '<li>—</li>'}</ul>
</div>

{f'<div class="card"><h2>Scan notes</h2><ul class="plain">{notes_html}</ul></div>' if notes_html else ''}

<div class="sub" style="text-align:center;margin-top:22px">
  Sentry is a local heuristic scanner, not a replacement for real-time endpoint
  protection. Keep your primary antivirus enabled.
</div>
</div></body></html>"""

    out.write_text(doc, encoding="utf-8")
    return out
