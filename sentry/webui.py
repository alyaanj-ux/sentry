"""Local web dashboard. Binds to loopback only."""
from __future__ import annotations

import json
import os
import string
import subprocess
import threading
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from . import config, engine, feeds, quarantine, report, store

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Mutating endpoints require this header. A hostile web page cannot set a custom
# header on a cross-origin form/simple request without passing CORS preflight,
# so this blocks the drive-by-CSRF case for a loopback service.
GUARD_HEADER = "X-Sentry-Local"


def _guard():
    if request.method in ("POST", "DELETE") and not request.headers.get(GUARD_HEADER):
        return jsonify({"error": "Missing local request header."}), 403
    host = (request.host or "").split(":")[0]
    if host not in ("127.0.0.1", "localhost", "[::1]", "::1"):
        return jsonify({"error": "This service only accepts loopback requests."}), 403
    return None


@app.before_request
def before():
    return _guard()


# --------------------------------------------------------------- state

@app.get("/api/state")
def api_state():
    cfg = config.load_config()
    return jsonify({
        "config": cfg,
        "presets": {k: {"label": config.PRESET_LABELS.get(k, k), "paths": v}
                    for k, v in config.preset_paths().items()},
        "resolved_paths": config.resolved_scan_paths(cfg),
        "counts": store.counts(),
        "progress": engine.PROGRESS.snapshot(),
        "last_scan": store.last_scan(),
        "feed": feeds.feed_status(),
        "yara": feeds.yara_status(),
        "data_root": str(config.DATA_ROOT),
        "quarantine_dir": str(config.QUARANTINE_DIR),
        "is_windows": config.IS_WINDOWS,
    })


def json_body() -> dict:
    """Request JSON as a dict, always.

    `get_json(silent=True) or {}` only covers *unparseable* bodies: a body that
    is valid JSON but not an object ([1,2,3], "str", 42, true) is truthy and
    survives the `or {}`, then blows up on .get()/.items() with a 500.
    """
    body = request.get_json(force=True, silent=True)
    return body if isinstance(body, dict) else {}


@app.post("/api/config")
def api_config():
    body = json_body()
    allowed = {"enabled_presets", "custom_paths", "exclusions", "report_threshold",
               "max_file_mb", "use_yara", "use_hash_feed", "follow_symlinks",
               "notify_on_scheduled_scan", "feed_max_age_days"}
    update = {k: v for k, v in body.items() if k in allowed}
    # Numeric settings must be validated here: a bad value is persisted and would
    # otherwise silently break every later scan (max_file_mb <= 0 gates out every
    # file on disk, and an unguarded int() answers 500 instead of 400).
    numeric = {"report_threshold": (int, 1, 100),
               "max_file_mb": (int, 1, 1024 * 1024),
               "feed_max_age_days": (float, 0, 3650)}
    for key, (caster, lo, hi) in numeric.items():
        if key not in update:
            continue
        try:
            val = caster(update[key])
        except (TypeError, ValueError):
            return jsonify({"error": f"{key} must be a number."}), 400
        if val != val or val in (float("inf"), float("-inf")):  # NaN / inf
            return jsonify({"error": f"{key} must be a number."}), 400
        update[key] = max(lo, min(hi, val))
    for key in ("enabled_presets", "custom_paths", "exclusions"):
        if key in update and not (isinstance(update[key], list)
                                  and all(isinstance(x, str) for x in update[key])):
            return jsonify({"error": f"{key} must be a list of strings."}), 400
    config.save_config(update)
    cfg = config.load_config()
    return jsonify({"ok": True, "config": cfg,
                    "resolved_paths": config.resolved_scan_paths(cfg)})


# ------------------------------------------------------- folder browser

def windows_drives() -> list[str]:
    """Drive roots that exist, via GetLogicalDrives.

    os.path.exists("A:\\\\") for every letter A-Z is the wrong way to do this on
    Windows: it can block for seconds per letter on a disconnected mapped
    network drive, and probing an empty removable/optical drive can raise the
    'There is no disk in the drive' hardware dialog. GetLogicalDrives is a
    single non-blocking bitmask read from kernel32, already in the stdlib via
    ctypes — no new dependency.
    """
    try:
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()  # type: ignore[attr-defined]
        if mask:
            return [f"{letter}:\\" for i, letter in enumerate(string.ascii_uppercase)
                    if mask & (1 << i)]
    except Exception:  # noqa: BLE001
        pass
    # Fallback for a non-Windows host or a locked-down ctypes environment.
    return [f"{letter}:\\" for letter in string.ascii_uppercase
            if os.path.exists(f"{letter}:\\")]


@app.get("/api/browse")
def api_browse():
    """Directory listing used by the folder picker."""
    raw = request.args.get("path", "")
    if not raw:
        roots = []
        if config.IS_WINDOWS:
            for d in windows_drives():
                roots.append({"name": d, "path": d})
            up = os.environ.get("USERPROFILE")
            if up:
                roots.insert(0, {"name": f"Home ({os.path.basename(up)})", "path": up})
        else:
            roots.append({"name": "Home", "path": os.path.expanduser("~")})
            roots.append({"name": "/", "path": "/"})
        return jsonify({"path": "", "parent": None, "dirs": roots})

    path = os.path.abspath(os.path.expandvars(os.path.expanduser(raw)))
    if not os.path.isdir(path):
        return jsonify({"error": f"Not a directory: {path}"}), 400

    dirs = []
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False) and not entry.name.startswith("$"):
                        dirs.append({"name": entry.name, "path": entry.path})
                except OSError:
                    continue
    except PermissionError:
        return jsonify({"error": f"Permission denied reading {path}"}), 403
    except OSError as exc:
        return jsonify({"error": str(exc)}), 400

    dirs.sort(key=lambda d: d["name"].lower())
    parent = os.path.dirname(path.rstrip(os.sep))
    if parent == path.rstrip(os.sep):
        parent = ""
    return jsonify({"path": path, "parent": parent, "dirs": dirs[:2000]})


# --------------------------------------------------------------- scans

@app.post("/api/scan")
def api_scan():
    body = json_body()
    paths = body.get("paths")
    if paths is not None:
        paths = [os.path.abspath(os.path.expandvars(p)) for p in paths
                 if os.path.exists(os.path.expandvars(p))]
        if not paths:
            return jsonify({"error": "None of the supplied paths exist."}), 400
    if not engine.scan_in_background(paths, trigger="manual"):
        return jsonify({"error": "A scan is already running."}), 409
    return jsonify({"ok": True})


@app.get("/api/scan/progress")
def api_progress():
    return jsonify(engine.PROGRESS.snapshot())


@app.post("/api/scan/cancel")
def api_cancel():
    engine.PROGRESS.cancel = True
    return jsonify({"ok": True})


@app.get("/api/scans")
def api_scans():
    return jsonify(store.scan_history(30))


# ------------------------------------------------------------ findings

@app.get("/api/findings")
def api_findings():
    include_safe = request.args.get("include_safe") == "1"
    scan_id = request.args.get("scan_id", type=int)
    return jsonify(store.get_findings(include_safe=include_safe, scan_id=scan_id))


@app.post("/api/verdict")
def api_verdict():
    body = json_body()
    raw_sha = body.get("sha256")
    raw_verdict = body.get("verdict")
    # A JSON number/list/object is truthy but has no .strip(): treat anything
    # that is not a string as absent so the guards below answer 400, not 500.
    sha = (raw_sha if isinstance(raw_sha, str) else "").strip().lower()
    verdict = (raw_verdict if isinstance(raw_verdict, str) else "").strip().lower()
    if len(sha) != 64:
        return jsonify({"error": "Invalid sha256."}), 400
    if verdict == "clear":
        store.clear_verdict(sha)
        return jsonify({"ok": True, "verdict": None})
    try:
        store.set_verdict(sha, verdict, path=body.get("path"), note=body.get("note"))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True, "verdict": verdict})


# ---------------------------------------------------------- quarantine

@app.get("/api/quarantine")
def api_quarantine_list():
    return jsonify(store.quarantine_list(active_only=False))


@app.post("/api/quarantine")
def api_quarantine():
    body = json_body()
    fid = body.get("finding_id")
    # bool is a subclass of int, so {"finding_id": true} would otherwise become
    # finding 1 and quarantine a file the caller never named.
    if not isinstance(fid, int) or isinstance(fid, bool):
        return jsonify({"error": "finding_id (int) required."}), 400
    try:
        result = quarantine.quarantine_finding(
            fid, allow_protected=body.get("allow_protected") is True)
    except quarantine.QuarantineError as exc:
        return jsonify({"error": str(exc),
                        "protected": bool(config.protected_reason(
                            (store.get_finding(fid) or {}).get("path", "")))}), 400
    return jsonify({"ok": True, **result})


@app.post("/api/restore")
def api_restore():
    body = json_body()
    mark_safe = body.get("mark_safe") is True
    try:
        # int(None) raises TypeError, which is not a ValueError.
        qid = int(body.get("quarantine_id", -1))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    entry = store.get_quarantine_entry(qid) if mark_safe else None
    try:
        result = quarantine.restore(qid)
    except (quarantine.QuarantineError, TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    # restore() clears the verdict so the file gets reviewed again next scan.
    # "Mark safe and restore" means the opposite: put it back AND allowlist it by
    # hash so it stops being flagged every week. Set after the move, so a failed
    # restore never leaves an allowlist entry behind.
    if mark_safe and entry:
        store.set_verdict(entry["sha256"], "safe",
                          path=entry["original_path"],
                          note="allowlisted on restore from quarantine")
        result["marked_safe"] = True
    return jsonify({"ok": True, **result})


@app.post("/api/purge")
def api_purge():
    body = json_body()
    if body.get("confirm") is not True:
        return jsonify({"error": "confirm:true required for permanent deletion."}), 400
    try:
        result = quarantine.purge(int(body.get("quarantine_id", -1)), confirm=True)
    except (quarantine.QuarantineError, TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"ok": True, **result})


# -------------------------------------------------------------- extras

@app.post("/api/feed/update")
def api_feed_update():
    full = bool((json_body()).get("full"))
    ok, msg = feeds.update_hash_feed(full=full)
    return jsonify({"ok": ok, "message": msg, "feed": feeds.feed_status()})


@app.get("/api/reports")
def api_reports():
    config.ensure_dirs()
    files = sorted(config.REPORTS_DIR.glob("*.html"),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    return jsonify([{"name": f.name, "size": f.stat().st_size,
                     "mtime": f.stat().st_mtime} for f in files[:40]])


@app.get("/reports/<path:name>")
def serve_report(name: str):
    return send_from_directory(config.REPORTS_DIR, name)


def explorer_cmdline(path: str) -> str:
    """Exact command line that reveals `path` in Explorer.

    explorer.exe parses its own command line and only understands the
    '/select,"<path>"' form, so this has to stay a raw command-line string
    rather than an argv list. It is passed to subprocess with shell=False,
    which on Windows hands the string straight to CreateProcess — no cmd.exe,
    so '&', '^', '%' and friends are never reinterpreted. A '"' cannot appear
    in a Windows filename, and is rejected below regardless.
    """
    p = os.path.normpath(path)
    if '"' in p or "\r" in p or "\n" in p:
        raise ValueError("Illegal character in path.")
    return f'explorer.exe /select,"{p}"'


@app.post("/api/open-folder")
def api_open_folder():
    """Reveal a file's containing folder in the OS file manager."""
    body = json_body()
    target = body.get("path")
    if not isinstance(target, str) or not target.strip():
        # os.path.abspath("") is the server's cwd, which always exists — so an
        # empty/absent path would pop a file manager on a folder nobody named.
        return jsonify({"error": "A path is required."}), 400
    p = Path(os.path.abspath(os.path.expandvars(target)))
    # The thing we are about to hand to the file manager must exist *now*. The
    # old guard passed whenever the PARENT existed, so a file that had been
    # moved or deleted since the scan still got handed to Explorer, which then
    # showed the user a modal "Location is not available" dialog. Revealing a
    # file means opening its parent, so for a file the parent is what must exist.
    reveal_dir = p.parent if p.is_file() else p
    if not p.exists() or not reveal_dir.is_dir():
        return jsonify({
            "error": "That path no longer exists — it may have been moved, "
                     "deleted, or quarantined since the last scan."
        }), 400
    try:
        if config.IS_WINDOWS:
            if p.is_file():
                # NOT os.system(): that goes through cmd.exe, so a filename
                # containing a double quote lets the rest of the path run as a
                # command, and '&', '^', '%' are all reinterpreted. An argument
                # list is handed to CreateProcess with no shell in between.
                subprocess.Popen(explorer_cmdline(str(p)), shell=False)
            else:
                os.startfile(str(p))  # type: ignore[attr-defined]
        else:
            subprocess.Popen(["xdg-open", str(p if p.is_dir() else p.parent)])
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 500
    return jsonify({"ok": True})


# ------------------------------------------------------- weekly schedule

TASK_NAME = "Sentry Weekly Scan"


def _schtasks(*args: str) -> tuple[int, str]:
    """Run schtasks; any spawn failure reads as exit -1, never an exception.

    schtasks can be missing (Server Core), blocked (test trip-wires stub
    process spawning), or time out — none of those should 500 the API.
    """
    try:
        r = subprocess.run(["schtasks", *args], capture_output=True, text=True,
                           timeout=15, check=False, errors="replace")
    except Exception as exc:  # noqa: BLE001
        return -1, str(exc)
    return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()


@app.get("/api/schedule")
def api_schedule():
    """State of the weekly scheduled task, for the pause/resume control."""
    if not config.IS_WINDOWS:
        return jsonify({"supported": False, "installed": False})
    rc, out = _schtasks("/Query", "/TN", TASK_NAME, "/FO", "CSV", "/NH")
    if rc != 0:
        return jsonify({"supported": True, "installed": False})
    # One CSV line: "TaskName","Next Run Time","Status"
    line = out.splitlines()[0] if out else ""
    parts = [p.strip().strip('"') for p in line.split('","')] if line else []
    status = parts[2] if len(parts) >= 3 else ""
    return jsonify({"supported": True, "installed": True,
                    "paused": status.lower() == "disabled",
                    "status": status,
                    "next_run": parts[1] if len(parts) >= 2 else None})


@app.post("/api/schedule")
def api_schedule_change():
    if not config.IS_WINDOWS:
        return jsonify({"error": "Scheduling is Windows-only."}), 400
    action = json_body().get("action")
    if action not in ("pause", "resume"):
        return jsonify({"error": "action must be 'pause' or 'resume'."}), 400
    flag = "/DISABLE" if action == "pause" else "/ENABLE"
    rc, out = _schtasks("/Change", "/TN", TASK_NAME, flag)
    if rc != 0:
        return jsonify({"error": out or f"schtasks exit {rc}"}), 400
    return jsonify({"ok": True, "paused": action == "pause"})


@app.get("/")
def index():
    return PAGE, 200, {"Content-Type": "text/html; charset=utf-8"}


@app.get("/review")
def review():
    """The triage queue used by the desktop app: one finding at a time."""
    return REVIEW_PAGE, 200, {"Content-Type": "text/html; charset=utf-8"}


def serve(port: int | None = None, open_browser: bool = True) -> None:
    store.init_db()
    cfg = config.load_config()
    port = port or int(cfg.get("web_port", 8787))
    url = f"http://127.0.0.1:{port}"
    print(f"\n  Sentry dashboard: {url}")
    print(f"  Data directory:   {config.DATA_ROOT}")
    print("  Press Ctrl+C to stop.\n")
    if open_browser:
        threading.Timer(1.0, lambda: __import__("webbrowser").open(url)).start()
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)


PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentry</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--bd:#e3e6eb;--fg:#16181d;
--mut:#6b7280;--acc:#2563eb;--accbg:#eff6ff;--hov:#f1f3f6}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a20;--bd:#262b35;
--fg:#e6e8ec;--mut:#9aa3b2;--acc:#60a5fa;--accbg:#132033;--hov:#1d2129}}
*{box-sizing:border-box}
body{margin:0;font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:var(--bg);color:var(--fg)}
.wrap{max-width:1240px;margin:0 auto;padding:22px 18px 70px}
header{display:flex;align-items:baseline;gap:12px;margin-bottom:6px;flex-wrap:wrap}
h1{margin:0;font-size:20px;letter-spacing:-.01em}
.tag{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);
border:1px solid var(--bd);padding:2px 7px;border-radius:20px}
.sub{color:var(--mut);font-size:13px;margin-bottom:18px}
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--bd);margin-bottom:20px;flex-wrap:wrap}
.tab{padding:9px 15px;font-size:14px;cursor:pointer;border:none;background:none;
color:var(--mut);border-bottom:2px solid transparent;font-family:inherit}
.tab.on{color:var(--fg);border-bottom-color:var(--acc);font-weight:600}
.tab .badge{display:inline-block;margin-left:6px;background:var(--acc);color:#fff;
font-size:10.5px;padding:1px 6px;border-radius:20px;font-weight:700}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;
margin-bottom:16px;overflow:hidden}
.card h2{margin:0;padding:13px 18px;font-size:11.5px;text-transform:uppercase;
letter-spacing:.06em;color:var(--mut);border-bottom:1px solid var(--bd);
display:flex;justify-content:space-between;align-items:center;gap:10px}
.pad{padding:16px 18px}
.stats{display:flex;gap:9px;flex-wrap:wrap;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--bd);border-radius:10px;
padding:11px 15px;min-width:112px}
.stat b{display:block;font-size:21px;line-height:1.2}
.stat span{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}
button{font-family:inherit;font-size:13.5px;padding:7px 13px;border-radius:8px;
border:1px solid var(--bd);background:var(--card);color:var(--fg);cursor:pointer}
button:hover:not(:disabled){background:var(--hov)}
button:disabled{opacity:.5;cursor:not-allowed}
button.primary{background:var(--acc);border-color:var(--acc);color:#fff}
button.primary:hover:not(:disabled){filter:brightness(1.08);background:var(--acc)}
button.sm{font-size:12.5px;padding:5px 10px}
button.mal{border-color:#dc2626;color:#dc2626}
button.mal.on{background:#dc2626;color:#fff}
button.unk{border-color:#d97706;color:#d97706}
button.unk.on{background:#d97706;color:#fff}
button.safe{border-color:#16a34a;color:#16a34a}
button.safe.on{background:#16a34a;color:#fff}
button.danger{border-color:#dc2626;color:#dc2626}
table{width:100%;border-collapse:collapse}
th{background:var(--hov);text-align:left;font-size:11px;text-transform:uppercase;
letter-spacing:.05em;color:var(--mut);padding:9px 14px;font-weight:600}
td{padding:13px 14px;border-top:1px solid var(--bd);vertical-align:top}
.sev{display:inline-block;padding:3px 9px;border-radius:20px;font-size:11.5px;font-weight:650;white-space:nowrap}
.s-high{background:#fee2e2;color:#991b1b}.s-medium{background:#fed7aa;color:#78350f}
.s-low{background:#dbeafe;color:#1e3a5f}.s-info{background:var(--hov);color:var(--mut)}
.fname{font-weight:600;word-break:break-all}
.fpath{color:var(--mut);font-size:12.5px;font-family:ui-monospace,Consolas,monospace;
word-break:break-all;margin-top:3px}
.fmeta{color:var(--mut);font-size:11.5px;margin-top:3px}
.fhash{color:var(--mut);opacity:.75;font-size:10.5px;font-family:ui-monospace,Consolas,monospace;
word-break:break-all;margin-top:3px}
ul.reasons{margin:0;padding-left:17px;font-size:13px}
ul.reasons li{margin-bottom:3px}
.acts{display:flex;flex-wrap:wrap;gap:5px}
.gone{text-decoration:line-through;opacity:.6}
.prot{background:#fffbeb;border:1px solid #f59e0b;color:#92400e;border-radius:7px;
padding:6px 9px;font-size:12.5px;margin-top:6px}
@media(prefers-color-scheme:dark){.prot{background:#2a2210;color:#fcd34d}}
label.chk{display:flex;align-items:flex-start;gap:9px;padding:9px 0;cursor:pointer;font-size:14px}
label.chk input{margin-top:4px}
label.chk .d{font-size:12.5px;color:var(--mut);font-family:ui-monospace,Consolas,monospace;
word-break:break-all}
.picker{display:flex;gap:14px;flex-wrap:wrap}
.plist{flex:1;min-width:290px;border:1px solid var(--bd);border-radius:9px;
max-height:290px;overflow:auto}
.pitem{padding:7px 12px;cursor:pointer;font-size:13.5px;border-bottom:1px solid var(--bd);
display:flex;justify-content:space-between;gap:8px;align-items:center}
.pitem:hover{background:var(--hov)}
.pitem:last-child{border-bottom:none}
.crumb{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:var(--mut);
padding:8px 12px;background:var(--hov);word-break:break-all}
.chosen{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.chip{background:var(--accbg);border:1px solid var(--acc);color:var(--acc);
border-radius:20px;padding:3px 10px;font-size:12.5px;display:flex;align-items:center;gap:7px;
font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.chip button{border:none;background:none;color:inherit;padding:0 2px;font-size:15px;line-height:1;cursor:pointer}
.note{background:var(--accbg);border:1px solid var(--acc);color:var(--acc);
border-radius:9px;padding:11px 15px;font-size:13.5px;margin-bottom:14px}
.warn{background:#fffbeb;border:1px solid #f59e0b;color:#92400e;border-radius:9px;
padding:11px 15px;font-size:13.5px;margin-bottom:14px}
@media(prefers-color-scheme:dark){.warn{background:#2a2210;color:#fcd34d}}
.bar{height:5px;background:var(--hov);border-radius:20px;overflow:hidden;margin-top:9px}
.bar i{display:block;height:100%;background:var(--acc);width:30%;
animation:sl 1.3s ease-in-out infinite}
@keyframes sl{0%{margin-left:-30%}100%{margin-left:100%}}
.empty{text-align:center;color:var(--mut);padding:38px 16px;font-size:14px}
.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
input[type=number],input[type=text]{font-family:inherit;font-size:13.5px;padding:6px 9px;
border:1px solid var(--bd);border-radius:7px;background:var(--card);color:var(--fg)}
code{background:var(--hov);padding:1px 5px;border-radius:4px;font-size:12.5px}
.vb{font-size:11.5px;padding:2px 8px;border-radius:5px;background:var(--hov);color:var(--mut)}
.vb.malicious{background:#fee2e2;color:#991b1b}
.vb.unknown{background:#fef3c7;color:#92400e}
.vb.safe{background:#dcfce7;color:#166534}
a{color:var(--acc)}
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#16181d;
color:#fff;padding:11px 18px;border-radius:9px;font-size:13.5px;opacity:0;
transition:opacity .25s;pointer-events:none;max-width:80vw;z-index:99}
#toast.show{opacity:1}
#toast.err{background:#991b1b}
</style></head><body><div class="wrap">

<header><h1>Sentry</h1><span class="tag">local heuristic scanner</span></header>
<div class="sub">Flags files for your review. Never moves or deletes anything on its own.</div>

<div class="stats" id="stats"></div>

<div class="tabs">
  <button class="tab on" data-t="findings">Findings <span class="badge" id="bFind">0</span></button>
  <button class="tab" data-t="scope">Scan scope</button>
  <button class="tab" data-t="quarantine">Quarantine <span class="badge" id="bQuar">0</span></button>
  <button class="tab" data-t="reports">Reports &amp; history</button>
  <button class="tab" data-t="settings">Settings</button>
</div>

<div id="v-findings">
  <div class="card"><h2>Scan
    <span class="row">
      <button class="primary" id="btnScan">Scan now</button>
      <button id="btnCancel" style="display:none">Cancel</button>
    </span></h2>
    <div class="pad" id="scanState"></div>
  </div>
  <div class="card"><h2>Flagged files
    <span class="row">
      <label style="font-size:12.5px;color:var(--mut);text-transform:none;letter-spacing:0">
        <input type="checkbox" id="showSafe"> show items marked safe</label>
      <button class="sm" onclick="loadFindings()">Refresh</button>
    </span></h2>
    <div id="findings"></div>
  </div>
</div>

<div id="v-scope" style="display:none">
  <div class="note">Pick what the weekly scheduled scan covers. These same
    locations are used when you click <b>Scan now</b>.</div>
  <div class="card"><h2>Preset locations</h2><div class="pad" id="presets"></div></div>
  <div class="card"><h2>Add specific folders</h2>
    <div class="pad">
      <div class="picker">
        <div style="flex:1;min-width:290px">
          <div class="crumb" id="crumb">Select a drive or folder</div>
          <div class="plist" id="browse"></div>
          <div class="row" style="margin-top:10px">
            <button class="sm" id="btnUp">Up one level</button>
            <button class="sm primary" id="btnAddHere">Add current folder</button>
          </div>
        </div>
        <div style="flex:1;min-width:250px">
          <div style="font-size:12.5px;color:var(--mut);margin-bottom:6px">
            Or paste a path:</div>
          <div class="row">
            <input type="text" id="manualPath" placeholder="C:\Users\you\SomeFolder" style="flex:1">
            <button class="sm" id="btnAddManual">Add</button>
          </div>
          <div style="font-size:12.5px;color:var(--mut);margin-top:14px">Selected folders:</div>
          <div class="chosen" id="chosen"></div>
        </div>
      </div>
    </div>
  </div>
  <div class="card"><h2>Effective scan list</h2><div class="pad" id="effective"></div></div>
</div>

<div id="v-quarantine" style="display:none">
  <div class="warn">Quarantined files are moved out of their original location and
    stripped of execute permission. Their original path is recorded, so
    <b>Restore</b> puts each file back exactly where it was. Nothing here is
    deleted unless you press Delete permanently.</div>
  <div class="card"><h2>Quarantine</h2><div id="quarantine"></div></div>
</div>

<div id="v-reports" style="display:none">
  <div class="card"><h2>Saved reports</h2><div id="reports"></div></div>
  <div class="card"><h2>Scan history</h2><div id="history"></div></div>
</div>

<div id="v-settings" style="display:none">
  <div class="card"><h2>Detection</h2><div class="pad" id="settings"></div></div>
  <div class="card"><h2>Environment</h2><div class="pad" id="env"></div></div>
</div>

<div id="toast"></div>
</div>
<script>
const H={'Content-Type':'application/json','X-Sentry-Local':'1'};
let S={}, FIND=[], POLL=null;

function toast(m,err){const t=document.getElementById('toast');t.textContent=m;
  t.className='show'+(err?' err':'');setTimeout(()=>t.className='',err?5200:2600);}
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function size(n){if(!n)return '0 B';const u=['B','KB','MB','GB'];let i=0;
  while(n>=1024&&i<3){n/=1024;i++}return (i?n.toFixed(1):n)+' '+u[i];}
function when(s){if(!s)return '—';const d=new Date(s);return isNaN(d)?s:
  d.toLocaleString(undefined,{weekday:'short',day:'numeric',month:'short',
  hour:'2-digit',minute:'2-digit'});}
async function api(url,opt){const r=await fetch(url,opt);let j={};
  try{j=await r.json()}catch(e){}
  if(!r.ok){throw new Error(j.error||('HTTP '+r.status))}return j;}
const post=(u,b)=>api(u,{method:'POST',headers:H,body:JSON.stringify(b||{})});

document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on'));
  b.classList.add('on');
  ['findings','scope','quarantine','reports','settings'].forEach(t=>
    document.getElementById('v-'+t).style.display = t===b.dataset.t?'':'none');
  if(b.dataset.t==='quarantine')loadQuarantine();
  if(b.dataset.t==='reports')loadReports();
  if(b.dataset.t==='scope')browse(BROWSE_AT);
});

// ------------------------------------------------------------- state
async function loadState(){
  S=await api('/api/state');
  const c=S.counts;
  document.getElementById('stats').innerHTML=[
    ['open_findings','awaiting review'],['malicious','marked malicious'],
    ['unknown','marked unknown'],['safe','allowlisted'],['quarantined','in quarantine']
  ].map(([k,l])=>`<div class="stat"><b>${c[k]}</b><span>${l}</span></div>`).join('');
  document.getElementById('bQuar').textContent=c.quarantined;
  renderScanState();renderPresets();renderChosen();renderEffective();renderSettings();
}

function renderScanState(){
  const p=S.progress||{}, last=S.last_scan;
  const el=document.getElementById('scanState');
  document.getElementById('btnScan').disabled=!!p.running;
  document.getElementById('btnCancel').style.display=p.running?'':'none';
  if(p.running){
    el.innerHTML=`<b>Scanning…</b> ${p.files_scanned.toLocaleString()} files checked,
      ${p.findings} flagged
      <div class="fpath">${esc(p.current_path||'')}</div>
      <div class="bar"><i></i></div>`;
  }else if(last){
    el.innerHTML=`Last scan: <b>${when(last.finished_at)}</b> (${esc(last.trigger)}) —
      ${(last.files_scanned||0).toLocaleString()} files checked,
      <b>${last.findings_count||0}</b> flagged, ${last.errors||0} unreadable.
      ${(p.notes&&p.notes.length)?'<ul class="reasons" style="margin-top:8px">'+
        p.notes.map(n=>'<li>'+esc(n)+'</li>').join('')+'</ul>':''}`;
  }else{
    el.innerHTML='No scan has run yet. Check your scan scope, then press <b>Scan now</b>.';
  }
}

document.getElementById('btnScan').onclick=async()=>{
  try{await post('/api/scan');toast('Scan started');startPoll();}
  catch(e){toast(e.message,1)}};
document.getElementById('btnCancel').onclick=async()=>{
  await post('/api/scan/cancel');toast('Cancelling…');};

function startPoll(){
  if(POLL)clearInterval(POLL);
  POLL=setInterval(async()=>{
    const p=await api('/api/scan/progress');S.progress=p;renderScanState();
    if(!p.running){clearInterval(POLL);POLL=null;await loadState();await loadFindings();
      toast('Scan finished — '+p.findings+' file(s) flagged');}
  },900);
}

// ---------------------------------------------------------- findings
async function loadFindings(){
  const safe=document.getElementById('showSafe').checked?'1':'0';
  FIND=await api('/api/findings?include_safe='+safe);
  document.getElementById('bFind').textContent=FIND.filter(f=>!f.verdict).length;
  const el=document.getElementById('findings');
  if(!FIND.length){el.innerHTML='<div class="empty">Nothing flagged. Either you '+
    'have not scanned yet, or nothing in the scanned locations crossed the '+
    'reporting threshold.</div>';return;}
  el.innerHTML=`<table><thead><tr>
    <th style="width:104px">Severity</th><th style="width:30%">File &amp; full path</th>
    <th>Why it was flagged</th><th style="width:212px">Your call</th>
    </tr></thead><tbody>${FIND.map(row).join('')}</tbody></table>`;
}

function row(f){
  const v=f.verdict||'', q=f.quarantine_id;
  const canQ=(v==='malicious'||v==='unknown')&&!q&&f.exists&&!f.protected;
  return `<tr>
    <td><span class="sev s-${f.severity}">${f.severity} · ${f.score}</span></td>
    <td>
      <div class="fname ${f.exists?'':'gone'}">${esc(f.filename)}</div>
      <div class="fpath">${esc(f.path)}</div>
      ${f.protected?`<div class="prot">Protected location — ${esc(f.protected)}.
        Quarantine is blocked here; removing it would likely break that program.</div>`:''}
      <div class="fmeta">${size(f.size)} · modified ${when(f.mtime)}
        ${f.exists?'':' · <b>file no longer at this path</b>'}
        ${q?' · <b>quarantined</b>':''}</div>
      <div class="fhash">SHA-256 ${esc(f.sha256)}</div>
      <div style="margin-top:7px"><button class="sm" onclick="reveal('${esc(f.path).replace(/'/g,"\\'")}')">Open folder</button></div>
    </td>
    <td><ul class="reasons">${f.reasons.map(r=>'<li>'+esc(r)+'</li>').join('')}</ul></td>
    <td>
      <div class="acts">
        <button class="sm mal ${v==='malicious'?'on':''}" onclick="mark('${f.sha256}','malicious','${esc(f.path).replace(/'/g,"\\'")}')">Malicious</button>
        <button class="sm unk ${v==='unknown'?'on':''}" onclick="mark('${f.sha256}','unknown','${esc(f.path).replace(/'/g,"\\'")}')">Unknown</button>
        <button class="sm safe ${v==='safe'?'on':''}" onclick="mark('${f.sha256}','safe','${esc(f.path).replace(/'/g,"\\'")}')">Safe</button>
      </div>
      <div class="acts" style="margin-top:6px">
        ${canQ?`<button class="sm primary" onclick="quar(${f.id})">Quarantine</button>`:''}
        ${(f.protected&&(v==='malicious'||v==='unknown')&&!q&&f.exists)?
          `<button class="sm danger" onclick="quar(${f.id},true)">Override &amp; quarantine</button>`:''}
        ${v?`<button class="sm" onclick="mark('${f.sha256}','clear','')">Clear mark</button>`:''}
      </div>
      ${v==='safe'?'<div class="fmeta">Allowlisted — future scans skip this file.</div>':''}
      ${(!v&&f.score>=45)?'<div class="fmeta">Marking is required before quarantine.</div>':''}
    </td></tr>`;
}

async function mark(sha,verdict,path){
  try{await post('/api/verdict',{sha256:sha,verdict:verdict,path:path});
    toast(verdict==='clear'?'Mark cleared':'Marked '+verdict);
    await loadFindings();await loadState();}
  catch(e){toast(e.message,1)}}

async function quar(id,override){
  const f=FIND.find(x=>x.id===id)||{};
  if(override){
    if(!confirm('OVERRIDE: this file is in a protected application folder.\n\n'+
      (f.protected||'')+'\n\nMoving it will probably stop that program from '+
      'working. If it is a game, the launcher\'s "verify integrity of game '+
      'files" replaces a bad file correctly and this does not.\n\nContinue?'))return;
    if(!confirm('Second confirmation: quarantine a file from a protected '+
      'application folder?'))return;
  }else if(!confirm('Move this file into quarantine?\n\nIt will be moved out of its '+
    'current folder and stripped of execute permission. Its original path is '+
    'recorded so you can restore it exactly. Nothing is deleted.'))return;
  try{const r=await post('/api/quarantine',{finding_id:id,allow_protected:override===true});
    toast('Quarantined → '+r.quarantine_path);
    await loadFindings();await loadState();}
  catch(e){toast(e.message,1)}}

async function reveal(p){try{await post('/api/open-folder',{path:p});}
  catch(e){toast(e.message,1)}}
document.getElementById('showSafe').onchange=loadFindings;

// -------------------------------------------------------- quarantine
async function loadQuarantine(){
  const q=await api('/api/quarantine');const el=document.getElementById('quarantine');
  if(!q.length){el.innerHTML='<div class="empty">Quarantine is empty.</div>';return;}
  el.innerHTML=`<table><thead><tr><th style="width:34%">Original location</th>
    <th>Details</th><th style="width:210px">Actions</th></tr></thead><tbody>${
    q.map(e=>{const active=!e.restored_at&&!e.deleted_at;
    return `<tr>
      <td><div class="fname">${esc(e.original_path.split(/[\\/]/).pop())}</div>
        <div class="fpath">${esc(e.original_path)}</div>
        <div class="fmeta">${size(e.size)} · quarantined ${when(e.quarantined_at)}</div></td>
      <td><div class="fmeta">Verdict: <span class="vb ${esc(e.verdict)}">${esc(e.verdict)}</span></div>
        <div class="fpath" style="margin-top:5px">now at: ${esc(e.quarantine_path)}</div>
        <div class="fhash">SHA-256 ${esc(e.sha256)}</div>
        <ul class="reasons" style="margin-top:6px">${(e.reasons||[]).map(r=>'<li>'+esc(r)+'</li>').join('')}</ul></td>
      <td>${active?`<div class="acts">
          <button class="sm" onclick="restore(${e.id})">Restore to original path</button>
          <button class="sm safe" onclick="restore(${e.id},true)">Mark safe &amp; restore</button>
          <button class="sm danger" onclick="purge(${e.id})">Delete permanently</button></div>`
        :`<div class="fmeta">${e.restored_at?'Restored '+when(e.restored_at)
          :'Deleted '+when(e.deleted_at)}</div>`}</td></tr>`}).join('')}</tbody></table>`;
}
async function restore(id,markSafe){
  try{const r=await post('/api/restore',{quarantine_id:id,mark_safe:markSafe===true});
    toast((markSafe?'Marked safe and restored to ':'Restored to ')+r.restored_to);
    loadQuarantine();loadState();loadFindings();}
  catch(e){toast(e.message,1)}}
async function purge(id){
  if(!confirm('Permanently delete this file?\n\nThis cannot be undone. If you are '+
    'not certain the file is malicious, restore it instead.'))return;
  if(!confirm('Final confirmation: delete permanently?'))return;
  try{await post('/api/purge',{quarantine_id:id,confirm:true});
    toast('Deleted permanently');loadQuarantine();loadState();}
  catch(e){toast(e.message,1)}}

// ------------------------------------------------------------- scope
function renderPresets(){
  const en=S.config.enabled_presets||[];
  document.getElementById('presets').innerHTML=Object.entries(S.presets).map(([k,v])=>
    `<label class="chk"><input type="checkbox" data-p="${k}" ${en.includes(k)?'checked':''}>
      <span><b>${esc(v.label)}</b><div class="d">${v.paths.map(esc).join('<br>')}</div></span>
    </label>`).join('');
  document.querySelectorAll('#presets input').forEach(i=>i.onchange=async()=>{
    const sel=[...document.querySelectorAll('#presets input:checked')].map(x=>x.dataset.p);
    await post('/api/config',{enabled_presets:sel});await loadState();toast('Scan scope saved');});
}
function renderChosen(){
  const cp=S.config.custom_paths||[];
  document.getElementById('chosen').innerHTML=cp.length?cp.map((p,i)=>
    `<span class="chip">${esc(p)}<button onclick="rmPath(${i})" title="remove">×</button></span>`
    ).join(''):'<span style="font-size:12.5px;color:var(--mut)">None</span>';
}
function renderEffective(){
  const r=S.resolved_paths||[];
  document.getElementById('effective').innerHTML=r.length?
    '<ul class="reasons">'+r.map(p=>'<li><code>'+esc(p)+'</code></li>').join('')+'</ul>'
    +`<div class="fmeta" style="margin-top:9px">${r.length} location(s). Paths already
      covered by a parent folder are removed automatically.</div>`
    :'<div class="fmeta">No valid locations selected — a scan would do nothing.</div>';
}
async function addPath(p){
  const cp=(S.config.custom_paths||[]).slice();
  if(cp.includes(p)){toast('Already in the list');return;}
  cp.push(p);await post('/api/config',{custom_paths:cp});await loadState();
  toast('Added '+p);}
async function rmPath(i){
  const cp=(S.config.custom_paths||[]).slice();cp.splice(i,1);
  await post('/api/config',{custom_paths:cp});await loadState();}

let BROWSE_AT='';
async function browse(p){
  try{const r=await api('/api/browse?path='+encodeURIComponent(p||''));
    BROWSE_AT=r.path||'';
    document.getElementById('crumb').textContent=r.path||'Select a drive or folder';
    document.getElementById('btnUp').disabled=!r.parent&&!r.path;
    document.getElementById('btnAddHere').disabled=!r.path;
    document.getElementById('browse').innerHTML=r.dirs.length?r.dirs.map(d=>
      `<div class="pitem"><span onclick="browse('${esc(d.path).replace(/'/g,"\\'")}')"
        style="flex:1">📁 ${esc(d.name)}</span>
       <button class="sm" onclick="addPath('${esc(d.path).replace(/'/g,"\\'")}')">add</button></div>`
      ).join(''):'<div class="empty" style="padding:20px">No subfolders</div>';
    window.__parent=r.parent;}
  catch(e){toast(e.message,1)}}
document.getElementById('btnUp').onclick=()=>browse(window.__parent||'');
document.getElementById('btnAddHere').onclick=()=>BROWSE_AT&&addPath(BROWSE_AT);
document.getElementById('btnAddManual').onclick=()=>{
  const v=document.getElementById('manualPath').value.trim();
  if(v){addPath(v);document.getElementById('manualPath').value='';}};

// ----------------------------------------------------------- reports
async function loadReports(){
  const r=await api('/api/reports');
  document.getElementById('reports').innerHTML=r.length?
    '<table><tbody>'+r.map(f=>`<tr><td><a href="/reports/${encodeURIComponent(f.name)}"
      target="_blank">${esc(f.name)}</a></td><td class="fmeta">${size(f.size)}</td>
      <td class="fmeta">${when(new Date(f.mtime*1000).toISOString())}</td></tr>`).join('')
      +'</tbody></table>'
    :'<div class="empty">No saved reports yet. The weekly scheduled scan writes one each run.</div>';
  const h=await api('/api/scans');
  document.getElementById('history').innerHTML=h.length?
    '<table><thead><tr><th>Started</th><th>Trigger</th><th>Files</th><th>Flagged</th>'+
    '<th>Errors</th></tr></thead><tbody>'+h.map(s=>`<tr><td>${when(s.started_at)}</td>
      <td>${esc(s.trigger)}</td><td>${(s.files_scanned||0).toLocaleString()}</td>
      <td>${s.findings_count||0}</td><td>${s.errors||0}</td></tr>`).join('')+'</tbody></table>'
    :'<div class="empty">No scans recorded.</div>';
}

// ---------------------------------------------------------- settings
function renderSettings(){
  const c=S.config;
  document.getElementById('settings').innerHTML=`
    <div class="row" style="margin-bottom:12px">
      <label style="flex:1">Reporting threshold (1–100, lower = noisier)</label>
      <input type="number" id="thr" min="1" max="100" value="${c.report_threshold}" style="width:82px">
    </div>
    <div class="row" style="margin-bottom:12px">
      <label style="flex:1">Skip files larger than (MB)</label>
      <input type="number" id="mx" min="1" max="4096" value="${c.max_file_mb}" style="width:82px">
    </div>
    <label class="chk"><input type="checkbox" id="uy" ${c.use_yara?'checked':''}>
      <span>Use YARA pattern rules<div class="d">${esc(S.yara.message)}</div></span></label>
    <label class="chk"><input type="checkbox" id="uh" ${c.use_hash_feed?'checked':''}>
      <span>Use known-bad hash feed<div class="d">${S.feed.available?
        S.feed.count.toLocaleString()+' hashes cached'+(S.feed.age_days!=null?
        ', '+S.feed.age_days.toFixed(1)+' days old':''):'no feed cached yet'}</div></span></label>
    <label class="chk"><input type="checkbox" id="nt" ${c.notify_on_scheduled_scan?'checked':''}>
      <span>Show a Windows notification after each scheduled scan</span></label>
    <div class="row" style="margin-top:12px">
      <button class="primary" id="saveSet">Save</button>
      <button id="updFeed">Update hash feed now</button>
      <button id="updFeedFull">Download full feed (large)</button>
    </div>`;
  document.getElementById('saveSet').onclick=async()=>{
    await post('/api/config',{
      report_threshold:+document.getElementById('thr').value,
      max_file_mb:+document.getElementById('mx').value,
      use_yara:document.getElementById('uy').checked,
      use_hash_feed:document.getElementById('uh').checked,
      notify_on_scheduled_scan:document.getElementById('nt').checked});
    await loadState();toast('Settings saved');};
  document.getElementById('updFeed').onclick=async()=>{
    toast('Updating feed…');const r=await post('/api/feed/update',{});
    toast(r.message,!r.ok);await loadState();};
  document.getElementById('updFeedFull').onclick=async()=>{
    toast('Downloading full feed, this can take a minute…');
    const r=await post('/api/feed/update',{full:true});toast(r.message,!r.ok);await loadState();};

  document.getElementById('env').innerHTML=`
    <div class="fmeta">Data directory: <code>${esc(S.data_root)}</code></div>
    <div class="fmeta">Quarantine folder: <code>${esc(S.quarantine_dir)}</code></div>
    <div class="fmeta">YARA rules folder: <code>${esc(S.yara.rules_dir)}</code></div>
    <div class="fmeta" style="margin-top:9px">Auto-quarantine is
      <b>${S.config.auto_quarantine?'ON':'OFF'}</b> — quarantine only ever runs when
      you click it on a file you marked malicious or unknown.</div>`;
}

(async()=>{await loadState();await loadFindings();await browse('');
  if(S.progress&&S.progress.running)startPoll();})();
</script></body></html>
"""

REVIEW_PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentry review</title>
<style>
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--bd:#e3e6eb;--fg:#16181d;
--mut:#6b7280;--acc:#2563eb;--accbg:#eff6ff;--hov:#f1f3f6;
--safe:#16a34a;--safebg:#f0fdf4;--unk:#d97706;--unkbg:#fffbeb;--bad:#dc2626;--badbg:#fef2f2}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a20;--bd:#262b35;
--fg:#e6e8ec;--mut:#9aa3b2;--acc:#60a5fa;--accbg:#132033;--hov:#1d2129;
--safe:#4ade80;--safebg:#122417;--unk:#fbbf24;--unkbg:#251d0d;--bad:#f87171;--badbg:#2a1414}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 "Segoe UI",system-ui,sans-serif;min-height:100vh;
display:flex;flex-direction:column}
header{display:flex;align-items:center;gap:12px;padding:14px 22px;
border-bottom:1px solid var(--bd)}
header h1{font-size:17px;margin:0;font-weight:600}
header .count{color:var(--mut);font-size:13px}
header .right{margin-left:auto;display:flex;gap:10px;align-items:center}
header a{color:var(--acc);text-decoration:none;font-size:13px}
.hbtn{padding:5px 12px;border-radius:8px;border:1px solid var(--bd);
background:var(--card);color:var(--mut);font-size:12px;cursor:pointer}
.hbtn:hover{background:var(--hov)}
.hbtn.on{color:var(--safe);border-color:var(--safe)}
.hbtn.off{color:var(--unk);border-color:var(--unk)}
#scope{position:absolute;top:52px;right:18px;background:var(--card);
border:1px solid var(--bd);border-radius:10px;padding:14px 16px;
box-shadow:0 8px 30px rgba(0,0,0,.25);font-size:13px;z-index:5}
#scope label{display:flex;gap:8px;align-items:center;margin:6px 0;cursor:pointer}
#scope .hint{color:var(--mut);font-size:11px;max-width:230px}
#scope .apply{margin-top:10px;width:100%;padding:7px;border-radius:8px;
border:1px solid var(--acc);background:var(--accbg);color:var(--acc);
font-weight:600;cursor:pointer}
main{flex:1;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;
padding:30px 34px;max-width:640px;width:100%;box-shadow:0 4px 24px rgba(0,0,0,.06)}
.sev{display:inline-block;font-size:12px;font-weight:600;padding:2px 10px;
border-radius:999px;margin-bottom:14px}
.sev.high{background:var(--badbg);color:var(--bad)}
.sev.medium{background:var(--unkbg);color:var(--unk)}
.sev.low,.sev.info{background:var(--accbg);color:var(--acc)}
h2{margin:0 0 2px;font-size:22px;word-break:break-all}
.dir{color:var(--mut);font-size:13px;word-break:break-all}
.meta{color:var(--mut);font-size:13px;margin:8px 0 14px}
ul.reasons{margin:0 0 22px;padding-left:20px}
ul.reasons li{margin:3px 0}
.verdicts{display:flex;gap:12px;margin-bottom:14px}
.verdicts button{flex:1;padding:16px 10px;border-radius:12px;border:2px solid;
font-size:16px;font-weight:600;cursor:pointer;background:transparent}
.verdicts .safe{border-color:var(--safe);color:var(--safe);background:var(--safebg)}
.verdicts .unk{border-color:var(--unk);color:var(--unk);background:var(--unkbg)}
.verdicts button:hover{filter:brightness(1.08)}
.verdicts small{display:block;font-weight:400;font-size:12px;opacity:.75}
.minor{display:flex;gap:10px;justify-content:center}
.minor button{padding:7px 14px;border-radius:8px;border:1px solid var(--bd);
background:var(--card);color:var(--mut);font-size:13px;cursor:pointer}
.minor button.bad{color:var(--bad);border-color:var(--bad)}
.minor button:hover{background:var(--hov)}
footer{padding:10px 22px 16px;color:var(--mut);font-size:12px;text-align:center}
.done{text-align:center}
.done .big{font-size:44px;margin-bottom:8px}
.done a{color:var(--acc)}
#toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);
background:#16181d;color:#fff;padding:9px 18px;border-radius:8px;font-size:13px;
opacity:0;transition:opacity .25s;pointer-events:none;max-width:80vw}
#toast.show{opacity:1}#toast.err{background:#991b1b}
kbd{background:var(--hov);border:1px solid var(--bd);border-radius:4px;
padding:0 5px;font-size:11px}
</style></head><body>
<header><h1>Sentry</h1><span class="count" id="count"></span>
<span class="right">
<button id="schedbtn" class="hbtn" hidden onclick="schedToggle()"></button>
<button class="hbtn" onclick="scopeToggle()">Scan scope</button>
<a href="/">Full dashboard &rarr;</a></span></header>
<div id="scope" hidden></div>
<main id="main"></main>
<footer><kbd>S</kbd> safe &nbsp; <kbd>D</kbd> don&#39;t recognize &nbsp;
<kbd>M</kbd> malicious &nbsp; <kbd>O</kbd> open folder &nbsp;
<kbd>&larr;</kbd><kbd>&rarr;</kbd> skip</footer>
<div id="toast"></div>
<script>
const H={'Content-Type':'application/json','X-Sentry-Local':'1'};
let Q=[],i=0,reviewed=0;
function toast(m,err){const t=document.getElementById('toast');t.textContent=m;
  t.className=err?'show err':'show';setTimeout(()=>t.className='',3000)}
function esc(s){const d=document.createElement('div');d.textContent=s??'';return d.innerHTML}
function fmtSize(b){if(b==null)return'';if(b>1048576)return(b/1048576).toFixed(1)+' MB';
  if(b>1024)return(b/1024).toFixed(1)+' KB';return b+' B'}
function counts(){const c=document.getElementById('count');
  c.textContent=Q.length?`${Q.length} to review`+(reviewed?` \u00b7 ${reviewed} done`:''):''}
function render(){
  counts();
  const m=document.getElementById('main');
  if(!Q.length){
    m.innerHTML=`<div class="card done"><div class="big">\u2714</div>
      <h2 style="word-break:normal">All reviewed</h2>
      <p class="meta">${reviewed?`You reviewed ${reviewed} file(s) this session.`:
      'Nothing is waiting for review.'}</p>
      <p><a href="/">Open the full dashboard</a></p></div>`;
    return;
  }
  if(i>=Q.length)i=0; if(i<0)i=Q.length-1;
  const f=Q[i];
  const dir=f.path.replace(/[\\/][^\\/]*$/,'');
  const name=f.path.split(/[\\/]/).pop();
  m.innerHTML=`<div class="card">
    <span class="sev ${esc(f.severity)}">${esc(f.severity)} \u00b7 ${f.score}</span>
    <h2>${esc(name)}</h2>
    <div class="dir">${esc(dir)}</div>
    <div class="meta">${fmtSize(f.size)}${f.last_seen?' \u00b7 seen '+esc(String(f.last_seen).slice(0,10)):''}
      \u00b7 ${i+1} of ${Q.length}</div>
    <ul class="reasons">${(f.reasons||[]).map(r=>`<li>${esc(r)}</li>`).join('')}</ul>
    <div class="verdicts">
      <button class="safe" onclick="mark('safe')">\u2713 I know this
        <small>mark Safe &mdash; skipped in future scans</small></button>
      <button class="unk" onclick="mark('unknown')">? Don&#39;t recognize
        <small>mark Unknown &mdash; can be quarantined</small></button>
    </div>
    <div class="minor">
      <button class="bad" onclick="mark('malicious')">Malicious</button>
      <button onclick="openFolder()">Open folder</button>
      <button onclick="skip(1)">Skip &rarr;</button>
    </div></div>`;
}
async function load(){
  try{
    const rows=await fetch('/api/findings').then(r=>r.json());
    Q=rows.filter(f=>!f.verdict&&!f.quarantine_path&&!f.quarantined_at)
          .sort((a,b)=>b.score-a.score);
  }catch(e){toast('Could not reach the Sentry engine: '+e.message,1)}
  render();
}
async function mark(verdict){
  if(!Q.length)return;
  const f=Q[i];
  try{
    const r=await fetch('/api/verdict',{method:'POST',headers:H,
      body:JSON.stringify({sha256:f.sha256,verdict,path:f.path})});
    const j=await r.json();
    if(!r.ok)throw new Error(j.error||r.status);
  }catch(e){toast(e.message,1);return}
  const dropped=Q.filter(x=>x.sha256===f.sha256).length;
  Q=Q.filter(x=>x.sha256!==f.sha256);
  reviewed+=dropped;
  if(verdict==='malicious')toast('Marked malicious \u2014 quarantine it from the dashboard');
  else if(dropped>1)toast(`Marked ${verdict} \u2014 covered ${dropped} identical files`);
  render();
}
async function openFolder(){
  if(!Q.length)return;
  try{
    const r=await fetch('/api/open-folder',{method:'POST',headers:H,
      body:JSON.stringify({path:Q[i].path})});
    const j=await r.json();
    if(!r.ok)throw new Error(j.error||r.status);
  }catch(e){toast(e.message,1)}
}
function skip(d){if(Q.length){i+=d;render()}}
let SCHED=null,SCOPE_KEEP=[];
async function schedLoad(){
  try{
    SCHED=await fetch('/api/schedule').then(r=>r.json());
    const b=document.getElementById('schedbtn');
    if(!SCHED.installed){b.hidden=true;return}
    b.hidden=false;
    b.textContent=SCHED.paused?'▶ Weekly scan: paused':'⏸ Weekly scan: on';
    b.className='hbtn '+(SCHED.paused?'off':'on');
    b.title=SCHED.paused?'Click to resume the weekly scheduled scan'
      :'Runs '+(SCHED.next_run||'weekly')+' — click to pause';
  }catch(e){}
}
async function schedToggle(){
  if(!SCHED)return;
  const action=SCHED.paused?'resume':'pause';
  try{
    const r=await fetch('/api/schedule',{method:'POST',headers:H,
      body:JSON.stringify({action})});
    const j=await r.json();
    if(!r.ok)throw new Error(j.error||r.status);
    toast(action==='pause'?'Weekly scan paused':'Weekly scan resumed');
  }catch(e){toast(e.message,1)}
  schedLoad();
}
async function scopeToggle(){
  const el=document.getElementById('scope');
  if(!el.hidden){el.hidden=true;return}
  try{
    const [state,roots]=await Promise.all([
      fetch('/api/state').then(r=>r.json()),
      fetch('/api/browse').then(r=>r.json())]);
    const customs=state.config.custom_paths||[];
    const isRoot=p=>/^[a-z]:\\?$/i.test(p);
    SCOPE_KEEP=customs.filter(p=>!isRoot(p));  // folders picked in the dashboard
    const chosen=customs.filter(isRoot).map(p=>p.toLowerCase().replace(/\\?$/,'\\'));
    const drives=(roots.dirs||[]).map(d=>d.path).filter(p=>isRoot(p));
    const presetsOn=(state.config.enabled_presets||[]).length>0;
    el.innerHTML='<b>What gets scanned</b>'+
      `<label><input type="checkbox" id="sc_presets" ${presetsOn?'checked':''}>
        My folders <span class="hint">Downloads, Desktop, Documents, Temp
        and startup locations</span></label>`+
      drives.map(d=>`<label><input type="checkbox" class="sc_drive" value="${d}"
        ${chosen.includes(d.toLowerCase())?'checked':''}> Whole drive ${d}</label>`).join('')+
      (SCOPE_KEEP.length?`<div class="hint">+ ${SCOPE_KEEP.length} custom folder(s)
        kept (manage them in the dashboard)</div>`:'')+
      '<button class="apply" onclick="scopeApply()">Apply</button>';
    el.hidden=false;
  }catch(e){toast(e.message,1)}
}
async function scopeApply(){
  const presets=document.getElementById('sc_presets').checked
    ?['high_risk','persistence']:[];
  const drives=[...document.querySelectorAll('.sc_drive')]
    .filter(c=>c.checked).map(c=>c.value);
  if(!presets.length&&!drives.length&&!SCOPE_KEEP.length){
    toast('Pick at least one thing to scan',1);return}
  try{
    const r=await fetch('/api/config',{method:'POST',headers:H,
      body:JSON.stringify({enabled_presets:presets,
                           custom_paths:SCOPE_KEEP.concat(drives)})});
    const j=await r.json();
    if(!r.ok)throw new Error(j.error||r.status);
    toast(`Scope saved — ${j.resolved_paths.length} location(s) will be scanned`);
    document.getElementById('scope').hidden=true;
  }catch(e){toast(e.message,1)}
}
let lastMark=0;
document.addEventListener('keydown',e=>{
  if(e.target.tagName==='INPUT')return;
  // A held-down key auto-repeats ~30x/s — without these guards one long
  // press of S mass-marks the whole queue as safe.
  if(e.repeat)return;
  const k=e.key.toLowerCase();
  if(k==='s'||k==='d'||k==='m'){
    const now=Date.now();
    if(now-lastMark<400)return;
    lastMark=now;
    mark(k==='s'?'safe':k==='d'?'unknown':'malicious');
  }
  else if(k==='o')openFolder();
  else if(e.key==='ArrowRight')skip(1);else if(e.key==='ArrowLeft')skip(-1);
});
load();
schedLoad();
</script></body></html>
"""
