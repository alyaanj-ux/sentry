"""Command-line entry point.

  python -m sentry app                   open the desktop review app
  python -m sentry serve                 start the dashboard (default)
  python -m sentry scan [PATH ...]       one-off scan, prints a summary
  python -m sentry weekly                headless scan + HTML report + notification
  python -m sentry status                current counts and configuration
  python -m sentry update-feed [--full]  refresh the known-bad hash cache
  python -m sentry install-schedule      register the weekly Windows task
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from pathlib import Path

from . import behavior, config, engine, feeds, report, store


def cmd_app(args) -> int:
    from . import app as desktop
    return desktop.main(page="" if args.dashboard else "review")


def cmd_serve(args) -> int:
    from . import webui
    webui.serve(port=args.port, open_browser=not args.no_browser)
    return 0


def _print_summary(result: dict, findings: list[dict]) -> None:
    s = result.get("summary", {})
    print(f"\n  Files checked : {s.get('files_scanned', 0):,}")
    print(f"  Flagged       : {s.get('findings', 0)}")
    print(f"  Read errors   : {s.get('errors', 0)}")
    for n in s.get("notes", []):
        print(f"  · {n}")
    if findings:
        print("\n  Top findings:")
        for f in findings[:15]:
            print(f"    [{f['severity']:<6} {f['score']:>3}] {f['path']}")
            for r in f["reasons"][:3]:
                print(f"        - {r}")
    print()


def cmd_scan(args) -> int:
    store.init_db()
    paths = [os.path.abspath(p) for p in args.paths] or None
    if args.threshold:
        config.save_config({"report_threshold": args.threshold})
    result = engine.run_scan(paths, trigger="manual")
    if "error" in result and "scan_id" not in result:
        print(f"  {result['error']}", file=sys.stderr)
        return 1
    findings = store.get_findings(scan_id=result["scan_id"])
    _print_summary(result, findings)
    return 0


def cmd_weekly(args) -> int:
    """Headless run intended for Task Scheduler."""
    from . import notify
    store.init_db()
    cfg = config.load_config()
    paths = config.resolved_scan_paths(cfg)
    result = engine.run_scan(paths, trigger="scheduled", cfg=cfg)

    if "scan_id" not in result:
        msg = result.get("error", "Scan failed to start.")
        print(f"  {msg}", file=sys.stderr)
        if cfg.get("notify_on_scheduled_scan", True):
            notify.notify("Sentry weekly scan failed", msg)
        return 1

    scan_id = result["scan_id"]
    findings = store.get_findings(scan_id=scan_id)
    indicators = []
    try:
        indicators = behavior.sweep(paths, cfg)
    except Exception as exc:  # noqa: BLE001
        print(f"  indicator sweep failed: {exc}", file=sys.stderr)

    # Our own row, by id. This used to be store.last_scan(): observed on
    # Windows with the dashboard open, a 4-file manual scan that started and
    # finished during the weekly run became "last", and the weekly report and
    # scan row were written with "4 files checked" for an 83,000-file scan.
    summary = result.get("summary", {})
    scan = store.get_scan(scan_id) or {}
    notes = summary.get("notes", [])
    out = report.build_report(scan_id, findings, scan, notes=notes,
                              indicators=indicators)
    store.finish_scan(scan_id,
                      files=summary.get("files_scanned", scan.get("files_scanned", 0)),
                      nbytes=summary.get("bytes_scanned", scan.get("bytes_scanned", 0)),
                      findings=len(findings),
                      errors=summary.get("errors", scan.get("errors", 0)),
                      report_path=str(out))
    scan = store.get_scan(scan_id) or scan

    high = sum(1 for f in findings if f["severity"] == "high")
    high += sum(1 for i in indicators if i.get("severity") == "high")
    unreviewed = sum(1 for f in findings if not f.get("verdict"))

    print(f"  Report written: {out}")
    _print_summary(result, findings)

    if cfg.get("notify_on_scheduled_scan", True):
        if high:
            title = f"Sentry: {high} high-severity item(s) need review"
        elif unreviewed:
            title = f"Sentry: {unreviewed} item(s) flagged for review"
        else:
            title = "Sentry weekly scan: nothing flagged"
        notify.notify(title,
                      f"{scan.get('files_scanned', 0):,} files checked. "
                      f"Open the report or run 'python -m sentry serve' to act on it.",
                      str(out))

    if args.open_report and (high or unreviewed):
        webbrowser.open(out.as_uri())
    return 0


def cmd_status(args) -> int:
    store.init_db()
    cfg = config.load_config()
    print(json.dumps({
        "data_root": str(config.DATA_ROOT),
        "counts": store.counts(),
        "scan_paths": config.resolved_scan_paths(cfg),
        "last_scan": store.last_scan(),
        "feed": feeds.feed_status(),
        "yara": feeds.yara_status(),
        "config": cfg,
    }, indent=2, default=str))
    return 0


def cmd_update_feed(args) -> int:
    ok, msg = feeds.update_hash_feed(full=args.full)
    print(f"  {msg}")
    return 0 if ok else 1


def cmd_install_schedule(args) -> int:
    if not config.IS_WINDOWS:
        print("  install-schedule is Windows-only. On Linux use a systemd timer "
              "or cron entry calling: python -m sentry weekly", file=sys.stderr)
        return 1
    script = (Path(__file__).resolve().parent.parent
              / "scripts" / "install_schedule.ps1")
    if not script.exists():
        print(f"  Missing {script}", file=sys.stderr)
        return 1
    import re
    import shutil
    import subprocess

    day = (args.day or "SUN").upper()
    if day not in {"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}:
        print(f"  --day must be one of SUN..SAT (got {args.day!r})", file=sys.stderr)
        return 2
    if not re.fullmatch(r"([01]?\d|2[0-3]):[0-5]\d", args.time or ""):
        print(f"  --time must be HH:MM 24-hour (got {args.time!r})", file=sys.stderr)
        return 2

    # 'powershell' is not always on PATH for a stripped or service environment,
    # and PATH lookup is the difference between this working and a FileNotFound.
    ps = shutil.which("powershell") or os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    if not os.path.exists(ps):
        print("  Could not locate powershell.exe.", file=sys.stderr)
        return 1

    print(f"  Running {script} …")
    r = subprocess.run(
        [ps, "-NoProfile", "-ExecutionPolicy", "Bypass",
         "-File", str(script), "-Day", day, "-Time", args.time],
        check=False)
    return r.returncode


def _print_scope() -> None:
    cfg = config.load_config()
    presets = config.preset_paths()
    enabled = cfg.get("enabled_presets", [])
    custom = cfg.get("custom_paths", [])
    resolved = config.resolved_scan_paths(cfg)

    print("\n  Presets:")
    for name in presets:
        mark = "x" if name in enabled else " "
        print(f"    [{mark}] {name:<14} {config.PRESET_LABELS.get(name, '')}")
    print("\n  Custom folders:")
    for p in custom or ["(none)"]:
        print(f"    - {p}")
    print("\n  Effective scan list:")
    for p in resolved or ["(nothing — a scan would do nothing)"]:
        print(f"    - {p}")
    print("\n  Exclusions:")
    for p in cfg.get("exclusions", []) or ["(none)"]:
        print(f"    - {p}")
    print()


def cmd_scope(args) -> int:
    """Show or change what gets scanned, without hand-editing config.json."""
    cfg = config.load_config()

    if args.reset:
        config.save_config({
            "enabled_presets": list(config.DEFAULTS["enabled_presets"]),
            "custom_paths": [],
        })
        print("  Scan scope reset to defaults.")
        _print_scope()
        return 0

    changed = False

    if args.only is not None:
        targets = []
        for raw in args.only:
            p = os.path.abspath(os.path.expandvars(os.path.expanduser(raw)))
            if not os.path.isdir(p):
                print(f"  Not a directory: {p}", file=sys.stderr)
                return 1
            targets.append(p)
        config.save_config({"enabled_presets": [], "custom_paths": targets})
        print(f"  Scope replaced: presets off, {len(targets)} folder(s) only.")
        changed = True
    else:
        if args.presets is not None:
            valid = set(config.preset_paths())
            names = [] if args.presets == ["none"] else args.presets
            bad = [n for n in names if n not in valid]
            if bad:
                print(f"  Unknown preset(s): {', '.join(bad)}\n"
                      f"  Valid: {', '.join(sorted(valid))}, or 'none'",
                      file=sys.stderr)
                return 1
            config.save_config({"enabled_presets": names})
            changed = True

        custom = list(cfg.get("custom_paths", []))
        for raw in args.add or []:
            p = os.path.abspath(os.path.expandvars(os.path.expanduser(raw)))
            if not os.path.isdir(p):
                print(f"  Not a directory: {p}", file=sys.stderr)
                return 1
            if p not in custom:
                custom.append(p)
                changed = True
        for raw in args.remove or []:
            p = os.path.abspath(os.path.expandvars(os.path.expanduser(raw)))
            before = len(custom)
            custom = [c for c in custom
                      if os.path.normcase(os.path.normpath(c))
                      != os.path.normcase(os.path.normpath(p))]
            if len(custom) != before:
                changed = True
        if changed:
            config.save_config({"custom_paths": custom})

    if changed:
        print("  Saved.")
    _print_scope()
    if changed and not config.resolved_scan_paths():
        print("  WARNING: nothing is in scope — a scan would check zero files.\n",
              file=sys.stderr)
        return 1
    return 0


def cmd_quarantine_list(args) -> int:
    store.init_db()
    rows = store.quarantine_list(active_only=False)
    if not rows:
        print("  Quarantine is empty.")
        return 0
    for e in rows:
        state = ("restored" if e["restored_at"] else
                 "deleted" if e["deleted_at"] else "held")
        print(f"  [{e['id']:>3}] {state:<8} {e['original_path']}")
        print(f"        now at: {e['quarantine_path']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sentry",
                                description="Local heuristic file scanner.")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("app", help="open the desktop review app (native window)")
    s.add_argument("--dashboard", action="store_true",
                   help="open on the full dashboard instead of the review queue")
    s.set_defaults(func=cmd_app)

    s = sub.add_parser("serve", help="start the local dashboard")
    s.add_argument("--port", type=int, default=None)
    s.add_argument("--no-browser", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("scan", help="run a scan now")
    s.add_argument("paths", nargs="*", help="paths to scan (default: configured scope)")
    s.add_argument("--threshold", type=int, default=None)
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("weekly", help="headless scan + HTML report + notification")
    s.add_argument("--open-report", action="store_true",
                   help="open the report in a browser if anything needs review")
    s.set_defaults(func=cmd_weekly)

    s = sub.add_parser("status", help="print current state as JSON")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("update-feed", help="refresh the known-bad hash cache")
    s.add_argument("--full", action="store_true", help="download the full dump")
    s.set_defaults(func=cmd_update_feed)

    s = sub.add_parser("install-schedule", help="register the weekly Windows task")
    s.add_argument("--day", default="SUN", help="SUN..SAT (default SUN)")
    s.add_argument("--time", default="12:00", help="HH:MM 24h (default 12:00)")
    s.set_defaults(func=cmd_install_schedule)

    s = sub.add_parser("scope", help="show or change what gets scanned")
    s.add_argument("--only", nargs="+", metavar="PATH",
                   help="scan ONLY these folders: turns every preset off and "
                        r'replaces the custom list (e.g. --only D:\)')
    s.add_argument("--presets", nargs="+", metavar="NAME",
                   help="set enabled presets, or 'none' to disable all")
    s.add_argument("--add", nargs="+", metavar="PATH", help="add folder(s)")
    s.add_argument("--remove", nargs="+", metavar="PATH", help="remove folder(s)")
    s.add_argument("--reset", action="store_true", help="restore default scope")
    s.set_defaults(func=cmd_scope)

    s = sub.add_parser("quarantine", help="list quarantine entries")
    s.set_defaults(func=cmd_quarantine_list)

    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        args = p.parse_args(["serve"])
    config.ensure_dirs()
    store.init_db()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
