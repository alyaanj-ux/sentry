# Sentry — local heuristic file scanner for Windows

This file is the project brief for Claude (and anyone else) landing in this
repo. Read this first; deeper history lives in `docs/`.

## What it is

A privacy-first, fully local malware *triage* tool for Windows. It scans
user-chosen locations on a weekly schedule, scores files with explainable
heuristics (no cloud, no telemetry), and **never acts on its own**: every
flagged file waits for a human verdict — Safe / Unknown / Malicious — and only
then can it be quarantined, restored, or purged.

Python 3.14, Flask (loopback-only), SQLite, pefile, optional YARA, pywebview
for the desktop app. No services, no admin rights, single user-level install.

## Layout

- `sentry/` — the package: `engine.py` (scan loop), `heuristics.py` (scoring),
  `quarantine.py` (move/harden/restore/purge), `webui.py` (dashboard + review
  app pages + JSON API), `app.py` (native window), `notify.py` (toasts),
  `behavior.py` (autostart/registry sweeps), `config.py`, `store.py`.
- `tests/` — 548 tests (`python tests\run_tests.py`), plus standalone suites:
  `selftest.py` (end-to-end on disposable decoys), `test_windows_paths.py`
  (Windows path/ACL/toast semantics), `test_detection_quality.py` (detection
  vs. false-positive gates).
- `scripts/` — installers (`install_schedule.ps1`, `install_app_shortcut.ps1`),
  icon generator, launchers. `Sentry.bat` is the menu entry point.
- `docs/` — `FINDINGS.md` (the 50-bug review that produced this build),
  `WINDOWS_REPORT.md` (on-hardware verification).
- Data root: `%LOCALAPPDATA%\Sentry` (SQLite DB, quarantine, HTML reports).

## Commands

`python -m sentry app|serve|scan|weekly|status|scope|update-feed|quarantine|install-schedule`

## Engineering highlights (true, verified claims — usable on a resume)

- **Heuristic detection engine** for PE executables, scripts, and Office
  macros: ~40 scored rules (packer/entropy/import analysis, API-combination
  rules, filename and content-type deception, autostart and registry
  persistence) with every score explainable in one sentence to a non-expert.
- **Measured false-positive engineering**: rules were tuned against a corpus
  of ~59,000 benign files plus real Windows PE/.NET binaries, taking the
  false-positive rate on clean Windows DLLs from 27.7% to 0% while raising
  true-positive detection to 25/25 structural decoys; verified end-to-end on
  real Windows hardware.
- **Safe quarantine on NTFS**: deny-execute ACE + attribute hardening with an
  exact-restore path (original location, permissions, and bytes verified by
  SHA-256), including cross-volume moves; re-hashes before acting so a swapped
  file can never be quarantined in place of the reviewed one.
- **Windows-correctness work**: `\\?\` long-path support beyond MAX_PATH,
  OneDrive placeholder detection that prevents accidental gigabyte hydration,
  both 32/64-bit registry views for autostart enumeration, locale-independent
  SIDs, GetLogicalDrives-based enumeration.
- **Security hardening of the local dashboard**: fixed a cmd.exe command
  injection (shell-free CreateProcess), CSRF guard header on all mutating
  routes, loopback-only binding, strict input validation (including the
  `isinstance(True, int)` JSON pitfall).
- **Desktop review app**: a native WebView2 window with a one-file-at-a-time
  triage queue (keyboard-driven verdicts by content hash), weekly-schedule
  pause/resume and scan-scope control in-app; toast notifications deep-link
  into the app via a custom URL protocol.
- **548 automated tests** across unit, integration, and platform-simulation
  suites; scheduled weekly scans via Task Scheduler with truthful
  missed-run/logon semantics documented.

## Conventions for future work

- Never let the tool delete or move a file without an explicit human verdict
  first; keep that invariant test-enforced.
- All mutating HTTP routes must sit behind the `X-Sentry-Local` guard header
  (`tests/test_webui.py` enumerates routes automatically — a new unguarded
  route fails the suite).
- Windows behaviors (paths, ACLs, toasts) get simulation tests in
  `tests/test_windows_paths.py` even when developed on Windows.
- Run `python tests\run_tests.py` before calling anything done.
