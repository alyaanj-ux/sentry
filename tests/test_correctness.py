"""Regression tests for correctness bugs found during the audit.

Each test corresponds to one fixed bug and fails on the unfixed code.

Run:  python3 test_correctness.py      (exit 0 = all passed)
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import traceback
from pathlib import Path

# This file lives in tests/, so the importable project root is two up.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Windows consoles and pipes default to a legacy code page (cp1252) that cannot
# encode the box-drawing characters printed below, and Python then aborts the
# whole run with UnicodeEncodeError before a single check has executed.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from sentry import config, engine, feeds, quarantine, store  # noqa: E402

PASS, FAIL = "  \033[32mPASS\033[0m", "  \033[31mFAIL\033[0m"
_results: list[tuple[bool, str]] = []
_TMPS: list[Path] = []

# Same structural PE stub the selftest uses. Harmless: it only has an MZ/PE
# header so the "PE content behind a document extension" heuristic fires.
PE_STUB = (
    b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    b"\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00"
    + b"\x00" * 32
    + b"\x80\x00\x00\x00"
    + b"\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!"
      b"This program cannot be run in DOS mode.\r\r\n$"
    + b"\x00" * 8
    + b"PE\x00\x00"
    + b"\x00" * 240
)


def check(cond: bool, label: str) -> bool:
    _results.append((bool(cond), label))
    print(f"{PASS if cond else FAIL}  {label}")
    return bool(cond)


def fresh() -> tuple[Path, Path]:
    """Point all Sentry state at a throwaway dir; return (root, sandbox)."""
    root = Path(tempfile.mkdtemp(prefix="sentry_regress_"))
    _TMPS.append(root)
    config.DATA_ROOT = root / "data"
    config.DB_PATH = config.DATA_ROOT / "sentry.db"
    config.QUARANTINE_DIR = config.DATA_ROOT / "quarantine"
    config.REPORTS_DIR = config.DATA_ROOT / "reports"
    config.RULES_DIR = config.DATA_ROOT / "rules"
    config.FEED_DIR = config.DATA_ROOT / "feeds"
    config.CONFIG_PATH = config.DATA_ROOT / "config.json"
    feeds.HASH_DB = config.FEED_DIR / "known_bad.csv"
    feeds.USER_HASH_DB = config.FEED_DIR / "custom_bad_hashes.txt"
    config.ensure_dirs()
    store.init_db()
    sandbox = root / "scan"
    sandbox.mkdir()
    return root, sandbox


def cfg() -> dict:
    c = dict(config.DEFAULTS)
    c["use_hash_feed"] = False      # offline + deterministic
    c["use_yara"] = False
    c["exclusions"] = []
    c["report_threshold"] = 25
    return c


def flaggable(path: Path, filler: int = 9000) -> None:
    """A file that scores well above threshold but is completely inert."""
    path.write_bytes(PE_STUB + b"\x00" * filler)


def flag_one(sandbox: Path, name: str = "invoice.pdf.exe") -> dict:
    """Create one flaggable file, scan, and return its finding."""
    flaggable(sandbox / name)
    res = engine.run_scan([str(sandbox)], trigger="manual", cfg=cfg())
    findings = store.get_findings(scan_id=res["scan_id"])
    return findings[0]


# ---------------------------------------------------------------- bug 1

def test_unstorable_finding_does_not_abort_scan() -> None:
    """A file whose name is not valid UTF-8 must not kill the whole scan."""
    _, sandbox = fresh()
    for i in range(5):
        flaggable(sandbox / f"good{i}.txt")
    if config.IS_WINDOWS:
        # NTFS names are UTF-16 and may contain an unpaired surrogate, which
        # Python surfaces as a str that cannot be UTF-8 encoded -- the exact
        # shape that made sqlite raise. A raw 0xFF byte is not representable
        # as a Windows filename at all (ntpath refuses to decode it).
        hostile = os.path.join(str(sandbox), "evil\udcff.txt")
    else:
        hostile = os.path.join(os.fsencode(str(sandbox)), b"evil\xff.txt")
    with open(hostile, "wb") as fh:
        fh.write(PE_STUB + b"\x00" * 9000)

    try:
        res = engine.run_scan([str(sandbox)], trigger="manual", cfg=cfg())
    except Exception as exc:  # noqa: BLE001
        check(False, f"scan survives an unstorable path (raised {exc!r})")
        return
    check("scan_id" in res, "scan survives a file with an unencodable name")
    check(len(store.get_findings(scan_id=res["scan_id"])) == 5,
          "findings discovered after the bad file are still recorded")
    check(res["summary"]["errors"] >= 1, "the unstorable finding is counted as an error")
    last = store.last_scan()
    check(last is not None and last["finished_at"],
          "the scan row is finished rather than left dangling")


# ---------------------------------------------------------------- bug 2

def test_quarantine_verifies_hash() -> None:
    """A file replaced after scoring must not be quarantined under the old hash."""
    root, sandbox = fresh()
    f = flag_one(sandbox, "meeting_notes.txt")
    store.set_verdict(f["sha256"], "malicious", path=f["path"])

    target = Path(f["path"])
    target.write_bytes(b"AN UNRELATED, UNREVIEWED FILE\n" * 50)
    try:
        quarantine.quarantine_finding(f["id"])
        check(False, "quarantine refuses a file that changed since the scan")
    except quarantine.QuarantineError as exc:
        check("changed since it was scanned" in str(exc),
              "quarantine refuses a file that changed since the scan")
    check(target.exists() and b"UNRELATED" in target.read_bytes(),
          "the replacement file is left untouched on disk")
    check(store.quarantine_list(active_only=False) == [],
          "no quarantine manifest row is written for the refused move")

    # Positive control: the unchanged file still quarantines fine.
    root2, sandbox2 = fresh()
    g = flag_one(sandbox2, "dropper.pdf.exe")
    store.set_verdict(g["sha256"], "malicious", path=g["path"])
    r = quarantine.quarantine_finding(g["id"])
    moved = Path(r["quarantine_path"])
    check(moved.exists() and not Path(g["path"]).exists(),
          "an unmodified file still quarantines normally")
    check(hashlib.sha256(moved.read_bytes()).hexdigest() == g["sha256"],
          "quarantined bytes match the reviewed SHA-256")


# ---------------------------------------------------------------- bug 3

def test_quarantine_refuses_symlink() -> None:
    """Quarantining a symlink would move the link, harden its target and then
    'permanently delete' nothing at all."""
    root, sandbox = fresh()
    real = root / "keepme.dat"
    flaggable(real)
    os.chmod(real, 0o644)
    link = sandbox / "invoice.pdf.exe"
    try:
        os.symlink(str(real), str(link))
    except OSError as exc:
        # Windows: creating a symlink needs SeCreateSymbolicLinkPrivilege
        # (Developer Mode or an elevated shell). Without it the refusal path
        # cannot be exercised here; say so rather than reporting a failure
        # that has nothing to do with the code under test.
        if getattr(exc, "winerror", None) == 1314:
            print("  SKIP  symlinks cannot be created in this session "
                  "(WinError 1314: privilege not held) -- run elevated or "
                  "with Developer Mode on to exercise this test")
            return
        raise

    f = store.get_findings(
        scan_id=engine.run_scan([str(sandbox)], trigger="manual",
                                cfg=cfg())["scan_id"])[0]
    store.set_verdict(f["sha256"], "malicious")
    try:
        quarantine.quarantine_finding(f["id"])
        check(False, "quarantine refuses a symbolic link")
    except quarantine.QuarantineError as exc:
        check("symbolic link" in str(exc), "quarantine refuses a symbolic link")
    check(stat.S_IMODE(os.stat(real).st_mode) == 0o644,
          "the link target keeps its original permissions")
    check(real.exists(), "the link target is left in place")
    check(link.is_symlink(), "the link itself is left in place")


# ---------------------------------------------------------------- bug 4

def test_sibling_of_data_root_is_scanned() -> None:
    """Only the data root itself is skipped, not paths that merely share a prefix."""
    root, _ = fresh()
    sibling = root / "data_backup"     # sibling of config.DATA_ROOT ("<root>/data")
    sibling.mkdir()
    flaggable(sibling / "invoice.pdf.exe")
    res = engine.run_scan([str(sibling)], trigger="manual", cfg=cfg())
    check(res["summary"]["files_scanned"] == 1,
          "a directory whose name merely starts with the data root is scanned")
    check(res["summary"]["findings"] == 1,
          "the finding in that directory is reported")

    # ...and the data root itself is still skipped.
    flaggable(config.QUARANTINE_DIR / "held.pdf.exe")
    res2 = engine.run_scan([str(config.DATA_ROOT)], trigger="manual", cfg=cfg())
    check(res2["summary"]["files_scanned"] == 0,
          "the data root itself is still pruned from scans")


# ---------------------------------------------------------------- bug 5

def test_background_scan_start_is_truthful_and_cancellable() -> None:
    """scan_in_background must reserve the slot and publish PROGRESS before it
    returns, so 'started' is true and a cancel cannot land on a stale object."""
    _, sandbox = fresh()
    for i in range(40):
        flaggable(sandbox / f"f{i}.txt")

    c = cfg()
    real_load = config.load_config

    def slow_load():                 # stand-in for real start-up work
        time.sleep(0.6)
        return c

    config.load_config = slow_load
    try:
        first = engine.scan_in_background([str(sandbox)], trigger="manual")
        time.sleep(0.05)
        second = engine.scan_in_background([str(sandbox)], trigger="manual")
        check(first is True, "the first background scan starts")
        check(second is False,
              "a second request during start-up is refused instead of faking success")
        deadline = time.time() + 30
        while (engine.PROGRESS.running or engine._SCAN_LOCK.locked()) \
                and time.time() < deadline:
            time.sleep(0.05)

        # A cancel issued immediately after the start must be honoured.
        started = engine.scan_in_background([str(sandbox)], trigger="manual")
        engine.PROGRESS.cancel = True          # what POST /api/scan/cancel does
        deadline = time.time() + 30
        while (engine.PROGRESS.running or engine._SCAN_LOCK.locked()) \
                and time.time() < deadline:
            time.sleep(0.05)
        snap = engine.PROGRESS.snapshot()
        check(started is True, "a scan starts for the cancel test")
        check(any("cancel" in n.lower() for n in snap["notes"]),
              "a cancel sent right after start-up is honoured")
        check(snap["files_scanned"] < 40,
              "the cancelled scan stops early instead of running to completion")
    finally:
        config.load_config = real_load


# ---------------------------------------------------------------- bug 6

def test_config_endpoint_validates_numbers() -> None:
    """Bad numeric settings are rejected with 400, not persisted, and a poisoned
    value can never blind the scanner."""
    _, sandbox = fresh()
    from sentry import webui
    client = webui.app.test_client()
    H = {"X-Sentry-Local": "1", "Content-Type": "application/json",
         "Host": "127.0.0.1:8787"}

    r = client.post("/api/config", headers=H,
                    data=json.dumps({"report_threshold": "high"}))
    check(r.status_code == 400, "non-numeric report_threshold is a 400, not a 500")

    r = client.post("/api/config", headers=H,
                    data=json.dumps({"max_file_mb": "lots"}))
    check(r.status_code == 400, "non-numeric max_file_mb is rejected")
    check(config.load_config().get("max_file_mb") == config.DEFAULTS["max_file_mb"],
          "the bad value is not persisted to config.json")

    r = client.post("/api/config", headers=H,
                    data=json.dumps({"report_threshold": 40, "max_file_mb": 64}))
    check(r.status_code == 200 and config.load_config()["report_threshold"] == 40,
          "valid numeric settings are still accepted")

    # Defence in depth: even a hand-edited config must not stop detection.
    flaggable(sandbox / "invoice.pdf.exe")
    poisoned = cfg()
    poisoned["max_file_mb"] = "lots"
    res = engine.run_scan([str(sandbox)], trigger="manual", cfg=poisoned)
    check(res["summary"]["findings"] == 1,
          "a corrupted max_file_mb falls back to the default instead of finding nothing")


# ---------------------------------------------------------------- bug 7

def test_findings_not_duplicated_by_quarantine_history() -> None:
    """Several quarantine rows for one (sha256, path) must not duplicate the finding."""
    _, sandbox = fresh()
    f = flag_one(sandbox, "dropper.pdf.exe")
    payload = PE_STUB + b"\x00" * 9000
    store.set_verdict(f["sha256"], "malicious", path=f["path"])
    quarantine.quarantine_finding(f["id"])

    # The same file comes back (re-downloaded, or restored from a backup).
    Path(f["path"]).write_bytes(payload)
    res = engine.run_scan([str(sandbox)], trigger="manual", cfg=cfg())
    f2 = store.get_findings(scan_id=res["scan_id"])[0]
    check(f2["id"] == f["id"], "the returning file reuses its finding row")
    quarantine.quarantine_finding(f2["id"])

    check(len(store.quarantine_list(active_only=True)) == 2,
          "both quarantine events are recorded")
    rows = store.get_findings()
    check(len(rows) == 1, "get_findings() returns the finding exactly once")
    check(rows and rows[0]["quarantine_id"] is not None,
          "the finding is still reported as quarantined")


# ---------------------------------------------------------------- bug 8

def test_restore_reports_unusable_parent_cleanly() -> None:
    """Restore into a parent path that is no longer a directory must raise a
    QuarantineError (400 in the API), not an unhandled OSError (500)."""
    _, sandbox = fresh()
    sub = sandbox / "sub"
    sub.mkdir()
    f = flag_one(sub, "dropper.pdf.exe")
    # flag_one scanned only `sub`? it scanned `sub` as the root - fine.
    store.set_verdict(f["sha256"], "malicious")
    q = quarantine.quarantine_finding(f["id"])

    shutil.rmtree(sub)
    sub.write_text("something else lives here now")
    try:
        quarantine.restore(q["quarantine_id"])
        check(False, "restore refuses an original folder that is now a file")
    except quarantine.QuarantineError as exc:
        check("Cannot recreate the original folder" in str(exc),
              "restore refuses an original folder that is now a file")
    except Exception as exc:  # noqa: BLE001
        check(False, f"restore refuses cleanly (raised {type(exc).__name__})")

    entry = store.get_quarantine_entry(q["quarantine_id"])
    check(entry["restored_at"] is None,
          "the failed restore is not recorded as restored")
    check(Path(entry["quarantine_path"]).exists(),
          "the quarantined copy is still held after a failed restore")


TESTS = [
    test_unstorable_finding_does_not_abort_scan,
    test_quarantine_verifies_hash,
    test_quarantine_refuses_symlink,
    test_sibling_of_data_root_is_scanned,
    test_background_scan_start_is_truthful_and_cancellable,
    test_config_endpoint_validates_numbers,
    test_findings_not_duplicated_by_quarantine_history,
    test_restore_reports_unusable_parent_cleanly,
]


def main() -> int:
    for t in TESTS:
        print(f"\n── {t.__name__} "
              f"{'─' * max(2, 54 - len(t.__name__))}")
        try:
            t()
        except Exception:  # noqa: BLE001
            traceback.print_exc()
            check(False, f"{t.__name__} raised an unexpected exception")

    for p in _TMPS:
        shutil.rmtree(p, ignore_errors=True)

    passed = sum(1 for ok, _ in _results if ok)
    failed = len(_results) - passed
    print("\n" + "─" * 56)
    print(f"  {passed} passed, {failed} failed")
    if failed:
        for ok, label in _results:
            if not ok:
                print(f"  FAILED: {label}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
