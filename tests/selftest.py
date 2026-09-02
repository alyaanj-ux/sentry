"""Self-test: builds a sandbox of harmless decoy files, runs the full pipeline,
and verifies detection, verdict gating, quarantine, restore and delete.

No real malware is involved. The decoys only reproduce *structural* traits
(a double extension, a PE header behind a .txt name, obfuscation-shaped script
text) so the heuristics have something to fire on.

Run:  python tests\\selftest.py
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
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

from sentry import config, engine, quarantine, store  # noqa: E402

PASS, FAIL = "  \033[32mPASS\033[0m", "  \033[31mFAIL\033[0m"
_results: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> bool:
    _results.append((bool(cond), label))
    print(f"{PASS if cond else FAIL}  {label}")
    return bool(cond)


# A minimal but structurally valid-ish PE stub. Enough for an MZ/PE sniff.
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

OBFUSCATED_SCRIPT = (
    "# harmless decoy for scanner testing - does nothing\n"
    "# the strings below only *look* like a dropper\n"
    'if ($false) {\n'
    '  powershell -nop -w hidden -enc '
    + "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA" * 4 + "==\n"
    '  IEX ([System.Text.Encoding]::UTF8.GetString('
    '[System.Convert]::FromBase64String("Zm9vYmFy")))\n'
    '  Add-MpPreference -ExclusionPath "C:\\Temp"\n'
    '}\n'
)

BENIGN_TEXT = ("Shopping list\n" + "eggs\nmilk\nbrake fluid\n" * 40)
BENIGN_CSV = "date,amount,note\n" + "\n".join(
    f"2026-0{i%9+1}-15,{i*12.5},row {i}" for i in range(200))


def build_sandbox(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    (root / "Downloads").mkdir(parents=True, exist_ok=True)
    (root / "Documents").mkdir(parents=True, exist_ok=True)

    # --- should be flagged
    p = root / "Downloads" / "invoice_2026.pdf.exe"
    p.write_bytes(PE_STUB + os.urandom(20000))
    files["double_ext"] = p

    p = root / "Downloads" / "meeting_notes.txt"
    p.write_bytes(PE_STUB + os.urandom(9000))
    files["ext_mismatch"] = p

    p = root / "Downloads" / "update_helper.ps1"
    p.write_text(OBFUSCATED_SCRIPT, encoding="utf-8")
    files["obfuscated_script"] = p

    # --- should NOT be flagged
    p = root / "Documents" / "shopping.txt"
    p.write_text(BENIGN_TEXT, encoding="utf-8")
    files["benign_txt"] = p

    p = root / "Documents" / "expenses.csv"
    p.write_text(BENIGN_CSV, encoding="utf-8")
    files["benign_csv"] = p

    p = root / "Documents" / "photo.jpg"
    p.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 5000)
    files["benign_jpg"] = p

    return files


def main() -> int:
    tmp_data = Path(tempfile.mkdtemp(prefix="sentry_selftest_data_"))
    sandbox = Path(tempfile.mkdtemp(prefix="sentry_selftest_scan_"))

    # Redirect all state into a throwaway directory so the real DB is untouched.
    config.DATA_ROOT = tmp_data
    config.DB_PATH = tmp_data / "sentry.db"
    config.QUARANTINE_DIR = tmp_data / "quarantine"
    config.REPORTS_DIR = tmp_data / "reports"
    config.RULES_DIR = tmp_data / "rules"
    config.FEED_DIR = tmp_data / "feeds"
    config.CONFIG_PATH = tmp_data / "config.json"
    for mod in (engine, quarantine, store):
        pass
    config.ensure_dirs()
    store.init_db()

    print(f"\n  sandbox : {sandbox}\n  state   : {tmp_data}\n")
    files = build_sandbox(sandbox)

    cfg = dict(config.DEFAULTS)
    cfg["use_hash_feed"] = False   # keep the test offline and deterministic
    cfg["use_yara"] = False
    cfg["exclusions"] = []
    cfg["report_threshold"] = 25

    print("── scan ──────────────────────────────────────────────")
    result = engine.run_scan([str(sandbox)], trigger="manual", cfg=cfg)
    check("scan_id" in result, "scan completed without fatal error")
    scan_id = result.get("scan_id")
    findings = store.get_findings(scan_id=scan_id)
    print(f"  {len(findings)} finding(s) from "
          f"{result['summary']['files_scanned']} file(s) checked")
    for f in findings:
        print(f"    [{f['severity']:<6} {f['score']:>3}] {f['filename']}")
        for r in f["reasons"]:
            print(f"        - {r}")

    flagged = {f["path"] for f in findings}
    print("\n── detection ─────────────────────────────────────────")
    check(str(files["double_ext"]) in flagged,
          "flags executable hidden behind a double extension")
    check(str(files["ext_mismatch"]) in flagged,
          "flags PE executable disguised with a .txt extension")
    check(str(files["obfuscated_script"]) in flagged,
          "flags obfuscated PowerShell with encoded command + Defender exclusion")
    check(str(files["benign_txt"]) not in flagged, "does not flag a plain text file")
    check(str(files["benign_csv"]) not in flagged, "does not flag a normal CSV")
    check(str(files["benign_jpg"]) not in flagged, "does not flag a real JPEG")

    target = next((f for f in findings
                   if f["path"] == str(files["double_ext"])), None)
    if not target:
        print("\n  cannot continue quarantine tests without a target finding")
        return _summarise()

    print("\n── verdict gating ────────────────────────────────────")
    try:
        quarantine.quarantine_finding(target["id"])
        check(False, "quarantine is refused when no verdict has been set")
    except quarantine.QuarantineError:
        check(True, "quarantine is refused when no verdict has been set")

    store.set_verdict(target["sha256"], "safe", path=target["path"])
    try:
        quarantine.quarantine_finding(target["id"])
        check(False, "quarantine is refused for a file marked safe")
    except quarantine.QuarantineError:
        check(True, "quarantine is refused for a file marked safe")

    print("\n── quarantine round-trip ─────────────────────────────")
    store.set_verdict(target["sha256"], "malicious", path=target["path"])
    original = Path(target["path"])
    original_bytes = original.read_bytes()
    import stat as _stat
    original_mode = _stat.S_IMODE(original.stat().st_mode)
    q = quarantine.quarantine_finding(target["id"])
    qpath = Path(q["quarantine_path"])
    check(not original.exists(), "file removed from its original location")
    check(qpath.exists(), "file present in the quarantine folder")
    check(qpath.read_bytes() == original_bytes,
          "quarantined bytes are byte-identical to the original")
    check(q["original_path"] == str(original),
          "original absolute path recorded for restore")
    sidecar = qpath.with_suffix(".quar.txt")
    check(sidecar.exists() and str(original) in sidecar.read_text(encoding="utf-8"),
          "sidecar note records the original path")

    qid = q["quarantine_id"]
    entry = store.get_quarantine_entry(qid)
    check(entry is not None and entry["original_path"] == str(original),
          "quarantine manifest row written to the database")

    print("\n── restore ───────────────────────────────────────────")
    r = quarantine.restore(qid)
    check(original.exists(), "file restored to its exact original path")
    check(original.read_bytes() == original_bytes,
          "restored bytes are byte-identical")
    check(r["restored_to"] == str(original), "restore reports the original path")
    if not config.IS_WINDOWS:
        check(_stat.S_IMODE(original.stat().st_mode) == original_mode,
              f"original permission bits restored ({original_mode:04o})")
    check(store.get_verdict(target["sha256"]) is None,
          "verdict cleared after restore so the file is re-reviewed next scan")
    check(not qpath.exists(), "quarantine copy removed after restore")

    print("\n── allowlist ─────────────────────────────────────────")
    store.set_verdict(target["sha256"], "safe", path=str(original))
    res2 = engine.run_scan([str(sandbox)], trigger="manual", cfg=cfg)
    f2 = store.get_findings(scan_id=res2["scan_id"])
    check(str(original) not in {f["path"] for f in f2},
          "file marked safe is skipped on the next scan")
    f2_incl = store.get_findings(scan_id=res2["scan_id"], include_safe=True)
    check(True, f"rescan produced {len(f2)} open finding(s) "
                f"({len(f2_incl)} including allowlisted)")

    print("\n── permanent delete ──────────────────────────────────")
    store.set_verdict(target["sha256"], "malicious", path=str(original))
    t3 = next(f for f in store.get_findings(include_safe=True)
              if f["path"] == str(original))
    q3 = quarantine.quarantine_finding(t3["id"])
    qid3 = q3["quarantine_id"]
    try:
        quarantine.purge(qid3, confirm=False)
        check(False, "deletion is refused without explicit confirmation")
    except quarantine.QuarantineError:
        check(True, "deletion is refused without explicit confirmation")
    quarantine.purge(qid3, confirm=True)
    check(not Path(q3["quarantine_path"]).exists(),
          "confirmed deletion removes the file from disk")
    e3 = store.get_quarantine_entry(qid3)
    check(e3 and e3["deleted_at"], "deletion recorded with a timestamp")
    try:
        quarantine.restore(qid3)
        check(False, "restoring a deleted entry is refused")
    except quarantine.QuarantineError:
        check(True, "restoring a deleted entry is refused")

    print("\n── report ────────────────────────────────────────────")
    from sentry import behavior, report
    inds = behavior.sweep([str(sandbox)], cfg)
    scan = store.last_scan() or {}
    out = report.build_report(res2["scan_id"], f2_incl, scan,
                              notes=["self-test run"], indicators=inds)
    html = out.read_text(encoding="utf-8")
    check(out.exists() and len(html) > 3000, "HTML report generated")
    check("Nothing has been moved or deleted" in html,
          "report states that no action was taken automatically")
    check(all(f["sha256"] in html for f in f2_incl) if f2_incl else True,
          "report includes the SHA-256 of every finding")

    code = _summarise()
    shutil.rmtree(sandbox, ignore_errors=True)
    shutil.rmtree(tmp_data, ignore_errors=True)
    return code


def _summarise() -> int:
    npass = sum(1 for ok, _ in _results if ok)
    nfail = len(_results) - npass
    print("\n" + "─" * 54)
    print(f"  {npass} passed, {nfail} failed")
    if nfail:
        for ok, label in _results:
            if not ok:
                print(f"    FAILED: {label}")
    print()
    return 1 if nfail else 0


if __name__ == "__main__":
    raise SystemExit(main())
