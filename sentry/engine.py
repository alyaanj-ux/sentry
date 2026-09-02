"""Scan orchestration: file walking, hashing, scoring, persistence."""
from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

from . import config, feeds, heuristics, store

CHUNK = 1024 * 1024
HEADER_BYTES = 4096


@dataclass
class ScanProgress:
    running: bool = False
    scan_id: int | None = None
    current_path: str = ""
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    findings: int = 0
    errors: int = 0
    cloud_placeholders_skipped: int = 0
    started_at: str | None = None
    finished_at: str | None = None
    trigger: str = "manual"
    notes: list[str] = field(default_factory=list)
    cancel: bool = False

    def snapshot(self) -> dict:
        d = self.__dict__.copy()
        d.pop("cancel", None)
        return d


PROGRESS = ScanProgress()
_SCAN_LOCK = threading.Lock()


def _begin_scan(trigger: str) -> bool:
    """Reserve the single scan slot and publish a fresh PROGRESS in one step.

    Reserving and publishing together is what makes PROGRESS safe to read and to
    mutate (e.g. `PROGRESS.cancel`) from the moment a caller is told a scan
    started — otherwise callers see, and write to, the previous scan's object.
    """
    global PROGRESS
    if not _SCAN_LOCK.acquire(blocking=False):
        return False
    PROGRESS = ScanProgress(running=True, trigger=trigger, started_at=store.now())
    return True


def sha256_file(path: str) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with open(config.long_path(path), "rb") as fh:
        while True:
            block = fh.read(CHUNK)
            if not block:
                break
            h.update(block)
            total += len(block)
    return h.hexdigest(), total


def _is_excluded(path: str, exclusions: list[str]) -> bool:
    norm = os.path.normcase(os.path.normpath(path))
    for ex in exclusions:
        e = os.path.normcase(os.path.normpath(os.path.expandvars(ex)))
        if norm == e or norm.startswith(e.rstrip(os.sep) + os.sep):
            return True
    return False


def _under(child_nc: str, parent_nc: str) -> bool:
    """Prefix test that respects directory boundaries.

    Plain startswith() would treat C:\\Users\\x\\SentryBackup as being inside
    C:\\Users\\x\\Sentry.
    """
    return (child_nc == parent_nc
            or child_nc.startswith(parent_nc.rstrip(os.sep) + os.sep))


def _is_reparse_dir(dirpath: str, name: str) -> bool:
    """True for a junction / directory symlink on Windows.

    The legacy compatibility junctions in %LOCALAPPDATA% ("Application Data",
    "History") point back at their own parent, so following them recurses
    forever. os.walk(followlinks=False) already refuses name-surrogate reparse
    points on CPython 3.8+, but follow_symlinks is a user-settable option here,
    so the guard has to be unconditional on Windows.
    """
    if not config.IS_WINDOWS:
        return False
    try:
        st = os.lstat(config.long_path(os.path.join(dirpath, name)))
    except OSError:
        return True  # unreadable: do not descend
    attrs = getattr(st, "st_file_attributes", 0) or 0
    if not attrs & config.FILE_ATTRIBUTE_REPARSE_POINT:
        return False
    tag = getattr(st, "st_reparse_tag", None)
    if tag is None:  # st_reparse_tag needs CPython 3.8+
        return os.path.islink(config.long_path(os.path.join(dirpath, name)))
    # Only name surrogates (junctions, dir symlinks) can create a loop. Cloud
    # (OneDrive) directory reparse points are enumerable without hydration, so
    # they are walked; their placeholder *files* are skipped in scan_file().
    return tag in config.NAME_SURROGATE_TAGS


def iter_candidate_files(paths: list[str], cfg: dict) -> Iterator[str]:
    exclusions = cfg.get("exclusions", [])
    follow = cfg.get("follow_symlinks", False)
    quar = os.path.normcase(os.path.normpath(str(config.DATA_ROOT)))
    # Sentry's own folder is pruned regardless of the exclusions list -- an
    # older or hand-edited config.json does not carry the default entry.
    self_dir = (None if cfg.get("scan_self")
                else os.path.normcase(os.path.normpath(config.install_dir())))
    seen_dirs: set[str] = set()

    for root_path in paths:
        if os.path.isfile(config.long_path(root_path)):
            yield root_path
            continue
        # Walking a \\?\-prefixed root makes every path yielded below it
        # long-path-safe, so deep trees are actually scanned instead of
        # silently vanishing. The prefix must be applied *unconditionally*:
        # the root is usually short (D:\), and long_path() would otherwise
        # leave it bare, so nothing below it was ever prefixed.
        walk_root = config.long_path(os.path.abspath(root_path), always=True)
        for dirpath, dirnames, filenames in os.walk(
                walk_root, topdown=True, followlinks=follow,
                onerror=lambda e: None):
            plain = config.strip_long_prefix(dirpath)
            nc = os.path.normcase(os.path.normpath(plain))
            if _under(nc, quar) or (self_dir and _under(nc, self_dir)):
                dirnames[:] = []
                continue
            if _is_excluded(plain, exclusions):
                dirnames[:] = []
                continue
            # Cheap loop guard, only when the user opted into following links
            # (keeping the set unconditionally would cost ~50MB on a C: sweep).
            if follow:
                if nc in seen_dirs:
                    dirnames[:] = []
                    continue
                seen_dirs.add(nc)
            # Prune early so we never descend into excluded trees.
            dirnames[:] = [
                d for d in dirnames
                if not config.excluded_dir_name(d)
                and not _is_excluded(os.path.join(plain, d), exclusions)
                and not _is_reparse_dir(dirpath, d)
            ]
            for fn in filenames:
                yield os.path.join(plain, fn)


def _should_inspect(path: str, size: int, cfg: dict) -> tuple[bool, str]:
    ext = os.path.splitext(path)[1].lower()
    if ext in config.SKIP_EXT:
        return False, "media/disk-image type"
    try:
        max_mb = int(cfg.get("max_file_mb", 128))
    except (TypeError, ValueError):
        # A corrupted setting must not blind the scanner for every file.
        max_mb = int(config.DEFAULTS["max_file_mb"])
    max_bytes = max_mb * 1024 * 1024
    if size > max_bytes:
        return False, "over size limit"
    if size == 0:
        return False, "empty file"
    return True, ""


# Reason fragments that are evidence of actual malice rather than of a file
# merely being packed or hardened. A finding carrying any of these is NEVER
# damped, no matter where it lives -- a trojaned game binary has to surface.
STRONG_SIGNALS = (
    "known-malicious hash feed",
    "YARA rule matched",
    "but content is a",              # extension/content mismatch
    "Double extension disguising",
    "bidirectional-override",
    "Attempts to add Windows Defender exclusions",
    "Deletes shadow copies",
    "certutil abused",
    "rundll32 script execution",
    "mshta remote execution",
    "Creates or elevates a local account",
    "Pipes remote content directly into a shell",
    "PowerShell encoded-command with long base64 blob",
    "auto-execution macro",
    "Office document references PowerShell",
    "Embedded PE executable found in resources",
)

# How much of the structural score survives inside a protected location.
PROTECTED_DAMPING = 0.3


def damp_protected(score: int, reasons: list[str],
                   protected: str) -> tuple[int, list[str]]:
    """Reduce a structure-only score for a file in a protected app folder.

    Anti-cheat and DRM are packed, high-entropy, and full of injection and
    anti-debug APIs by design -- that is their entire job. Scoring them the
    same as an unknown binary in Downloads produces a weekly report full of
    files you must never touch, which is how a scanner teaches you to ignore it.

    A file carrying any STRONG_SIGNALS keeps its full score: this damps the
    "it looks hardened" evidence, never the "it is behaving maliciously"
    evidence.
    """
    if any(sig in r for r in reasons for sig in STRONG_SIGNALS):
        reasons.append(
            f"NOTE: {protected}, but the evidence above is behavioural rather "
            "than structural, so the score was not reduced. If this is a game "
            "file, use the launcher's 'verify integrity of game files' rather "
            "than quarantining it.")
        return score, reasons

    damped = int(round(score * PROTECTED_DAMPING))
    reasons.append(
        f"Score reduced from {score} to {damped}: {protected}. Anti-cheat and "
        "DRM are packed and obfuscated by design, so the structural findings "
        "above are expected here. Quarantine is blocked for this location.")
    return damped, reasons


def scan_file(path: str, *, known_bad: dict[str, str], yara_rules,
              cfg: dict, allow: set[str]) -> dict | None:
    """Score a single file. Returns a finding dict, or None if not worth reporting."""
    wpath = config.long_path(path)
    try:
        st = os.stat(wpath)
    except (OSError, ValueError):
        return None

    # A OneDrive / cloud placeholder holds no local bytes: open()ing it makes
    # Windows download the whole file. Never touch one.
    if config.is_dehydrated(st):
        PROGRESS.files_skipped += 1
        PROGRESS.cloud_placeholders_skipped += 1
        return None

    ok, _why = _should_inspect(path, st.st_size, cfg)
    if not ok:
        return None

    ext = os.path.splitext(path)[1].lower()
    interesting_ext = (ext in config.BINARY_EXT or ext in config.SCRIPT_EXT
                       or ext in config.MACRO_EXT or ext == "")

    try:
        with open(wpath, "rb") as fh:
            header = fh.read(HEADER_BYTES)
    except (OSError, PermissionError):
        return None

    is_pe = header.startswith(heuristics.MZ)
    is_elf = header.startswith(heuristics.ELF)

    name_hits = heuristics.check_filename(path)
    mismatch_hits = heuristics.check_content_type_mismatch(path, header)

    # Skip the expensive path for plain data files with nothing odd about them.
    if not (interesting_ext or is_pe or is_elf or name_hits or mismatch_hits):
        return None

    try:
        sha, nbytes = sha256_file(path)
    except (OSError, PermissionError):
        return None

    if sha in allow:
        return None

    score = 0
    reasons: list[str] = []
    meta: dict = {}

    label = known_bad.get(sha)
    if label is not None:
        score = 100
        reasons.append(f"SHA-256 matches known-malicious hash feed"
                       + (f" (family: {label})" if label else ""))

    for delta, reason in name_hits + mismatch_hits:
        score += delta
        reasons.append(reason)

    if yara_rules is not None:
        try:
            matches = yara_rules.match(filepath=wpath, timeout=30)
            for m in matches:
                tags = ",".join(getattr(m, "tags", []) or [])
                sev = 45 if tags and any(
                    t in tags for t in ("malware", "trojan", "ransomware")) else 30
                score += sev
                reasons.append(f"YARA rule matched: {m.rule}"
                               + (f" [{tags}]" if tags else ""))
        except Exception:  # noqa: BLE001 - yara raises on locked/odd files
            pass

    if is_pe:
        pe_hits, meta = heuristics.analyse_pe(wpath)
        for delta, reason in pe_hits:
            score += delta
            reasons.append(reason)

    if ext in config.SCRIPT_EXT or ext in {".txt", ".log"}:
        try:
            with open(wpath, "rb") as fh:
                data = fh.read(heuristics.SCRIPT_SNIFF_BYTES)
            for delta, reason in heuristics.analyse_script(path, data):
                score += delta
                reasons.append(reason)
        except (OSError, PermissionError):
            pass

    if ext in config.MACRO_EXT:
        try:
            with open(wpath, "rb") as fh:
                data = fh.read(2 * 1024 * 1024)
            for delta, reason in heuristics.analyse_macro_office(path, data):
                score += delta
                reasons.append(reason)
        except (OSError, PermissionError):
            pass

    protected = config.protected_reason(path)
    if protected:
        score, reasons = damp_protected(score, reasons, protected)

    score = min(score, 100)
    threshold = int(cfg.get("report_threshold", 25))
    if score < threshold:
        return None

    return {
        "path": os.path.abspath(path),
        "sha256": sha,
        "size": nbytes,
        "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc)
                         .isoformat(timespec="seconds"),
        "score": score,
        "severity": heuristics.severity_for(score),
        "reasons": reasons,
        "meta": meta,
    }


def run_scan(paths: list[str] | None = None, *, trigger: str = "manual",
             cfg: dict | None = None,
             on_progress: Callable[[ScanProgress], None] | None = None,
             _reserved: bool = False) -> dict:
    """Full scan. Writes findings to the DB and returns a summary dict."""
    if not _reserved and not _begin_scan(trigger):
        return {"error": "A scan is already running."}

    try:
        # An explicitly-passed empty dict means "this config", not "reload from
        # disk"; only None asks for the saved config.
        cfg = config.load_config() if cfg is None else cfg
        store.init_db()
        if paths is None:
            paths = config.resolved_scan_paths(cfg)

        if not paths:
            PROGRESS.notes.append("No scan paths configured or none exist.")
            return {"error": "No valid scan paths configured.",
                    "summary": PROGRESS.snapshot()}

        known_bad: dict[str, str] = {}
        if cfg.get("use_hash_feed", True):
            age = feeds.feed_age_days()
            max_age = float(cfg.get("feed_max_age_days", 7))
            if age is None or age > max_age:
                ok, msg = feeds.update_hash_feed()
                PROGRESS.notes.append(msg)
            known_bad = feeds.load_known_bad()
            PROGRESS.notes.append(f"{len(known_bad):,} known-bad hashes loaded.")
        else:
            PROGRESS.notes.append("Hash feed disabled in config.")

        yara_rules = None
        if cfg.get("use_yara", True):
            yara_rules, msg = feeds.load_yara()
            PROGRESS.notes.append(msg)

        allow = store.allowlist()
        if allow:
            PROGRESS.notes.append(f"{len(allow)} file(s) on your allowlist will be skipped.")

        scan_id = store.start_scan(paths, trigger)
        PROGRESS.scan_id = scan_id

        for path in iter_candidate_files(paths, cfg):
            if PROGRESS.cancel:
                PROGRESS.notes.append("Scan cancelled by user.")
                break
            PROGRESS.current_path = path
            try:
                finding = scan_file(path, known_bad=known_bad, yara_rules=yara_rules,
                                    cfg=cfg, allow=allow)
            except Exception:  # noqa: BLE001 - never let one file kill the scan
                PROGRESS.errors += 1
                continue

            PROGRESS.files_scanned += 1
            if finding:
                try:
                    store.upsert_finding(finding, scan_id)
                except Exception as exc:  # noqa: BLE001 - e.g. an unencodable path
                    # One unstorable finding must not abandon the whole scan and
                    # throw away every result after it.
                    PROGRESS.errors += 1
                    note = ("Could not record a finding "
                            f"({type(exc).__name__}); it was skipped.")
                    if note not in PROGRESS.notes:
                        PROGRESS.notes.append(note)
                    continue
                PROGRESS.bytes_scanned += finding["size"]
                PROGRESS.findings += 1
            if on_progress and PROGRESS.files_scanned % 250 == 0:
                on_progress(PROGRESS)

        if PROGRESS.cloud_placeholders_skipped:
            PROGRESS.notes.append(
                f"{PROGRESS.cloud_placeholders_skipped:,} cloud placeholder "
                "file(s) skipped — not downloaded from OneDrive. Use "
                "'Always keep on this device' if you want them scanned.")
        store.finish_scan(scan_id, files=PROGRESS.files_scanned,
                          nbytes=PROGRESS.bytes_scanned,
                          findings=PROGRESS.findings, errors=PROGRESS.errors)
        PROGRESS.finished_at = store.now()
        store.log_event("scan", f"{trigger} scan #{scan_id}: "
                                f"{PROGRESS.files_scanned} files, "
                                f"{PROGRESS.findings} findings")
        return {"scan_id": scan_id, "summary": PROGRESS.snapshot()}
    finally:
        PROGRESS.running = False
        PROGRESS.current_path = ""
        _SCAN_LOCK.release()


def scan_in_background(paths: list[str] | None = None,
                       trigger: str = "manual") -> bool:
    # Reserve the slot in the calling thread so the answer is truthful and so the
    # caller can immediately read/cancel the progress object for *this* scan.
    if not _begin_scan(trigger):
        return False
    t = threading.Thread(target=run_scan,
                         kwargs={"paths": paths, "trigger": trigger,
                                 "_reserved": True},
                         daemon=True)
    try:
        t.start()
    except BaseException:
        PROGRESS.running = False
        _SCAN_LOCK.release()
        raise
    return True
