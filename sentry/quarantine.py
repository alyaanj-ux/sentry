"""Quarantine: move, restore, purge.

Design rules enforced here, not just documented:
  * Quarantine only ever runs for a file you explicitly marked 'malicious'
    or 'unknown'. Anything else raises.
  * The original absolute path is recorded before the move, so restore is exact.
  * Nothing is ever deleted as part of quarantining. Deletion is a separate,
    explicit call.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from . import config, store

QUARANTINABLE = {"malicious", "unknown"}


class QuarantineError(RuntimeError):
    pass


def _sha256(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with open(config.long_path(str(path)), "rb") as fh:
        while True:
            block = fh.read(1024 * 1024)
            if not block:
                break
            h.update(block)
            total += len(block)
    return h.hexdigest(), total


# SID literals rather than names: icacls resolves '*S-1-1-0' on any locale and
# any domain membership, whereas %USERNAME% can be wrong for Microsoft accounts
# and 'Everyone' is localised (e.g. 'Jeder' on a German install).
SID_EVERYONE = "*S-1-1-0"


def _icacls(*args: str) -> tuple[int, str]:
    """Run icacls and return (returncode, combined output).

    icacls exits non-zero and prints 'Failed processing N files' when it cannot
    change a DACL, so the return code has to be inspected — the previous code
    reported success unconditionally.
    """
    r = subprocess.run(["icacls", *args], capture_output=True, timeout=30,
                       check=False, text=True, errors="replace")
    return r.returncode, ((r.stdout or "") + (r.stderr or "")).strip()


def _harden(path: Path) -> list[str]:
    """Make a quarantined file awkward to run by accident.

    Deliberately does NOT use '/inheritance:r' + '/grant:r USER:(R)'. That
    combination leaves the file with a DACL that grants read only, so the
    subsequent restore/purge (which needs DELETE to rename or unlink the file)
    fails with Access Denied. Here inheritance is *copied* rather than removed,
    so the owner keeps full control, and a single explicit deny-execute ACE for
    Everyone is what actually blocks execution. Deny ACEs are evaluated before
    allow ACEs, so this wins over the inherited grants.
    """
    notes: list[str] = []
    try:
        if config.IS_WINDOWS:
            # Convert inherited ACEs to explicit ones. Unlike /inheritance:r
            # this keeps existing access, so we cannot lock ourselves out.
            rc1, out1 = _icacls(str(path), "/inheritance:d")
            rc2, out2 = _icacls(str(path), "/deny", f"{SID_EVERYONE}:(X)")
            if rc2 == 0:
                notes.append("execute denied for Everyone (deny ACE)")
            else:
                notes.append(f"could not deny execute: {out2 or f'icacls exit {rc2}'}")
            if rc1 != 0:
                notes.append(f"could not detach inherited ACLs: "
                             f"{out1 or f'icacls exit {rc1}'}")
            # Read-only attribute as a second, filesystem-independent barrier.
            # This is the only protection that survives on FAT32/exFAT, where
            # there are no ACLs at all and icacls fails outright.
            try:
                os.chmod(path, stat.S_IREAD)
                notes.append("read-only attribute set")
            except OSError as exc:
                notes.append(f"could not set read-only attribute ({exc})")
        else:
            os.chmod(path, stat.S_IRUSR)
            notes.append("mode set to 0400")
    except Exception as exc:  # noqa: BLE001
        notes.append(f"could not harden permissions ({exc})")
    return notes


def _unharden(path: Path) -> None:
    """Undo _harden so the file can be moved or deleted again."""
    try:
        if config.IS_WINDOWS:
            # Clear the read-only attribute first: os.unlink and os.rename both
            # fail on a read-only file on Windows.
            try:
                os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
            _icacls(str(path), "/remove:d", SID_EVERYONE)
            # Older builds may have hardened with a username-based deny ACE.
            user = os.environ.get("USERNAME", "")
            if user:
                _icacls(str(path), "/remove:d", user)
            # /reset alone only reapplies *inherited* ACEs, which is a no-op
            # while the file is still flagged as protected from inheritance —
            # so re-enable inheritance explicitly before resetting.
            _icacls(str(path), "/inheritance:e")
            _icacls(str(path), "/reset")
        else:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:  # noqa: BLE001
        pass


def _unique_dest(sha256: str) -> Path:
    config.ensure_dirs()
    base = config.QUARANTINE_DIR / f"{sha256}.quar"
    n = 1
    dest = base
    while dest.exists():
        dest = config.QUARANTINE_DIR / f"{sha256}.{n}.quar"
        n += 1
    return dest


def quarantine_finding(finding_id: int, *, allow_protected: bool = False) -> dict:
    """Move the file for `finding_id` into quarantine. Requires a verdict first."""
    finding = store.get_finding(finding_id)
    if not finding:
        raise QuarantineError(f"No finding with id {finding_id}.")

    verdict = store.get_verdict(finding["sha256"])
    if verdict not in QUARANTINABLE:
        raise QuarantineError(
            "Quarantine requires the file to be marked 'malicious' or 'unknown' "
            f"first (current verdict: {verdict or 'none'})."
        )

    # Refuse to break an installed application. Moving a file out of a game or
    # program folder does not make an uncertain file safe -- it makes the
    # program stop working, usually much later and in a way nobody connects
    # back to this tool. If a game file really is bad, the launcher's "verify
    # integrity of game files" replaces it correctly; quarantining it does not.
    protected = config.protected_reason(finding["path"])
    if protected and not allow_protected:
        raise QuarantineError(
            f"Refusing to quarantine: this file is {protected}. Removing it "
            "would likely break that program. If it is a game, use the "
            "launcher's 'verify integrity of game files' to replace the file "
            "instead. Override only if you are certain."
        )

    src = Path(finding["path"])
    if not os.path.exists(config.long_path(str(src))):
        raise QuarantineError(f"File no longer exists at {src}")
    if src.is_symlink():
        # Moving a link would leave the real payload in place while hardening and
        # later deleting whatever the link happens to point at.
        raise QuarantineError(
            f"{src} is a symbolic link, not a real file. Quarantine acts on the "
            "link's target, which is not what was reviewed; scan and act on "
            f"{os.path.realpath(src)} instead.")

    # The file may have been replaced since it was scored. Acting on a different
    # file than the one reviewed is exactly what must never happen here.
    try:
        current_sha, current_size = _sha256(src)
    except OSError as exc:
        raise QuarantineError(f"Could not read {src}: {exc}") from exc
    if current_sha != finding["sha256"]:
        raise QuarantineError(
            f"The file at {src} has changed since it was scanned (now SHA-256 "
            f"{current_sha[:16]}…, reviewed {finding['sha256'][:16]}…). "
            "Re-scan and review it again before quarantining.")

    try:
        original_mode = stat.S_IMODE(os.stat(config.long_path(str(src))).st_mode)
    except OSError:
        original_mode = None

    dest = _unique_dest(finding["sha256"])
    try:
        shutil.move(config.long_path(str(src)), str(dest))
    except (OSError, shutil.Error) as exc:
        raise QuarantineError(
            f"Could not move file — it may be locked or in use by a running "
            f"process. Close whatever is using it and retry. ({exc})") from exc

    notes = _harden(dest)
    qid = store.record_quarantine(
        sha256=finding["sha256"], original_path=str(src),
        quarantine_path=str(dest), size=finding["size"],
        verdict=verdict, reasons=finding["reasons"],
        original_mode=original_mode,
    )
    # Write a sidecar so the quarantine folder is self-describing even without the DB.
    try:
        dest.with_suffix(".quar.txt").write_text(
            f"Quarantined by Sentry\n"
            f"Quarantine ID : {qid}\n"
            f"Original path : {src}\n"
            f"SHA-256       : {finding['sha256']}\n"
            f"Size          : {finding['size']} bytes\n"
            f"Verdict       : {verdict}\n"
            f"Score         : {finding['score']}\n"
            f"Reasons       :\n" + "".join(f"  - {r}\n" for r in finding["reasons"]),
            encoding="utf-8")
    except OSError:
        pass

    store.log_event("quarantine", f"{src} -> {dest} ({verdict})")
    return {"quarantine_id": qid, "original_path": str(src),
            "quarantine_path": str(dest), "notes": notes}


def restore(qid: int) -> dict:
    entry = store.get_quarantine_entry(qid)
    if not entry:
        raise QuarantineError(f"No quarantine entry with id {qid}.")
    if entry["restored_at"]:
        raise QuarantineError("Already restored.")
    if entry["deleted_at"]:
        raise QuarantineError("This file was permanently deleted and cannot be restored.")

    src = Path(entry["quarantine_path"])
    dest = Path(entry["original_path"])
    if not src.exists():
        raise QuarantineError(f"Quarantined file missing from {src}")
    long_dest = config.long_path(str(dest))

    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise QuarantineError(
            f"Cannot recreate the original folder {dest.parent}: {exc}") from exc
    if os.path.exists(long_dest):
        raise QuarantineError(
            f"Something already exists at the original path: {dest}. "
            "Move or rename it first.")

    _unharden(src)
    try:
        shutil.move(str(src), long_dest)
    except (OSError, shutil.Error) as exc:
        raise QuarantineError(f"Restore failed: {exc}") from exc

    # Put the original permission bits back rather than leaving the
    # hardened 0600 that quarantining applied.
    mode = entry.get("original_mode")
    if mode:
        try:
            if config.IS_WINDOWS:
                # Only the read-only bit is meaningful on Windows; _harden set
                # it, so put it back the way we found it.
                os.chmod(long_dest, stat.S_IREAD if not int(mode) & stat.S_IWRITE
                         else stat.S_IWRITE | stat.S_IREAD)
            else:
                os.chmod(dest, int(mode))
        except OSError:
            pass

    sidecar = src.with_suffix(".quar.txt")
    if sidecar.exists():
        try:
            sidecar.unlink()
        except OSError:
            pass

    store.mark_restored(qid)
    store.clear_verdict(entry["sha256"])
    store.log_event("restore", f"{src} -> {dest}")
    return {"restored_to": str(dest)}


def purge(qid: int, *, confirm: bool = False) -> dict:
    """Permanently delete a quarantined file. Requires confirm=True."""
    if not confirm:
        raise QuarantineError("Deletion requires explicit confirmation.")
    entry = store.get_quarantine_entry(qid)
    if not entry:
        raise QuarantineError(f"No quarantine entry with id {qid}.")
    if entry["deleted_at"]:
        raise QuarantineError("Already deleted.")

    src = Path(entry["quarantine_path"])
    if src.exists():
        _unharden(src)
        try:
            src.unlink()
        except OSError as exc:
            raise QuarantineError(f"Delete failed: {exc}") from exc
    sidecar = src.with_suffix(".quar.txt")
    if sidecar.exists():
        try:
            sidecar.unlink()
        except OSError:
            pass

    store.mark_deleted(qid)
    store.log_event("delete", f"purged {entry['original_path']} "
                              f"(sha256 {entry['sha256'][:16]})")
    return {"deleted": entry["original_path"]}
