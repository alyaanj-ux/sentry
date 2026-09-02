"""Known-bad hash feed + YARA rule loading.

Both are optional. If the machine is offline or the optional dependency is
missing, scanning continues with heuristics only and says so in the report.
"""
from __future__ import annotations

import csv
import io
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from . import config

# MalwareBazaar publishes a rolling dump of recent samples (SHA-256 + signature).
BAZAAR_RECENT = "https://bazaar.abuse.ch/export/csv/recent/"
BAZAAR_FULL = "https://bazaar.abuse.ch/export/csv/full/"

HASH_DB = config.FEED_DIR / "known_bad.csv"
USER_HASH_DB = config.FEED_DIR / "custom_bad_hashes.txt"


def _download(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(
        url, headers={"User-Agent": "Sentry-Local-Scanner/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def update_hash_feed(full: bool = False) -> tuple[bool, str]:
    """Refresh the local known-bad hash cache. Returns (ok, message)."""
    config.ensure_dirs()
    url = BAZAAR_FULL if full else BAZAAR_RECENT
    try:
        raw = _download(url)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return False, f"Feed download failed ({exc}). Continuing with cached data."

    rows: list[tuple[str, str]] = []
    try:
        if raw[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                name = zf.namelist()[0]
                text = zf.read(name).decode("utf-8", "replace")
        else:
            text = raw.decode("utf-8", "replace")

        for line in text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = next(csv.reader([line]))
            parts = [p.strip().strip('"') for p in parts]
            sha = next((p for p in parts if len(p) == 64
                        and all(c in "0123456789abcdefABCDEF" for c in p)), None)
            if not sha:
                continue
            label = ""
            if len(parts) > 8:
                label = parts[8] or ""
            rows.append((sha.lower(), label))
    except Exception as exc:  # noqa: BLE001
        return False, f"Feed parse failed ({type(exc).__name__}): {exc}"

    if not rows:
        return False, "Feed returned no usable rows."

    # Merge with whatever we already had so a 'recent' pull never shrinks coverage.
    existing = _read_hash_db()
    for sha, label in rows:
        existing[sha] = label or existing.get(sha, "")

    with HASH_DB.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["sha256", "label"])
        for sha, label in existing.items():
            w.writerow([sha, label])

    return True, f"Hash feed updated: {len(rows):,} rows fetched, {len(existing):,} total."


def _read_hash_db() -> dict[str, str]:
    out: dict[str, str] = {}
    if HASH_DB.exists():
        try:
            with HASH_DB.open("r", encoding="utf-8", newline="") as fh:
                r = csv.reader(fh)
                next(r, None)
                for row in r:
                    if len(row) >= 1 and len(row[0]) == 64:
                        out[row[0].lower()] = row[1] if len(row) > 1 else ""
        except OSError:
            pass
    return out


def load_known_bad() -> dict[str, str]:
    """SHA-256 -> label map from the cached feed plus any user-supplied hashes."""
    known = _read_hash_db()
    if USER_HASH_DB.exists():
        try:
            for line in USER_HASH_DB.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                sha = line.split()[0].lower()
                if len(sha) == 64:
                    label = line[len(sha):].strip() or "user-supplied hash"
                    known[sha] = label
        except OSError:
            pass
    return known


def feed_age_days() -> float | None:
    if not HASH_DB.exists():
        return None
    return (time.time() - HASH_DB.stat().st_mtime) / 86400.0


def feed_status() -> dict:
    known = load_known_bad()
    return {
        "available": bool(known),
        "count": len(known),
        "age_days": feed_age_days(),
        "path": str(HASH_DB),
    }


# ----------------------------------------------------------------- YARA

def load_yara():
    """Compile every .yar/.yara file in the rules dir. Returns (rules|None, message)."""
    try:
        import yara  # type: ignore
    except ImportError:
        return None, ("yara-python is not installed — pattern rules are disabled. "
                      "Install with: pip install yara-python")

    config.ensure_dirs()
    files = sorted(list(config.RULES_DIR.rglob("*.yar")) +
                   list(config.RULES_DIR.rglob("*.yara")))
    if not files:
        return None, (f"No YARA rules found in {config.RULES_DIR}. "
                      "Drop .yar files there to enable pattern matching.")

    sources = {}
    skipped = []
    for f in files:
        try:
            yara.compile(filepath=str(f))
            sources[f.stem] = str(f)
        except Exception as exc:  # noqa: BLE001
            skipped.append(f"{f.name}: {exc}")

    if not sources:
        return None, f"All {len(files)} rule file(s) failed to compile."
    try:
        rules = yara.compile(filepaths=sources)
    except Exception as exc:  # noqa: BLE001
        return None, f"Rule set failed to link: {exc}"

    msg = f"{len(sources)} YARA rule file(s) loaded."
    if skipped:
        msg += f" {len(skipped)} skipped: {'; '.join(skipped[:2])}"
    return rules, msg


def yara_status() -> dict:
    rules, msg = load_yara()
    return {"available": rules is not None, "message": msg,
            "rules_dir": str(config.RULES_DIR)}
