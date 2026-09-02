"""SQLite-backed persistence: findings, verdicts, quarantine manifest, scan history."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import config

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256      TEXT NOT NULL,
    path        TEXT NOT NULL,
    directory   TEXT NOT NULL,
    filename    TEXT NOT NULL,
    size        INTEGER NOT NULL,
    mtime       TEXT,
    score       INTEGER NOT NULL,
    severity    TEXT NOT NULL,
    reasons     TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    scan_id     INTEGER,
    UNIQUE(sha256, path)
);
CREATE INDEX IF NOT EXISTS idx_findings_sha ON findings(sha256);

CREATE TABLE IF NOT EXISTS verdicts (
    sha256      TEXT PRIMARY KEY,
    verdict     TEXT NOT NULL,          -- malicious | unknown | safe
    path        TEXT,
    note        TEXT,
    marked_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT NOT NULL,
    original_path   TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    size            INTEGER,
    verdict         TEXT NOT NULL,
    reasons         TEXT,
    quarantined_at  TEXT NOT NULL,
    restored_at     TEXT,
    deleted_at      TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    trigger        TEXT NOT NULL,       -- manual | scheduled
    paths          TEXT NOT NULL,
    files_scanned  INTEGER DEFAULT 0,
    bytes_scanned  INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0,
    errors         INTEGER DEFAULT 0,
    report_path    TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    kind      TEXT NOT NULL,
    detail    TEXT
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    config.ensure_dirs()
    conn = sqlite3.connect(config.DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


MIGRATIONS = [
    ("quarantine", "original_mode", "ALTER TABLE quarantine ADD COLUMN original_mode INTEGER"),
]


def init_db() -> None:
    with _LOCK, connect() as conn:
        conn.executescript(SCHEMA)
        for table, column, ddl in MIGRATIONS:
            cols = {r["name"] for r in conn.execute(
                f"PRAGMA table_info({table})").fetchall()}
            if column not in cols:
                conn.execute(ddl)


def log_event(kind: str, detail: str = "") -> None:
    with _LOCK, connect() as conn:
        conn.execute("INSERT INTO events (at, kind, detail) VALUES (?,?,?)",
                     (now(), kind, detail))


# ---------------------------------------------------------------- scans

def start_scan(paths: Iterable[str], trigger: str = "manual") -> int:
    with _LOCK, connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (started_at, trigger, paths) VALUES (?,?,?)",
            (now(), trigger, json.dumps(list(paths))),
        )
        return int(cur.lastrowid)


def finish_scan(scan_id: int, *, files: int, nbytes: int, findings: int,
                errors: int, report_path: str | None = None) -> None:
    with _LOCK, connect() as conn:
        conn.execute(
            "UPDATE scans SET finished_at=?, files_scanned=?, bytes_scanned=?,"
            " findings_count=?, errors=?, report_path=? WHERE id=?",
            (now(), files, nbytes, findings, errors, report_path, scan_id),
        )


def get_scan(scan_id: int) -> dict | None:
    """One scan row by id. cmd_weekly must use this, not last_scan(): while a
    weekly run is in progress the dashboard can start and finish another scan,
    and "the most recent finished scan" is then the wrong one."""
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None


def last_scan() -> dict | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE finished_at IS NOT NULL"
            " ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None


def scan_history(limit: int = 20) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


# ------------------------------------------------------------- findings

def upsert_finding(f: dict, scan_id: int) -> None:
    p = Path(f["path"])
    with _LOCK, connect() as conn:
        conn.execute(
            """
            INSERT INTO findings (sha256, path, directory, filename, size, mtime,
                                  score, severity, reasons, first_seen, last_seen, scan_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(sha256, path) DO UPDATE SET
                score=excluded.score,
                severity=excluded.severity,
                reasons=excluded.reasons,
                size=excluded.size,
                mtime=excluded.mtime,
                last_seen=excluded.last_seen,
                scan_id=excluded.scan_id
            """,
            (f["sha256"], f["path"], str(p.parent), p.name, f["size"],
             f.get("mtime"), f["score"], f["severity"],
             json.dumps(f.get("reasons", [])), now(), now(), scan_id),
        )


def get_findings(*, scan_id: int | None = None, include_safe: bool = False,
                 min_score: int = 0) -> list[dict]:
    """Findings joined with any verdict, newest-scan-first, highest score first."""
    q = """
        SELECT f.*, v.verdict AS verdict, v.marked_at AS marked_at,
               q.id AS quarantine_id, q.quarantined_at AS quarantined_at,
               q.restored_at AS restored_at, q.deleted_at AS deleted_at
        FROM findings f
        LEFT JOIN verdicts v ON v.sha256 = f.sha256
        LEFT JOIN (
                 SELECT sha256, original_path, MAX(id) AS id
                 FROM quarantine
                 WHERE restored_at IS NULL AND deleted_at IS NULL
                 GROUP BY sha256, original_path
             ) qa ON qa.sha256 = f.sha256 AND qa.original_path = f.path
        LEFT JOIN quarantine q ON q.id = qa.id
        WHERE f.score >= ?
    """
    params: list[Any] = [min_score]
    if scan_id is not None:
        q += " AND f.scan_id = ?"
        params.append(scan_id)
    if not include_safe:
        q += " AND (v.verdict IS NULL OR v.verdict != 'safe')"
    q += " ORDER BY f.score DESC, f.last_seen DESC"

    with connect() as conn:
        rows = conn.execute(q, params).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["reasons"] = json.loads(d["reasons"] or "[]")
        d["exists"] = Path(d["path"]).exists()
        # Surfaced so the dashboard can mark the row before anyone clicks
        # Quarantine, rather than only explaining after it is refused.
        d["protected"] = config.protected_reason(d["path"])
        out.append(d)
    return out


def get_finding(finding_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id=?",
                           (finding_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["reasons"] = json.loads(d["reasons"] or "[]")
    return d


def delete_finding(finding_id: int) -> None:
    with _LOCK, connect() as conn:
        conn.execute("DELETE FROM findings WHERE id=?", (finding_id,))


# ------------------------------------------------------------- verdicts

VALID_VERDICTS = {"malicious", "unknown", "safe"}


def set_verdict(sha256: str, verdict: str, path: str | None = None,
                note: str | None = None) -> None:
    if verdict not in VALID_VERDICTS:
        raise ValueError(f"invalid verdict: {verdict!r}")
    with _LOCK, connect() as conn:
        conn.execute(
            "INSERT INTO verdicts (sha256, verdict, path, note, marked_at)"
            " VALUES (?,?,?,?,?)"
            " ON CONFLICT(sha256) DO UPDATE SET verdict=excluded.verdict,"
            " path=excluded.path, note=excluded.note, marked_at=excluded.marked_at",
            (sha256, verdict, path, note, now()),
        )
    log_event("verdict", f"{verdict} {sha256[:16]} {path or ''}")


def get_verdict(sha256: str) -> str | None:
    with connect() as conn:
        row = conn.execute("SELECT verdict FROM verdicts WHERE sha256=?",
                           (sha256,)).fetchone()
    return row["verdict"] if row else None


def clear_verdict(sha256: str) -> None:
    with _LOCK, connect() as conn:
        conn.execute("DELETE FROM verdicts WHERE sha256=?", (sha256,))


def allowlist() -> set[str]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT sha256 FROM verdicts WHERE verdict='safe'").fetchall()
    return {r["sha256"] for r in rows}


def verdict_list() -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM verdicts ORDER BY marked_at DESC").fetchall()
    return [dict(r) for r in rows]


# ----------------------------------------------------------- quarantine

def record_quarantine(*, sha256: str, original_path: str, quarantine_path: str,
                      size: int, verdict: str, reasons: list[str],
                      original_mode: int | None = None) -> int:
    with _LOCK, connect() as conn:
        cur = conn.execute(
            "INSERT INTO quarantine (sha256, original_path, quarantine_path, size,"
            " verdict, reasons, quarantined_at, original_mode)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (sha256, original_path, quarantine_path, size, verdict,
             json.dumps(reasons), now(), original_mode),
        )
        return int(cur.lastrowid)


def get_quarantine_entry(qid: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM quarantine WHERE id=?", (qid,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["reasons"] = json.loads(d["reasons"] or "[]")
    return d


def quarantine_list(active_only: bool = True) -> list[dict]:
    q = "SELECT * FROM quarantine"
    if active_only:
        q += " WHERE restored_at IS NULL AND deleted_at IS NULL"
    q += " ORDER BY quarantined_at DESC"
    with connect() as conn:
        rows = conn.execute(q).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["reasons"] = json.loads(d["reasons"] or "[]")
        out.append(d)
    return out


def mark_restored(qid: int) -> None:
    with _LOCK, connect() as conn:
        conn.execute("UPDATE quarantine SET restored_at=? WHERE id=?", (now(), qid))


def mark_deleted(qid: int) -> None:
    with _LOCK, connect() as conn:
        conn.execute("UPDATE quarantine SET deleted_at=? WHERE id=?", (now(), qid))


def counts() -> dict:
    with connect() as conn:
        def one(sql: str, *p) -> int:
            return int(conn.execute(sql, p).fetchone()[0])
        return {
            "open_findings": one(
                "SELECT COUNT(*) FROM findings f LEFT JOIN verdicts v"
                " ON v.sha256=f.sha256 WHERE v.verdict IS NULL"),
            "malicious": one("SELECT COUNT(*) FROM verdicts WHERE verdict='malicious'"),
            "unknown": one("SELECT COUNT(*) FROM verdicts WHERE verdict='unknown'"),
            "safe": one("SELECT COUNT(*) FROM verdicts WHERE verdict='safe'"),
            "quarantined": one(
                "SELECT COUNT(*) FROM quarantine WHERE restored_at IS NULL"
                " AND deleted_at IS NULL"),
        }
