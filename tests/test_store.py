"""Unit tests for sentry.store -- schema, migrations, upserts, verdicts, counts."""
from __future__ import annotations

import json
import sqlite3
import unittest
from unittest import mock

from sentry import config, store
from tests.support import TempEnvMixin

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64

T1 = "2026-01-01T00:00:00+00:00"
T2 = "2026-02-02T12:30:00+00:00"
T3 = "2026-03-03T23:59:59+00:00"


class StoreTestCase(TempEnvMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        store.init_db()

    def raw(self) -> sqlite3.Connection:
        conn = sqlite3.connect(config.DB_PATH)
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        return conn

    def finding(self, *, sha=SHA_A, path=None, score=50, severity="medium",
                size=1234, reasons=("because",), mtime="2026-01-01T00:00:00+00:00"):
        return {"sha256": sha, "path": path or str(self.sandbox / "f.exe"),
                "size": size, "mtime": mtime, "score": score,
                "severity": severity, "reasons": list(reasons)}

    def at(self, timestamp: str):
        """Freeze store.now() for the duration of a `with` block."""
        return mock.patch.object(store, "now", return_value=timestamp)


# ==========================================================================
# init_db / migrations
# ==========================================================================

class TestInitDb(TempEnvMixin, unittest.TestCase):

    def tables(self) -> set[str]:
        conn = sqlite3.connect(config.DB_PATH)
        try:
            return {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()

    def columns(self, table: str) -> set[str]:
        conn = sqlite3.connect(config.DB_PATH)
        try:
            return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        finally:
            conn.close()

    def test_creates_every_table(self):
        store.init_db()
        self.assertLessEqual({"findings", "verdicts", "quarantine", "scans",
                              "events"}, self.tables())

    def test_creates_the_findings_sha_index(self):
        store.init_db()
        conn = sqlite3.connect(config.DB_PATH)
        self.addCleanup(conn.close)
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertIn("idx_findings_sha", names)

    def test_is_idempotent_across_three_runs(self):
        store.init_db()
        store.init_db()
        store.init_db()
        self.assertLessEqual({"findings", "verdicts", "quarantine", "scans",
                              "events"}, self.tables())
        self.assertIn("original_mode", self.columns("quarantine"))

    def test_three_runs_preserve_existing_rows(self):
        store.init_db()
        sid = store.start_scan(["/tmp"], "manual")
        store.set_verdict(SHA_A, "malicious")
        store.init_db()
        store.init_db()
        self.assertEqual(store.get_verdict(SHA_A), "malicious")
        self.assertEqual(len(store.scan_history()), 1)
        self.assertEqual(store.scan_history()[0]["id"], sid)

    def test_unique_constraint_on_sha_and_path_exists(self):
        store.init_db()
        conn = sqlite3.connect(config.DB_PATH)
        self.addCleanup(conn.close)
        sql = conn.execute("SELECT sql FROM sqlite_master WHERE name='findings'"
                           ).fetchone()[0]
        self.assertIn("UNIQUE(sha256, path)", sql)

    # ---- migration -----------------------------------------------------

    PRE_MIGRATION_QUARANTINE = """
        CREATE TABLE quarantine (
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
    """

    def _make_pre_migration_db(self) -> None:
        """Recreate a database from before the original_mode column existed."""
        conn = sqlite3.connect(config.DB_PATH)
        try:
            conn.executescript(self.PRE_MIGRATION_QUARANTINE)
            conn.execute(
                "INSERT INTO quarantine (sha256, original_path, quarantine_path,"
                " size, verdict, reasons, quarantined_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (SHA_A, "/old/path/thing.exe", "/quar/thing.quar", 99,
                 "malicious", json.dumps(["legacy row"]), T1))
            conn.commit()
        finally:
            conn.close()

    def test_legacy_db_lacks_the_column_before_migration(self):
        self._make_pre_migration_db()
        self.assertNotIn("original_mode", self.columns("quarantine"))

    def test_migration_adds_original_mode_to_a_legacy_db(self):
        self._make_pre_migration_db()
        store.init_db()
        self.assertIn("original_mode", self.columns("quarantine"))

    def test_migration_preserves_the_legacy_row_with_a_null_mode(self):
        self._make_pre_migration_db()
        store.init_db()
        entry = store.get_quarantine_entry(1)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["original_path"], "/old/path/thing.exe")
        self.assertEqual(entry["reasons"], ["legacy row"])
        self.assertIsNone(entry["original_mode"])

    def test_migrated_db_accepts_new_rows_carrying_a_mode(self):
        self._make_pre_migration_db()
        store.init_db()
        qid = store.record_quarantine(
            sha256=SHA_B, original_path="/new/x.exe",
            quarantine_path="/quar/x.quar", size=1, verdict="unknown",
            reasons=[], original_mode=0o644)
        self.assertEqual(store.get_quarantine_entry(qid)["original_mode"], 0o644)

    def test_migration_runs_only_once(self):
        self._make_pre_migration_db()
        store.init_db()
        store.init_db()
        store.init_db()
        cols = [c for c in self.columns("quarantine") if c == "original_mode"]
        self.assertEqual(len(cols), 1)

    def test_every_declared_migration_column_is_present_after_init(self):
        store.init_db()
        for table, column, _ddl in store.MIGRATIONS:
            self.assertIn(column, self.columns(table), f"{table}.{column}")


# ==========================================================================
# findings upsert
# ==========================================================================

class TestUpsertFinding(StoreTestCase):

    def rows(self) -> list[sqlite3.Row]:
        return self.raw().execute("SELECT * FROM findings ORDER BY id").fetchall()

    def test_inserts_one_row_with_split_out_directory_and_filename(self):
        path = str(self.sandbox / "sub" / "payload.exe")
        store.upsert_finding(self.finding(path=path), scan_id=7)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["path"], path)
        self.assertEqual(rows[0]["filename"], "payload.exe")
        self.assertEqual(rows[0]["directory"], str(self.sandbox / "sub"))
        self.assertEqual(rows[0]["scan_id"], 7)
        self.assertEqual(json.loads(rows[0]["reasons"]), ["because"])

    def test_same_sha_and_path_twice_updates_rather_than_duplicating(self):
        store.upsert_finding(self.finding(score=30, severity="low"), scan_id=1)
        store.upsert_finding(self.finding(score=88, severity="high",
                                          size=999, reasons=["worse now"]),
                             scan_id=2)
        rows = self.rows()
        self.assertEqual(len(rows), 1, "upsert must not create a second row")
        self.assertEqual(rows[0]["score"], 88)
        self.assertEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["size"], 999)
        self.assertEqual(json.loads(rows[0]["reasons"]), ["worse now"])
        self.assertEqual(rows[0]["scan_id"], 2)

    def test_upsert_keeps_the_same_primary_key(self):
        store.upsert_finding(self.finding(), scan_id=1)
        first_id = self.rows()[0]["id"]
        store.upsert_finding(self.finding(score=90), scan_id=2)
        self.assertEqual(self.rows()[0]["id"], first_id)

    def test_same_sha_at_two_paths_creates_two_rows(self):
        p1 = str(self.sandbox / "one.exe")
        p2 = str(self.sandbox / "two.exe")
        store.upsert_finding(self.finding(path=p1), scan_id=1)
        store.upsert_finding(self.finding(path=p2), scan_id=1)
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["path"] for r in rows}, {p1, p2})
        self.assertEqual({r["sha256"] for r in rows}, {SHA_A})

    def test_different_sha_at_the_same_path_creates_two_rows(self):
        path = str(self.sandbox / "same.exe")
        store.upsert_finding(self.finding(sha=SHA_A, path=path), scan_id=1)
        store.upsert_finding(self.finding(sha=SHA_B, path=path), scan_id=1)
        self.assertEqual(len(self.rows()), 2)

    def test_first_seen_is_preserved_while_last_seen_advances(self):
        with self.at(T1):
            store.upsert_finding(self.finding(score=30), scan_id=1)
        with self.at(T2):
            store.upsert_finding(self.finding(score=40), scan_id=2)
        with self.at(T3):
            store.upsert_finding(self.finding(score=50), scan_id=3)
        row = self.rows()[0]
        self.assertEqual(row["first_seen"], T1,
                         "first_seen must record the original sighting")
        self.assertEqual(row["last_seen"], T3,
                         "last_seen must advance on every re-sighting")

    def test_first_seen_of_a_second_path_is_its_own(self):
        with self.at(T1):
            store.upsert_finding(self.finding(path=str(self.sandbox / "a.exe")),
                                 scan_id=1)
        with self.at(T2):
            store.upsert_finding(self.finding(path=str(self.sandbox / "b.exe")),
                                 scan_id=2)
        seen = {r["filename"]: r["first_seen"] for r in self.rows()}
        self.assertEqual(seen, {"a.exe": T1, "b.exe": T2})

    def test_missing_mtime_is_stored_as_null(self):
        f = self.finding()
        del f["mtime"]
        store.upsert_finding(f, scan_id=1)
        self.assertIsNone(self.rows()[0]["mtime"])

    def test_missing_reasons_defaults_to_an_empty_json_list(self):
        f = self.finding()
        del f["reasons"]
        store.upsert_finding(f, scan_id=1)
        self.assertEqual(json.loads(self.rows()[0]["reasons"]), [])

    def test_reason_list_ordering_survives_the_round_trip(self):
        order = ["first", "second", "third"]
        store.upsert_finding(self.finding(reasons=order), scan_id=1)
        self.assertEqual(store.get_findings()[0]["reasons"], order)


class TestGetFindings(StoreTestCase):

    def seed(self):
        self.p_high = str(self.sandbox / "high.exe")
        self.p_mid = str(self.sandbox / "mid.exe")
        self.p_low = str(self.sandbox / "low.exe")
        store.upsert_finding(self.finding(sha=SHA_A, path=self.p_high,
                                          score=90, severity="high"), scan_id=1)
        store.upsert_finding(self.finding(sha=SHA_B, path=self.p_mid,
                                          score=50, severity="medium"), scan_id=1)
        store.upsert_finding(self.finding(sha=SHA_C, path=self.p_low,
                                          score=26, severity="low"), scan_id=2)

    def test_sorted_by_score_descending(self):
        self.seed()
        self.assertEqual([f["score"] for f in store.get_findings()], [90, 50, 26])

    def test_min_score_filter_is_inclusive(self):
        self.seed()
        self.assertEqual([f["score"] for f in store.get_findings(min_score=50)],
                         [90, 50])
        self.assertEqual([f["score"] for f in store.get_findings(min_score=51)],
                         [90])

    def test_scan_id_filter(self):
        self.seed()
        self.assertEqual([f["score"] for f in store.get_findings(scan_id=1)],
                         [90, 50])
        self.assertEqual([f["score"] for f in store.get_findings(scan_id=2)], [26])
        self.assertEqual(store.get_findings(scan_id=99), [])

    def test_safe_verdicts_are_hidden_by_default(self):
        self.seed()
        store.set_verdict(SHA_A, "safe")
        self.assertEqual([f["score"] for f in store.get_findings()], [50, 26])

    def test_safe_verdicts_are_shown_when_requested(self):
        self.seed()
        store.set_verdict(SHA_A, "safe")
        self.assertEqual([f["score"] for f in
                          store.get_findings(include_safe=True)], [90, 50, 26])

    def test_malicious_and_unknown_verdicts_stay_visible(self):
        self.seed()
        store.set_verdict(SHA_A, "malicious")
        store.set_verdict(SHA_B, "unknown")
        got = {f["sha256"]: f["verdict"] for f in store.get_findings()}
        self.assertEqual(got[SHA_A], "malicious")
        self.assertEqual(got[SHA_B], "unknown")
        self.assertIsNone(got[SHA_C])

    def test_exists_flag_reflects_the_filesystem(self):
        real = self.write("real.exe", b"MZ")
        store.upsert_finding(self.finding(path=str(real)), scan_id=1)
        store.upsert_finding(self.finding(sha=SHA_B,
                                          path=str(self.sandbox / "gone.exe")),
                             scan_id=1)
        by_name = {f["filename"]: f["exists"] for f in store.get_findings()}
        self.assertTrue(by_name["real.exe"])
        self.assertFalse(by_name["gone.exe"])

    def test_active_quarantine_row_is_joined_in(self):
        self.seed()
        qid = store.record_quarantine(sha256=SHA_A, original_path=self.p_high,
                                      quarantine_path="/q/a.quar", size=1,
                                      verdict="malicious", reasons=[])
        row = next(f for f in store.get_findings() if f["sha256"] == SHA_A)
        self.assertEqual(row["quarantine_id"], qid)
        self.assertIsNotNone(row["quarantined_at"])

    def test_restored_quarantine_row_is_not_joined_in(self):
        self.seed()
        qid = store.record_quarantine(sha256=SHA_A, original_path=self.p_high,
                                      quarantine_path="/q/a.quar", size=1,
                                      verdict="malicious", reasons=[])
        store.mark_restored(qid)
        row = next(f for f in store.get_findings() if f["sha256"] == SHA_A)
        self.assertIsNone(row["quarantine_id"])

    def test_quarantine_join_requires_a_matching_original_path(self):
        self.seed()
        store.record_quarantine(sha256=SHA_A, original_path="/somewhere/else",
                                quarantine_path="/q/a.quar", size=1,
                                verdict="malicious", reasons=[])
        row = next(f for f in store.get_findings() if f["sha256"] == SHA_A)
        self.assertIsNone(row["quarantine_id"])

    def test_empty_database_returns_an_empty_list(self):
        self.assertEqual(store.get_findings(), [])


class TestGetAndDeleteFinding(StoreTestCase):

    def test_get_finding_by_id(self):
        store.upsert_finding(self.finding(reasons=["r1", "r2"]), scan_id=1)
        fid = store.get_findings()[0]["id"]
        got = store.get_finding(fid)
        self.assertEqual(got["sha256"], SHA_A)
        self.assertEqual(got["reasons"], ["r1", "r2"])

    def test_get_finding_returns_none_for_an_unknown_id(self):
        self.assertIsNone(store.get_finding(4242))

    def test_delete_finding_removes_exactly_one_row(self):
        store.upsert_finding(self.finding(path=str(self.sandbox / "a.exe")),
                             scan_id=1)
        store.upsert_finding(self.finding(sha=SHA_B,
                                          path=str(self.sandbox / "b.exe")),
                             scan_id=1)
        fid = store.get_findings()[0]["id"]
        store.delete_finding(fid)
        self.assertIsNone(store.get_finding(fid))
        self.assertEqual(len(store.get_findings()), 1)

    def test_delete_finding_on_an_unknown_id_is_a_no_op(self):
        store.upsert_finding(self.finding(), scan_id=1)
        store.delete_finding(9999)
        self.assertEqual(len(store.get_findings()), 1)


# ==========================================================================
# verdicts
# ==========================================================================

class TestVerdicts(StoreTestCase):

    def test_set_then_get(self):
        for verdict in sorted(store.VALID_VERDICTS):
            with self.subTest(verdict=verdict):
                store.set_verdict(SHA_A, verdict)
                self.assertEqual(store.get_verdict(SHA_A), verdict)

    def test_get_verdict_is_none_when_unmarked(self):
        self.assertIsNone(store.get_verdict(SHA_A))

    def test_set_verdict_stores_path_and_note(self):
        store.set_verdict(SHA_A, "unknown", path="/x/y.exe", note="looks odd")
        row = next(v for v in store.verdict_list() if v["sha256"] == SHA_A)
        self.assertEqual(row["path"], "/x/y.exe")
        self.assertEqual(row["note"], "looks odd")
        self.assertEqual(row["verdict"], "unknown")

    def test_set_verdict_upserts_on_the_same_sha(self):
        store.set_verdict(SHA_A, "unknown", note="first")
        store.set_verdict(SHA_A, "malicious", note="second")
        rows = [v for v in store.verdict_list() if v["sha256"] == SHA_A]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "malicious")
        self.assertEqual(rows[0]["note"], "second")

    def test_marked_at_advances_on_re_marking(self):
        with self.at(T1):
            store.set_verdict(SHA_A, "unknown")
        with self.at(T2):
            store.set_verdict(SHA_A, "malicious")
        row = next(v for v in store.verdict_list() if v["sha256"] == SHA_A)
        self.assertEqual(row["marked_at"], T2)

    def test_invalid_verdicts_are_rejected_with_a_named_error(self):
        for bad in ("bad", "", "SAFE", "Malicious", "clear", "none", "unknown ",
                    "malicious;drop table"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as ctx:
                    store.set_verdict(SHA_A, bad)
                self.assertIn("invalid verdict", str(ctx.exception))
                self.assertIn(repr(bad), str(ctx.exception))

    def test_a_rejected_verdict_writes_nothing(self):
        with self.assertRaises(ValueError):
            store.set_verdict(SHA_A, "nonsense")
        self.assertIsNone(store.get_verdict(SHA_A))
        self.assertEqual(store.verdict_list(), [])

    def test_valid_verdict_set_is_exactly_the_documented_three(self):
        self.assertEqual(store.VALID_VERDICTS, {"malicious", "unknown", "safe"})

    def test_clear_verdict_removes_the_row(self):
        store.set_verdict(SHA_A, "malicious")
        store.clear_verdict(SHA_A)
        self.assertIsNone(store.get_verdict(SHA_A))
        self.assertEqual(store.verdict_list(), [])

    def test_clear_verdict_on_an_unmarked_sha_is_a_no_op(self):
        store.set_verdict(SHA_B, "safe")
        store.clear_verdict(SHA_A)
        self.assertEqual(store.get_verdict(SHA_B), "safe")

    def test_clear_verdict_only_touches_the_named_sha(self):
        store.set_verdict(SHA_A, "malicious")
        store.set_verdict(SHA_B, "safe")
        store.clear_verdict(SHA_A)
        self.assertIsNone(store.get_verdict(SHA_A))
        self.assertEqual(store.get_verdict(SHA_B), "safe")

    def test_allowlist_contains_only_safe_hashes(self):
        store.set_verdict(SHA_A, "safe")
        store.set_verdict(SHA_B, "malicious")
        store.set_verdict(SHA_C, "unknown")
        self.assertEqual(store.allowlist(), {SHA_A})

    def test_allowlist_is_empty_when_nothing_is_marked_safe(self):
        store.set_verdict(SHA_B, "malicious")
        self.assertEqual(store.allowlist(), set())

    def test_allowlist_shrinks_when_a_safe_verdict_is_changed(self):
        store.set_verdict(SHA_A, "safe")
        self.assertEqual(store.allowlist(), {SHA_A})
        store.set_verdict(SHA_A, "malicious")
        self.assertEqual(store.allowlist(), set())

    def test_allowlist_shrinks_when_a_safe_verdict_is_cleared(self):
        store.set_verdict(SHA_A, "safe")
        store.clear_verdict(SHA_A)
        self.assertEqual(store.allowlist(), set())

    def test_verdict_list_is_newest_first(self):
        with self.at(T1):
            store.set_verdict(SHA_A, "safe")
        with self.at(T3):
            store.set_verdict(SHA_B, "malicious")
        with self.at(T2):
            store.set_verdict(SHA_C, "unknown")
        self.assertEqual([v["sha256"] for v in store.verdict_list()],
                         [SHA_B, SHA_C, SHA_A])

    def test_setting_a_verdict_logs_an_event(self):
        store.set_verdict(SHA_A, "malicious", path="/x/y.exe")
        rows = self.raw().execute(
            "SELECT kind, detail FROM events ORDER BY id").fetchall()
        self.assertEqual(rows[-1]["kind"], "verdict")
        self.assertIn("malicious", rows[-1]["detail"])
        self.assertIn(SHA_A[:16], rows[-1]["detail"])
        self.assertIn("/x/y.exe", rows[-1]["detail"])


# ==========================================================================
# counts
# ==========================================================================

class TestCounts(StoreTestCase):

    def test_all_zero_on_a_fresh_database(self):
        self.assertEqual(store.counts(), {"open_findings": 0, "malicious": 0,
                                          "unknown": 0, "safe": 0,
                                          "quarantined": 0})

    def _seed_fixture(self) -> int:
        # 4 findings; A marked malicious, B marked safe, C+D unmarked.
        for i, sha in enumerate((SHA_A, SHA_B, SHA_C, "d" * 64)):
            store.upsert_finding(self.finding(
                sha=sha, path=str(self.sandbox / f"f{i}.exe")), scan_id=1)
        store.set_verdict(SHA_A, "malicious")
        store.set_verdict(SHA_B, "safe")
        store.set_verdict("e" * 64, "unknown")        # verdict with no finding
        qid = store.record_quarantine(sha256=SHA_A,
                                      original_path=str(self.sandbox / "f0.exe"),
                                      quarantine_path="/q/a.quar", size=5,
                                      verdict="malicious", reasons=[])
        return qid

    def test_known_fixture_state(self):
        self._seed_fixture()
        self.assertEqual(store.counts(), {"open_findings": 2, "malicious": 1,
                                          "unknown": 1, "safe": 1,
                                          "quarantined": 1})

    def test_restoring_decrements_the_quarantined_count(self):
        store.mark_restored(self._seed_fixture())
        self.assertEqual(store.counts()["quarantined"], 0)

    def test_deleting_decrements_the_quarantined_count(self):
        store.mark_deleted(self._seed_fixture())
        self.assertEqual(store.counts()["quarantined"], 0)

    def test_open_findings_counts_rows_not_hashes(self):
        # Same hash at two paths = two open findings awaiting review.
        store.upsert_finding(self.finding(path=str(self.sandbox / "a.exe")),
                             scan_id=1)
        store.upsert_finding(self.finding(path=str(self.sandbox / "b.exe")),
                             scan_id=1)
        self.assertEqual(store.counts()["open_findings"], 2)

    def test_marking_one_hash_closes_every_finding_for_that_hash(self):
        store.upsert_finding(self.finding(path=str(self.sandbox / "a.exe")),
                             scan_id=1)
        store.upsert_finding(self.finding(path=str(self.sandbox / "b.exe")),
                             scan_id=1)
        store.set_verdict(SHA_A, "unknown")
        self.assertEqual(store.counts()["open_findings"], 0)


# ==========================================================================
# scans / events
# ==========================================================================

class TestScans(StoreTestCase):

    def test_start_scan_returns_increasing_ids(self):
        a = store.start_scan(["/tmp"], "manual")
        b = store.start_scan(["/tmp"], "scheduled")
        self.assertEqual(b, a + 1)

    def test_start_scan_records_paths_as_json_and_the_trigger(self):
        sid = store.start_scan(["/a", "/b"], "scheduled")
        row = self.raw().execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        self.assertEqual(json.loads(row["paths"]), ["/a", "/b"])
        self.assertEqual(row["trigger"], "scheduled")
        self.assertIsNone(row["finished_at"])

    def test_start_scan_accepts_any_iterable(self):
        sid = store.start_scan(iter(["/a", "/b"]), "manual")
        row = self.raw().execute("SELECT paths FROM scans WHERE id=?",
                                 (sid,)).fetchone()
        self.assertEqual(json.loads(row["paths"]), ["/a", "/b"])

    def test_finish_scan_writes_every_statistic(self):
        sid = store.start_scan(["/tmp"], "manual")
        store.finish_scan(sid, files=12, nbytes=345, findings=6, errors=1,
                          report_path="/r/x.html")
        row = self.raw().execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        self.assertEqual(row["files_scanned"], 12)
        self.assertEqual(row["bytes_scanned"], 345)
        self.assertEqual(row["findings_count"], 6)
        self.assertEqual(row["errors"], 1)
        self.assertEqual(row["report_path"], "/r/x.html")
        self.assertIsNotNone(row["finished_at"])

    def test_last_scan_ignores_unfinished_scans(self):
        sid = store.start_scan(["/tmp"], "manual")
        store.finish_scan(sid, files=1, nbytes=1, findings=0, errors=0)
        store.start_scan(["/tmp"], "manual")        # still running
        self.assertEqual(store.last_scan()["id"], sid)

    def test_last_scan_is_none_when_nothing_has_finished(self):
        store.start_scan(["/tmp"], "manual")
        self.assertIsNone(store.last_scan())

    def test_scan_history_is_newest_first_and_respects_the_limit(self):
        ids = [store.start_scan(["/tmp"], "manual") for _ in range(5)]
        self.assertEqual([s["id"] for s in store.scan_history()],
                         list(reversed(ids)))
        self.assertEqual([s["id"] for s in store.scan_history(limit=2)],
                         list(reversed(ids))[:2])

    def test_log_event_appends_rows(self):
        store.log_event("scan", "one")
        store.log_event("scan", "two")
        rows = self.raw().execute(
            "SELECT kind, detail FROM events ORDER BY id").fetchall()
        self.assertEqual([(r["kind"], r["detail"]) for r in rows],
                         [("scan", "one"), ("scan", "two")])

    def test_log_event_detail_is_optional(self):
        store.log_event("boot")
        row = self.raw().execute("SELECT detail FROM events").fetchone()
        self.assertEqual(row["detail"], "")

    def test_now_is_iso8601_utc_to_the_second(self):
        value = store.now()
        self.assertRegex(value, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")


# ==========================================================================
# quarantine manifest state transitions
# ==========================================================================

class TestQuarantineRecords(StoreTestCase):

    def record(self, sha=SHA_A, path="/orig/thing.exe", **kw):
        params = {"sha256": sha, "original_path": path,
                  "quarantine_path": f"/q/{sha[:8]}.quar", "size": 4096,
                  "verdict": "malicious", "reasons": ["r1", "r2"]}
        params.update(kw)
        return store.record_quarantine(**params)

    def test_record_returns_an_id_and_stores_every_field(self):
        qid = self.record(original_mode=0o750)
        entry = store.get_quarantine_entry(qid)
        self.assertEqual(entry["sha256"], SHA_A)
        self.assertEqual(entry["original_path"], "/orig/thing.exe")
        self.assertEqual(entry["quarantine_path"], "/q/aaaaaaaa.quar")
        self.assertEqual(entry["size"], 4096)
        self.assertEqual(entry["verdict"], "malicious")
        self.assertEqual(entry["reasons"], ["r1", "r2"])
        self.assertEqual(entry["original_mode"], 0o750)

    def test_a_new_record_is_active(self):
        qid = self.record()
        entry = store.get_quarantine_entry(qid)
        self.assertIsNone(entry["restored_at"])
        self.assertIsNone(entry["deleted_at"])
        self.assertIsNotNone(entry["quarantined_at"])
        self.assertIn(qid, [e["id"] for e in store.quarantine_list()])

    def test_get_entry_returns_none_for_an_unknown_id(self):
        self.assertIsNone(store.get_quarantine_entry(1234))

    def test_active_to_restored_transition(self):
        qid = self.record()
        with self.at(T2):
            store.mark_restored(qid)
        entry = store.get_quarantine_entry(qid)
        self.assertEqual(entry["restored_at"], T2)
        self.assertIsNone(entry["deleted_at"])
        self.assertEqual(store.quarantine_list(active_only=True), [])
        self.assertEqual(len(store.quarantine_list(active_only=False)), 1)

    def test_active_to_deleted_transition(self):
        qid = self.record()
        with self.at(T3):
            store.mark_deleted(qid)
        entry = store.get_quarantine_entry(qid)
        self.assertEqual(entry["deleted_at"], T3)
        self.assertIsNone(entry["restored_at"])
        self.assertEqual(store.quarantine_list(active_only=True), [])

    def test_marking_restored_then_deleted_records_both_timestamps(self):
        qid = self.record()
        with self.at(T2):
            store.mark_restored(qid)
        with self.at(T3):
            store.mark_deleted(qid)
        entry = store.get_quarantine_entry(qid)
        self.assertEqual(entry["restored_at"], T2)
        self.assertEqual(entry["deleted_at"], T3)

    def test_mark_helpers_on_an_unknown_id_are_no_ops(self):
        qid = self.record()
        store.mark_restored(999)
        store.mark_deleted(999)
        entry = store.get_quarantine_entry(qid)
        self.assertIsNone(entry["restored_at"])
        self.assertIsNone(entry["deleted_at"])

    def test_marks_only_affect_the_named_entry(self):
        a = self.record(sha=SHA_A)
        b = self.record(sha=SHA_B)
        store.mark_restored(a)
        self.assertIsNone(store.get_quarantine_entry(b)["restored_at"])

    def test_quarantine_list_is_newest_first(self):
        with self.at(T1):
            a = self.record(sha=SHA_A)
        with self.at(T3):
            b = self.record(sha=SHA_B)
        with self.at(T2):
            c = self.record(sha=SHA_C)
        self.assertEqual([e["id"] for e in store.quarantine_list()], [b, c, a])

    def test_same_file_can_be_quarantined_twice_over_its_lifetime(self):
        a = self.record()
        store.mark_restored(a)
        b = self.record()
        self.assertNotEqual(a, b)
        self.assertEqual([e["id"] for e in store.quarantine_list(active_only=True)],
                         [b])

    def test_reasons_default_to_an_empty_list(self):
        qid = self.record(reasons=[])
        self.assertEqual(store.get_quarantine_entry(qid)["reasons"], [])
        self.assertEqual(store.quarantine_list()[0]["reasons"], [])

    def test_original_mode_defaults_to_null(self):
        qid = self.record()
        self.assertIsNone(store.get_quarantine_entry(qid)["original_mode"])


if __name__ == "__main__":
    unittest.main()
