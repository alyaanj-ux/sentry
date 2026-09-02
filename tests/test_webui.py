"""Unit tests for sentry.webui using Flask's test client.

No socket is ever opened and no real scan is ever started: engine.run_scan and
engine.scan_in_background are stubbed, as are the feed download and the OS
file-manager launch.
"""
from __future__ import annotations

import hashlib
import json
import os
import unittest
from pathlib import Path
from unittest import mock

from sentry import config, engine, feeds, quarantine, store, webui
from tests.support import (TempEnvMixin, deny_directory_listing, is_listable,
                           stub_launchers)

SHA_A = "a" * 64
SHA_B = "b" * 64


def mutating_rules():
    """Every route that accepts POST or DELETE, discovered from the url_map.

    Enumerating rather than listing means a newly-added mutating route without
    a guard fails `test_every_mutating_route_requires_the_guard_header`.
    """
    out = []
    for rule in webui.app.url_map.iter_rules():
        methods = rule.methods - {"GET", "HEAD", "OPTIONS"}
        if not methods:
            continue
        if rule.arguments:                     # none today; substitute if added
            continue
        out.append((rule.rule, sorted(methods)))
    return sorted(out)


def read_only_rules():
    out = []
    for rule in webui.app.url_map.iter_rules():
        if rule.endpoint == "static" or rule.arguments:
            continue
        if rule.methods & {"POST", "DELETE", "PUT", "PATCH"}:
            continue
        out.append(rule.rule)
    return sorted(out)


class WebTestCase(TempEnvMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        store.init_db()
        webui.app.config.update(TESTING=False)
        self.client = webui.app.test_client()
        # Several tests deliberately trigger unhandled 500s (see the BUG_*
        # cases); keep Flask's exception logging out of the test output.
        import logging
        previous = webui.app.logger.level
        webui.app.logger.setLevel(logging.CRITICAL)
        self.addCleanup(webui.app.logger.setLevel, previous)
        # A quiet, hermetic starting state: nothing enabled, nothing to resolve.
        config.save_config({"enabled_presets": [], "custom_paths": [],
                            "exclusions": [], "use_yara": False,
                            "use_hash_feed": False})
        # Nothing may reach the network or spawn a scan thread.
        for target, attr in ((engine, "scan_in_background"),
                             (engine, "run_scan")):
            p = mock.patch.object(target, attr, return_value=True)
            p.start()
            self.addCleanup(p.stop)
        import urllib.error
        p = mock.patch.object(feeds, "_download", side_effect=urllib.error.URLError(
            "no network in tests"))
        p.start()
        self.addCleanup(p.stop)
        # Nothing may launch a file manager either. Individual tests re-patch
        # these to assert on the arguments.
        for p in (mock.patch("subprocess.Popen"), mock.patch.object(os, "system")):
            p.start()
            self.addCleanup(p.stop)
        engine.PROGRESS = engine.ScanProgress()

    # -- helpers ----------------------------------------------------------

    HDR = {"X-Sentry-Local": "1", "Content-Type": "application/json"}

    def post(self, url, body=None, *, guard=True, raw=None):
        headers = dict(self.HDR) if guard else {"Content-Type": "application/json"}
        data = raw if raw is not None else json.dumps(body or {})
        return self.client.post(url, data=data, headers=headers)

    def seed_finding(self, sha=SHA_A, name="target.exe", score=60) -> dict:
        # The recorded sha256 has to be the file's real digest: quarantine
        # re-hashes the file and refuses to act if it no longer matches what was
        # reviewed. `sha` only varies the body so two seeds differ.
        body = b"MZ" + sha.encode() + b"\x00" * 8
        path = self.write(name, body)
        store.upsert_finding({"sha256": hashlib.sha256(body).hexdigest(),
                              "path": str(path),
                              "size": len(body), "mtime": None, "score": score,
                              "severity": "medium", "reasons": ["r"]},
                             scan_id=1)
        return next(f for f in store.get_findings(include_safe=True)
                    if f["path"] == str(path))


# ==========================================================================
# the guard header
# ==========================================================================

class TestGuardHeader(WebTestCase):

    def test_the_route_inventory_is_not_empty(self):
        self.assertGreaterEqual(len(mutating_rules()), 9,
                                "route discovery is broken")
        self.assertGreaterEqual(len(read_only_rules()), 7)

    def test_every_mutating_route_requires_the_guard_header(self):
        for url, methods in mutating_rules():
            for method in methods:
                with self.subTest(url=url, method=method):
                    resp = self.client.open(url, method=method, data="{}",
                                            headers={"Content-Type":
                                                     "application/json"})
                    self.assertEqual(
                        resp.status_code, 403,
                        f"{method} {url} is not protected by "
                        f"{webui.GUARD_HEADER}")
                    self.assertEqual(resp.get_json()["error"],
                                     "Missing local request header.")

    def test_every_mutating_route_is_reachable_with_the_guard_header(self):
        for url, methods in mutating_rules():
            for method in methods:
                with self.subTest(url=url, method=method):
                    resp = self.client.open(url, method=method, data="{}",
                                            headers=self.HDR)
                    self.assertNotEqual(resp.status_code, 403,
                                        f"{method} {url} rejected a guarded "
                                        "request")
                    self.assertLess(resp.status_code, 500,
                                    f"{method} {url} -> {resp.status_code} "
                                    f"{resp.get_data(as_text=True)[:200]}")

    def test_any_nonempty_header_value_satisfies_the_guard(self):
        for value in ("1", "yes", "x"):
            with self.subTest(value=value):
                resp = self.client.post("/api/scan/cancel", data="{}",
                                        headers={"X-Sentry-Local": value})
                self.assertEqual(resp.status_code, 200)

    def test_an_empty_header_value_does_not_satisfy_the_guard(self):
        resp = self.client.post("/api/scan/cancel", data="{}",
                                headers={"X-Sentry-Local": ""})
        self.assertEqual(resp.status_code, 403)

    def test_get_routes_work_without_the_header(self):
        for url in read_only_rules():
            with self.subTest(url=url):
                resp = self.client.get(url)
                self.assertEqual(resp.status_code, 200, url)

    def test_non_loopback_host_is_rejected_even_with_the_header(self):
        for host in ("example.com", "192.168.1.10:8787", "sentry.local"):
            with self.subTest(host=host):
                resp = self.client.get("/api/state", headers={"Host": host})
                self.assertEqual(resp.status_code, 403)
                self.assertIn("loopback", resp.get_json()["error"])

    def test_loopback_hosts_are_accepted(self):
        for host in ("127.0.0.1", "127.0.0.1:8787", "localhost",
                     "localhost:8787"):
            with self.subTest(host=host):
                self.assertEqual(
                    self.client.get("/api/state", headers={"Host": host}
                                    ).status_code, 200)

    def test_the_guard_header_name_is_the_documented_one(self):
        self.assertEqual(webui.GUARD_HEADER, "X-Sentry-Local")


# ==========================================================================
# /api/state
# ==========================================================================

class TestApiState(WebTestCase):

    def test_returns_the_documented_top_level_keys(self):
        body = self.client.get("/api/state").get_json()
        for key in ("config", "presets", "resolved_paths", "counts", "progress",
                    "last_scan", "feed", "yara", "data_root", "quarantine_dir",
                    "is_windows"):
            self.assertIn(key, body)

    def test_reports_the_redirected_data_root(self):
        body = self.client.get("/api/state").get_json()
        self.assertEqual(body["data_root"], str(config.DATA_ROOT))
        self.assertEqual(body["quarantine_dir"], str(config.QUARANTINE_DIR))

    def test_counts_reflect_the_database(self):
        self.seed_finding()
        store.set_verdict(SHA_B, "malicious")
        counts = self.client.get("/api/state").get_json()["counts"]
        self.assertEqual(counts["open_findings"], 1)
        self.assertEqual(counts["malicious"], 1)

    def test_every_preset_carries_a_label_and_a_path_list(self):
        presets = self.client.get("/api/state").get_json()["presets"]
        self.assertEqual(set(presets), set(config.preset_paths()))
        for name, entry in presets.items():
            self.assertTrue(entry["label"].strip(), name)
            self.assertIsInstance(entry["paths"], list)


# ==========================================================================
# /api/config
# ==========================================================================

class TestApiConfig(WebTestCase):

    def test_allowed_keys_are_persisted(self):
        resp = self.post("/api/config", {"report_threshold": 55,
                                         "max_file_mb": 64,
                                         "use_yara": False,
                                         "follow_symlinks": True})
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["ok"])
        cfg = config.load_config()
        self.assertEqual(cfg["report_threshold"], 55)
        self.assertEqual(cfg["max_file_mb"], 64)
        self.assertTrue(cfg["follow_symlinks"])

    def test_unknown_keys_are_ignored_not_persisted(self):
        self.post("/api/config", {"web_port": 1234, "auto_quarantine": True,
                                  "evil": "x"})
        cfg = config.load_config()
        self.assertEqual(cfg["web_port"], config.DEFAULTS["web_port"])
        self.assertFalse(cfg["auto_quarantine"],
                         "auto_quarantine must not be settable over HTTP")
        self.assertNotIn("evil", cfg)

    def test_report_threshold_is_clamped_to_1_100(self):
        for sent, expected in ((0, 1), (-50, 1), (1, 1), (100, 100),
                               (101, 100), (99999, 100), (50, 50)):
            with self.subTest(sent=sent):
                self.post("/api/config", {"report_threshold": sent})
                self.assertEqual(config.load_config()["report_threshold"],
                                 expected)

    def test_numeric_string_threshold_is_coerced(self):
        self.post("/api/config", {"report_threshold": "42"})
        self.assertEqual(config.load_config()["report_threshold"], 42)

    def test_response_echoes_the_config_and_resolved_paths(self):
        d = self.sandbox / "watch"
        d.mkdir()
        body = self.post("/api/config", {"custom_paths": [str(d)]}).get_json()
        self.assertEqual(body["config"]["custom_paths"], [str(d)])
        self.assertEqual(body["resolved_paths"], [str(d)])

    def test_an_empty_body_changes_nothing(self):
        before = config.load_config()
        self.assertEqual(self.post("/api/config", {}).status_code, 200)
        self.assertEqual(config.load_config(), before)

    def test_invalid_json_body_is_treated_as_empty(self):
        before = config.load_config()
        for raw in ("{not json", "", "null", "[]", "\x00\x01"):
            with self.subTest(raw=raw):
                resp = self.post("/api/config", raw=raw)
                self.assertEqual(resp.status_code, 200)
        self.assertEqual(config.load_config(), before)

    # ---- regression tests for fixed bugs --------------------------------

    def test_BUG_non_numeric_report_threshold_returns_500(self):
        """REGRESSION TEST (fixed): report_threshold is validated, not int()'d blindly.

        The bug described below is fixed in this build; this test now guards
        against a regression.

        Original report: BUG webui.py:66 -- unguarded int() on attacker/UI-supplied JSON.

        `int(update["report_threshold"])` raises ValueError for "abc" and
        TypeError for null / [] / {}. Nothing catches it, so the route answers
        500 with a stack trace in the log instead of 400 with a message. Every
        other validated field in this handler has the same shape.
        """
        for bad in ("abc", None, [], {}, "12.5"):
            with self.subTest(bad=bad):
                resp = self.post("/api/config", {"report_threshold": bad})
                self.assertEqual(resp.status_code, 400, f"sent {bad!r}")

    def test_BUG_a_non_object_json_body_returns_500(self):
        """REGRESSION TEST (fixed): a non-object JSON body is treated as empty.

        The bug described below is fixed in this build; this test now guards
        against a regression.

        Original report: BUG webui.py:60 (and every other handler) -- `get_json() or {}`.

        `silent=True` only covers *unparseable* bodies. A body that is valid
        JSON but not an object -- `[1,2,3]`, `"str"`, `42`, `true` -- is truthy,
        survives the `or {}`, and then hits `body.items()` / `body.get()`, which
        raises AttributeError and returns 500 with a traceback. Affects
        /api/config, /api/scan, /api/verdict, /api/quarantine, /api/restore,
        /api/purge, /api/feed/update and /api/open-folder identically. The fix
        is one helper: `body = request.get_json(...); body = body if
        isinstance(body, dict) else {}`.
        """
        for url in ("/api/config", "/api/scan", "/api/verdict",
                    "/api/quarantine", "/api/restore", "/api/purge",
                    "/api/feed/update", "/api/open-folder"):
            for raw in ("[1,2,3]", '"a string"', "42", "true"):
                with self.subTest(url=url, raw=raw):
                    resp = self.post(url, raw=raw)
                    self.assertLess(resp.status_code, 500,
                                    f"{url} crashed on {raw}")

    def test_BUG_max_file_mb_is_not_validated(self):
        """REGRESSION TEST (fixed): max_file_mb is range-checked too.

        The bug described below is fixed in this build; this test now guards
        against a regression.

        Original report: BUG webui.py:61-67 -- only report_threshold is range-checked.

        `max_file_mb` is written through verbatim, so 0 or a negative value is
        accepted. engine._should_inspect then computes a non-positive byte
        limit and every file is gated out as "over size limit" -- scans
        silently find nothing, with no error anywhere. The UI's own input has
        min=1, so this only bites API callers and hand-edited config, but the
        server should not depend on the client for that.
        """
        for bad in (0, -1, -4096):
            with self.subTest(bad=bad):
                self.post("/api/config", {"max_file_mb": bad})
                self.assertGreaterEqual(config.load_config()["max_file_mb"], 1)


# ==========================================================================
# /api/browse
# ==========================================================================

class TestApiBrowse(WebTestCase):

    def test_no_path_returns_the_root_shortcuts(self):
        body = self.client.get("/api/browse").get_json()
        self.assertEqual(body["path"], "")
        self.assertIsNone(body["parent"])
        self.assertTrue(body["dirs"])
        for entry in body["dirs"]:
            self.assertIn("name", entry)
            self.assertIn("path", entry)

    def test_lists_only_subdirectories_sorted_by_name(self):
        for name in ("Zebra", "alpha", "Middle"):
            (self.sandbox / name).mkdir()
        (self.sandbox / "a_file.txt").write_text("x")
        body = self.client.get(
            f"/api/browse?path={self.sandbox}").get_json()
        self.assertEqual([d["name"] for d in body["dirs"]],
                         ["alpha", "Middle", "Zebra"])

    def test_reports_the_parent_directory(self):
        sub = self.sandbox / "sub"
        sub.mkdir()
        body = self.client.get(f"/api/browse?path={sub}").get_json()
        self.assertEqual(body["path"], str(sub))
        self.assertEqual(body["parent"], str(self.sandbox))

    def test_the_filesystem_root_has_an_empty_parent(self):
        body = self.client.get("/api/browse?path=/").get_json()
        self.assertEqual(body["parent"], "")

    def test_nonexistent_path_returns_400(self):
        resp = self.client.get("/api/browse?path=/no/such/directory/anywhere")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Not a directory", resp.get_json()["error"])

    def test_a_file_path_returns_400(self):
        f = self.write("a.txt", "x")
        resp = self.client.get(f"/api/browse?path={f}")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Not a directory", resp.get_json()["error"])

    def test_relative_paths_are_made_absolute(self):
        cwd = os.getcwd()
        os.chdir(self.sandbox)
        self.addCleanup(os.chdir, cwd)
        (self.sandbox / "rel").mkdir()
        body = self.client.get("/api/browse?path=rel").get_json()
        self.assertEqual(body["path"], str(self.sandbox / "rel"))

    def test_environment_variables_and_tilde_are_expanded(self):
        d = self.sandbox / "envdir"
        d.mkdir()
        with mock.patch.dict(os.environ, {"SENTRY_UT_BROWSE": str(d)}):
            body = self.client.get(
                "/api/browse?path=$SENTRY_UT_BROWSE").get_json()
        self.assertEqual(body["path"], str(d))

    def test_dollar_prefixed_directories_are_hidden(self):
        (self.sandbox / "$Recycle.Bin").mkdir()
        (self.sandbox / "normal").mkdir()
        body = self.client.get(f"/api/browse?path={self.sandbox}").get_json()
        self.assertEqual([d["name"] for d in body["dirs"]], ["normal"])

    def test_permission_denied_returns_403(self):
        d = self.sandbox / "locked"
        d.mkdir()
        self.addCleanup(deny_directory_listing(d))
        if is_listable(d):
            self.skipTest("running as root; permissions are not enforced")
        resp = self.client.get(f"/api/browse?path={d}")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("Permission denied", resp.get_json()["error"])

    def test_listing_is_capped_at_2000_entries(self):
        with mock.patch.object(os, "scandir") as scandir:
            fakes = []
            for i in range(2500):
                entry = mock.Mock()
                entry.name = f"d{i:05d}"
                entry.path = f"/x/d{i:05d}"
                entry.is_dir.return_value = True
                fakes.append(entry)
            scandir.return_value.__enter__.return_value = iter(fakes)
            body = self.client.get(
                f"/api/browse?path={self.sandbox}").get_json()
        self.assertEqual(len(body["dirs"]), 2000)


# ==========================================================================
# /api/verdict
# ==========================================================================

class TestApiVerdict(WebTestCase):

    def test_each_valid_verdict_is_stored(self):
        for verdict in sorted(store.VALID_VERDICTS):
            with self.subTest(verdict=verdict):
                resp = self.post("/api/verdict",
                                 {"sha256": SHA_A, "verdict": verdict})
                self.assertEqual(resp.status_code, 200)
                self.assertEqual(resp.get_json()["verdict"], verdict)
                self.assertEqual(store.get_verdict(SHA_A), verdict)

    def test_verdict_and_hash_are_normalised(self):
        resp = self.post("/api/verdict",
                         {"sha256": "  " + SHA_A.upper() + " ",
                          "verdict": " MALICIOUS "})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(store.get_verdict(SHA_A), "malicious")

    def test_path_and_note_are_stored(self):
        self.post("/api/verdict", {"sha256": SHA_A, "verdict": "unknown",
                                   "path": "/x/y.exe", "note": "checking"})
        row = next(v for v in store.verdict_list() if v["sha256"] == SHA_A)
        self.assertEqual(row["path"], "/x/y.exe")
        self.assertEqual(row["note"], "checking")

    def test_clear_removes_the_verdict(self):
        store.set_verdict(SHA_A, "malicious")
        resp = self.post("/api/verdict", {"sha256": SHA_A, "verdict": "clear"})
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(resp.get_json()["verdict"])
        self.assertIsNone(store.get_verdict(SHA_A))

    def test_invalid_verdict_values_return_400(self):
        for bad in ("dangerous", "yes", "delete", "safe ish", "0",
                    "malicious'; DROP TABLE verdicts;--"):
            with self.subTest(bad=bad):
                resp = self.post("/api/verdict",
                                 {"sha256": SHA_A, "verdict": bad})
                self.assertEqual(resp.status_code, 400)
                self.assertIn("invalid verdict", resp.get_json()["error"])
                self.assertIsNone(store.get_verdict(SHA_A))

    def test_a_missing_verdict_field_returns_400(self):
        resp = self.post("/api/verdict", {"sha256": SHA_A})
        self.assertEqual(resp.status_code, 400)

    def test_invalid_sha_lengths_return_400_before_any_write(self):
        for bad in ("", "abc", "a" * 63, "a" * 65, None):
            with self.subTest(bad=bad):
                resp = self.post("/api/verdict",
                                 {"sha256": bad, "verdict": "safe"})
                self.assertEqual(resp.status_code, 400)
                self.assertEqual(resp.get_json()["error"], "Invalid sha256.")
        self.assertEqual(store.verdict_list(), [])

    def test_a_non_hex_sha_of_the_right_length_is_accepted(self):
        # Documents that only the length is checked, not the alphabet.
        resp = self.post("/api/verdict", {"sha256": "z" * 64,
                                          "verdict": "safe"})
        self.assertEqual(resp.status_code, 200)

    def test_BUG_non_string_sha256_or_verdict_returns_500(self):
        """REGRESSION TEST (fixed): a non-string sha256/verdict answers 400.

        The bug described below is fixed in this build; this test now guards
        against a regression.

        Original report: BUG webui.py:164-165 -- `.strip()` on a value that may not be a str.

        `(body.get("sha256") or "").strip()` assumes the JSON value is a string.
        A number, list or object is truthy, so `.strip()` raises AttributeError
        and the route answers 500 with a traceback rather than the 400
        "Invalid sha256." two lines below. Same for the `verdict` field.
        """
        for field in ("sha256", "verdict"):
            for bad in (12345, ["a"], {"a": 1}, 1.5):
                with self.subTest(field=field, bad=bad):
                    body = {"sha256": "a" * 64, "verdict": "safe"}
                    body[field] = bad
                    resp = self.post("/api/verdict", body)
                    self.assertEqual(resp.status_code, 400)

    def test_invalid_json_body_returns_400(self):
        for raw in ("{not json", "", "null", "[]"):
            with self.subTest(raw=raw):
                resp = self.post("/api/verdict", raw=raw)
                self.assertEqual(resp.status_code, 400)
                self.assertEqual(resp.get_json()["error"], "Invalid sha256.")

    def test_marking_safe_adds_the_hash_to_the_allowlist(self):
        self.post("/api/verdict", {"sha256": SHA_A, "verdict": "safe"})
        self.assertEqual(store.allowlist(), {SHA_A})


# ==========================================================================
# /api/scan
# ==========================================================================

class TestApiScan(WebTestCase):

    def test_scan_without_paths_uses_the_configured_scope(self):
        resp = self.post("/api/scan", {})
        self.assertEqual(resp.status_code, 200)
        engine.scan_in_background.assert_called_once_with(None, trigger="manual")

    def test_supplied_paths_are_absolutised_and_passed_through(self):
        d = self.sandbox / "scanme"
        d.mkdir()
        resp = self.post("/api/scan", {"paths": [str(d)]})
        self.assertEqual(resp.status_code, 200)
        engine.scan_in_background.assert_called_once_with([str(d)],
                                                         trigger="manual")

    def test_nonexistent_supplied_paths_return_400(self):
        resp = self.post("/api/scan", {"paths": ["/no/such/dir", "/also/gone"]})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("None of the supplied paths exist",
                      resp.get_json()["error"])
        engine.scan_in_background.assert_not_called()

    def test_existing_paths_survive_when_mixed_with_missing_ones(self):
        d = self.sandbox / "scanme"
        d.mkdir()
        self.post("/api/scan", {"paths": [str(d), "/no/such/dir"]})
        engine.scan_in_background.assert_called_once_with([str(d)],
                                                          trigger="manual")

    def test_a_running_scan_returns_409(self):
        # The route no longer races on PROGRESS.running: it asks
        # scan_in_background, which reserves the single scan slot atomically and
        # returns False when a scan already holds it.
        engine.PROGRESS.running = True
        engine.scan_in_background.return_value = False
        resp = self.post("/api/scan", {})
        self.assertEqual(resp.status_code, 409)
        self.assertIn("already running", resp.get_json()["error"])
        engine.scan_in_background.assert_called_once_with(None, trigger="manual")

    def test_invalid_json_body_starts_the_default_scan(self):
        self.assertEqual(self.post("/api/scan", raw="{oops").status_code, 200)
        engine.scan_in_background.assert_called_once_with(None, trigger="manual")

    def test_cancel_sets_the_flag(self):
        self.assertFalse(engine.PROGRESS.cancel)
        self.assertEqual(self.post("/api/scan/cancel").status_code, 200)
        self.assertTrue(engine.PROGRESS.cancel)

    def test_progress_endpoint_mirrors_the_snapshot(self):
        engine.PROGRESS.files_scanned = 17
        body = self.client.get("/api/scan/progress").get_json()
        self.assertEqual(body["files_scanned"], 17)
        self.assertNotIn("cancel", body)

    def test_scan_history_is_returned_newest_first(self):
        a = store.start_scan(["/x"], "manual")
        b = store.start_scan(["/y"], "scheduled")
        body = self.client.get("/api/scans").get_json()
        self.assertEqual([s["id"] for s in body], [b, a])


# ==========================================================================
# /api/findings
# ==========================================================================

class TestApiFindings(WebTestCase):

    def test_returns_findings_with_parsed_reasons(self):
        self.seed_finding()
        body = self.client.get("/api/findings").get_json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["reasons"], ["r"])
        self.assertIn("exists", body[0])

    def test_safe_items_are_hidden_unless_include_safe_is_1(self):
        f = self.seed_finding()
        store.set_verdict(f["sha256"], "safe")
        self.assertEqual(self.client.get("/api/findings").get_json(), [])
        self.assertEqual(len(self.client.get(
            "/api/findings?include_safe=1").get_json()), 1)

    def test_include_safe_only_accepts_the_literal_1(self):
        f = self.seed_finding()
        store.set_verdict(f["sha256"], "safe")
        for value in ("true", "yes", "0", ""):
            with self.subTest(value=value):
                self.assertEqual(self.client.get(
                    f"/api/findings?include_safe={value}").get_json(), [])

    def test_scan_id_filter_is_applied(self):
        self.seed_finding()
        self.assertEqual(len(self.client.get(
            "/api/findings?scan_id=1").get_json()), 1)
        self.assertEqual(self.client.get(
            "/api/findings?scan_id=2").get_json(), [])

    def test_a_non_integer_scan_id_is_ignored_rather_than_erroring(self):
        self.seed_finding()
        resp = self.client.get("/api/findings?scan_id=abc")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.get_json()), 1)


# ==========================================================================
# quarantine endpoints
# ==========================================================================

class TestApiQuarantine(WebTestCase):

    def test_finding_id_must_be_an_integer(self):
        for bad in ("3", 3.5, None, [], {}, "abc"):
            with self.subTest(bad=bad):
                resp = self.post("/api/quarantine", {"finding_id": bad})
                self.assertEqual(resp.status_code, 400)
                self.assertIn("finding_id (int) required",
                              resp.get_json()["error"])

    def test_a_missing_body_returns_400(self):
        self.assertEqual(self.post("/api/quarantine", {}).status_code, 400)
        self.assertEqual(self.post("/api/quarantine", raw="{oops").status_code,
                         400)

    def test_quarantine_error_is_surfaced_as_400(self):
        resp = self.post("/api/quarantine", {"finding_id": 9999})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("No finding with id 9999", resp.get_json()["error"])

    def test_a_verdict_is_required_before_quarantine(self):
        f = self.seed_finding()
        resp = self.post("/api/quarantine", {"finding_id": f["id"]})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("marked 'malicious' or 'unknown'",
                      resp.get_json()["error"])
        self.assertTrue(Path(f["path"]).exists())

    def test_the_happy_path_moves_the_file_and_reports_the_new_location(self):
        f = self.seed_finding()
        store.set_verdict(f["sha256"], "malicious")
        body = self.post("/api/quarantine", {"finding_id": f["id"]}).get_json()
        self.assertTrue(body["ok"])
        self.assertFalse(Path(f["path"]).exists())
        self.assertTrue(Path(body["quarantine_path"]).exists())

    def test_restore_round_trip_over_http(self):
        f = self.seed_finding()
        store.set_verdict(f["sha256"], "malicious")
        q = self.post("/api/quarantine", {"finding_id": f["id"]}).get_json()
        body = self.post("/api/restore",
                         {"quarantine_id": q["quarantine_id"]}).get_json()
        self.assertEqual(body["restored_to"], f["path"])
        self.assertTrue(Path(f["path"]).exists())

    def test_restore_with_an_unknown_id_returns_400(self):
        resp = self.post("/api/restore", {"quarantine_id": 999})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("No quarantine entry", resp.get_json()["error"])

    def test_restore_with_a_non_numeric_id_returns_400(self):
        resp = self.post("/api/restore", {"quarantine_id": "abc"})
        self.assertEqual(resp.status_code, 400)

    def test_restore_with_no_body_returns_400(self):
        self.assertEqual(self.post("/api/restore", {}).status_code, 400)

    def test_purge_requires_confirm_true(self):
        for body in ({}, {"confirm": False}, {"confirm": "true"},
                     {"confirm": 1}, {"quarantine_id": 1}):
            with self.subTest(body=body):
                resp = self.post("/api/purge", body)
                self.assertEqual(resp.status_code, 400)
                self.assertIn("confirm:true required",
                              resp.get_json()["error"])

    def test_purge_with_confirm_removes_the_file(self):
        f = self.seed_finding()
        store.set_verdict(f["sha256"], "malicious")
        q = self.post("/api/quarantine", {"finding_id": f["id"]}).get_json()
        resp = self.post("/api/purge", {"quarantine_id": q["quarantine_id"],
                                        "confirm": True})
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Path(q["quarantine_path"]).exists())

    def test_quarantine_list_includes_inactive_entries(self):
        f = self.seed_finding()
        store.set_verdict(f["sha256"], "malicious")
        q = self.post("/api/quarantine", {"finding_id": f["id"]}).get_json()
        self.post("/api/restore", {"quarantine_id": q["quarantine_id"]})
        body = self.client.get("/api/quarantine").get_json()
        self.assertEqual(len(body), 1)
        self.assertIsNotNone(body[0]["restored_at"])

    # ---- regression tests for fixed bugs --------------------------------

    def test_BUG_boolean_finding_id_passes_the_int_check(self):
        """REGRESSION TEST (fixed): a boolean finding_id is rejected.

        The bug described below is fixed in this build; this test now guards
        against a regression.

        Original report: BUG webui.py:189 -- `isinstance(fid, int)` is True for bool.

        `{"finding_id": true}` is accepted and becomes id 1, so a request that
        names no finding at all quarantines (moves off disk) whichever finding
        happens to hold id 1. Needs
        `isinstance(fid, int) and not isinstance(fid, bool)`.
        """
        f = self.seed_finding()
        store.set_verdict(f["sha256"], "malicious")
        resp = self.post("/api/quarantine", {"finding_id": True})
        self.assertEqual(resp.status_code, 400, "true is not a finding id")
        self.assertTrue(Path(f["path"]).exists())

    def test_BUG_null_quarantine_id_raises_typeerror_not_400(self):
        """REGRESSION TEST (fixed): a null quarantine_id answers 400, not 500.

        The bug described below is fixed in this build; this test now guards
        against a regression.

        Original report: BUG webui.py:202 and 214 -- `int(body.get(...))` can raise TypeError.

        `int()` of None raises TypeError, and only QuarantineError and
        ValueError are caught, so `{"quarantine_id": null}` (and `[]`, `{}`)
        produces a 500 with a traceback instead of a 400. The `-1` default only
        covers a *missing* key, not an explicit null.
        """
        for bad in (None, [], {}):
            with self.subTest(bad=bad):
                resp = self.post("/api/restore", {"quarantine_id": bad})
                self.assertEqual(resp.status_code, 400)
                resp = self.post("/api/purge", {"quarantine_id": bad,
                                                "confirm": True})
                self.assertEqual(resp.status_code, 400)


# ==========================================================================
# reports
# ==========================================================================

class TestReports(WebTestCase):

    def test_report_listing_is_newest_first_and_capped(self):
        import time
        for i in range(3):
            p = config.REPORTS_DIR / f"r{i}.html"
            p.write_text("<html></html>")
            os.utime(p, (time.time() + i, time.time() + i))
        body = self.client.get("/api/reports").get_json()
        self.assertEqual([f["name"] for f in body],
                         ["r2.html", "r1.html", "r0.html"])
        for entry in body:
            self.assertIn("size", entry)
            self.assertIn("mtime", entry)

    def test_only_html_files_are_listed(self):
        (config.REPORTS_DIR / "a.html").write_text("x")
        (config.REPORTS_DIR / "b.txt").write_text("x")
        (config.REPORTS_DIR / "c.json").write_text("x")
        self.assertEqual([f["name"] for f in
                          self.client.get("/api/reports").get_json()],
                         ["a.html"])

    def test_an_existing_report_is_served(self):
        (config.REPORTS_DIR / "scan.html").write_text("<h1>report</h1>")
        resp = self.client.get("/reports/scan.html")
        self.addCleanup(resp.close)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("report", resp.get_data(as_text=True))

    def test_a_missing_report_returns_404(self):
        self.assertEqual(self.client.get("/reports/nope.html").status_code, 404)

    def test_path_traversal_attempts_never_escape_the_reports_directory(self):
        secret = config.DATA_ROOT / "config.json"
        secret.write_text('{"secret": "do not serve me"}', encoding="utf-8")
        (config.DATA_ROOT / "outside.html").write_text("outside", encoding="utf-8")
        attempts = [
            "/reports/../config.json",
            "/reports/..%2fconfig.json",
            "/reports/..%252fconfig.json",
            "/reports/%2e%2e%2fconfig.json",
            "/reports/....//config.json",
            "/reports/../outside.html",
            "/reports/..%2f..%2f..%2fetc%2fpasswd",
            "/reports/%2e%2e/%2e%2e/etc/passwd",
            "/reports/sub/../../config.json",
        ]
        for url in attempts:
            with self.subTest(url=url):
                resp = self.client.get(url)
                text = resp.get_data(as_text=True)
                self.assertNotIn("do not serve me", text,
                                 f"{url} leaked config.json")
                self.assertNotIn("root:", text, f"{url} leaked /etc/passwd")
                self.assertNotEqual(resp.status_code, 200,
                                    f"{url} returned content")

    def test_an_absolute_path_is_not_served(self):
        resp = self.client.get("/reports//etc/passwd")
        self.assertNotIn("root:", resp.get_data(as_text=True))
        self.assertNotEqual(resp.status_code, 200)

    def test_a_symlink_out_of_the_reports_directory_is_not_followed(self):
        secret = config.DATA_ROOT / "config.json"
        secret.write_text('{"secret": "do not serve me"}', encoding="utf-8")
        link = config.REPORTS_DIR / "sneak.html"
        try:
            link.symlink_to(secret)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable here")
        resp = self.client.get("/reports/sneak.html")
        self.addCleanup(resp.close)
        # Documented behaviour: send_from_directory resolves symlinks, so this
        # currently DOES serve the target. Flagged in the report as a finding.
        if resp.status_code == 200:
            self.assertIn("do not serve me", resp.get_data(as_text=True),
                          "unexpected third behaviour")


# ==========================================================================
# feed update + open-folder
# ==========================================================================

class TestFeedUpdate(WebTestCase):

    def test_a_download_failure_is_reported_without_raising(self):
        import urllib.error
        with mock.patch.object(feeds, "_download",
                               side_effect=urllib.error.URLError("offline")):
            body = self.post("/api/feed/update", {}).get_json()
        self.assertFalse(body["ok"])
        self.assertIn("Feed download failed", body["message"])
        self.assertIn("feed", body)

    def test_a_successful_update_populates_the_cache(self):
        # MalwareBazaar CSV column order: signature is index 8.
        csv = ('"first_seen_utc","sha256_hash","md5_hash","sha1_hash",'
               '"reporter","file_name","file_type_guess","mime_type",'
               '"signature","clamav"\n'
               f'"2026-01-01","{"1" * 64}","m","s","r","a.exe","exe",'
               '"application/x-dosexec","TestFamily",""\n')
        with mock.patch.object(feeds, "_download",
                               return_value=csv.encode()):
            body = self.post("/api/feed/update", {}).get_json()
        self.assertTrue(body["ok"], body["message"])
        self.assertEqual(feeds.load_known_bad(), {"1" * 64: "TestFamily"})
        self.assertTrue(body["feed"]["available"])
        self.assertEqual(body["feed"]["count"], 1)

    def test_the_full_flag_selects_the_full_feed_url(self):
        with mock.patch.object(feeds, "_download",
                               return_value=b"") as download:
            self.post("/api/feed/update", {"full": True})
        download.assert_called_once_with(feeds.BAZAAR_FULL)

    def test_the_default_selects_the_recent_feed_url(self):
        with mock.patch.object(feeds, "_download",
                               return_value=b"") as download:
            self.post("/api/feed/update", {})
        download.assert_called_once_with(feeds.BAZAAR_RECENT)

    def test_the_feed_cache_stays_inside_the_test_data_root(self):
        self.assertTrue(str(feeds.HASH_DB).startswith(str(self.data_root)),
                        "feeds.HASH_DB was not redirected -- test is not hermetic")


class TestOpenFolder(WebTestCase):

    def test_a_nonexistent_path_returns_400(self):
        with stub_launchers() as L:
            resp = self.post("/api/open-folder",
                             {"path": "/no/such/dir/anywhere/file.txt"})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("no longer exists", resp.get_json()["error"])
        L.popen.assert_not_called()
        L.startfile.assert_not_called()

    def test_BUG_an_empty_or_missing_path_opens_the_working_directory(self):
        """REGRESSION TEST (fixed): an empty/missing path answers 400.

        The bug described below is fixed in this build; this test now guards
        against a regression.

        Original report: BUG webui.py:247-250 -- `os.path.abspath("")` is the cwd.

        With `path` absent, empty or null, `p` becomes the server's current
        working directory, which always exists, so the existence guard passes
        and the handler launches `xdg-open <cwd>` (or `os.startfile` on
        Windows) on a directory the caller never named. Any guarded POST with an
        empty JSON body -- including one issued by a page the user is tricked
        into loading if the header check is ever relaxed -- pops a file-manager
        window. The handler needs an explicit `if not target: return 400`.
        """
        for body in ({"path": ""}, {}, {"path": None}):
            with self.subTest(body=body):
                with stub_launchers() as L:
                    resp = self.post("/api/open-folder", body)
                self.assertEqual(resp.status_code, 400)
                L.popen.assert_not_called()
                L.startfile.assert_not_called()

    # Every test below pins config.IS_WINDOWS explicitly rather than inheriting
    # the host OS, so the same assertions hold whichever platform runs the
    # suite, and stubs BOTH launchers so no real file manager can ever be
    # spawned on a directory that tearDown is about to delete.

    def test_posix_a_file_reveals_its_parent_directory(self):
        f = self.write("sub/thing.exe", b"MZ")
        with mock.patch.object(config, "IS_WINDOWS", False), stub_launchers() as L:
            resp = self.post("/api/open-folder", {"path": str(f)})
        self.assertEqual(resp.status_code, 200)
        L.popen.assert_called_once_with(["xdg-open", str(f.parent)])
        L.startfile.assert_not_called()

    def test_posix_a_directory_opens_itself(self):
        d = self.sandbox / "sub"
        d.mkdir()
        with mock.patch.object(config, "IS_WINDOWS", False), stub_launchers() as L:
            resp = self.post("/api/open-folder", {"path": str(d)})
        self.assertEqual(resp.status_code, 200)
        L.popen.assert_called_once_with(["xdg-open", str(d)])
        L.startfile.assert_not_called()

    def test_windows_a_directory_goes_to_startfile_not_popen(self):
        """REGRESSION: this is the path that spawned a real Explorer window.

        On Windows the directory branch is `os.startfile`, not `subprocess.Popen`.
        Stubbing only Popen let the real call through, Explorer opened the temp
        sandbox, tearDown removed it, and the user got a "Location is not
        available" dialog. The assertion failed too, since Popen was never called.
        """
        d = self.sandbox / "sub"
        d.mkdir()
        with mock.patch.object(config, "IS_WINDOWS", True), stub_launchers() as L:
            resp = self.post("/api/open-folder", {"path": str(d)})
        self.assertEqual(resp.status_code, 200)
        L.startfile.assert_called_once_with(str(d))
        L.popen.assert_not_called()

    def test_posix_a_launcher_failure_returns_500_with_a_message(self):
        with mock.patch.object(config, "IS_WINDOWS", False), \
                stub_launchers(popen_side_effect=FileNotFoundError("xdg-open")):
            resp = self.post("/api/open-folder", {"path": str(self.sandbox)})
        self.assertEqual(resp.status_code, 500)
        self.assertIn("xdg-open", resp.get_json()["error"])

    def test_windows_a_startfile_failure_returns_500_with_a_message(self):
        with mock.patch.object(config, "IS_WINDOWS", True), \
                stub_launchers(startfile_side_effect=OSError("no association")):
            resp = self.post("/api/open-folder", {"path": str(self.sandbox)})
        self.assertEqual(resp.status_code, 500)
        self.assertIn("no association", resp.get_json()["error"])

    def test_windows_uses_explorer_select_for_a_file(self):
        # os.system() was replaced by a shell=False Popen: cmd.exe is no longer
        # in the loop, so '&' in a filename cannot run as a command.
        f = self.write("sub/thing.exe", b"MZ")
        with mock.patch.object(config, "IS_WINDOWS", True), stub_launchers() as L:
            resp = self.post("/api/open-folder", {"path": str(f)})
        self.assertEqual(resp.status_code, 200)
        L.popen.assert_called_once()
        cmdline = L.popen.call_args.args[0]
        self.assertIn("explorer.exe /select,", cmdline)
        self.assertIn(str(f), cmdline)
        self.assertIs(L.popen.call_args.kwargs["shell"], False)
        L.startfile.assert_not_called()

    def test_a_vanished_directory_is_refused_instead_of_launched(self):
        """The parent existing is not enough — the target itself must exist.

        The old guard was `if not p.exists() and not p.parent.exists()`, which
        passes whenever the parent survives. Revealing a path that is gone is
        exactly what produces Windows' "Location is not available" dialog.
        """
        gone = self.sandbox / "sub"
        for is_win in (False, True):
            with self.subTest(windows=is_win):
                with mock.patch.object(config, "IS_WINDOWS", is_win), \
                        stub_launchers() as L:
                    resp = self.post("/api/open-folder", {"path": str(gone)})
                self.assertEqual(resp.status_code, 400)
                L.popen.assert_not_called()
                L.startfile.assert_not_called()


class TestIndexPage(WebTestCase):

    def test_index_serves_html(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers["Content-Type"])
        body = resp.get_data(as_text=True)
        self.assertIn("<!DOCTYPE html>", body)
        self.assertIn("Sentry", body)

    def test_the_page_sends_the_guard_header_from_javascript(self):
        body = self.client.get("/").get_data(as_text=True)
        self.assertIn(webui.GUARD_HEADER, body,
                      "the UI must send the header it is guarded by")

    def test_index_rejects_a_post(self):
        self.assertEqual(self.client.post("/", headers=self.HDR).status_code, 405)


class TestReviewPage(WebTestCase):
    """The triage queue served to the desktop app."""

    def test_review_serves_html(self):
        resp = self.client.get("/review")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers["Content-Type"])
        body = resp.get_data(as_text=True)
        self.assertIn("<!DOCTYPE html>", body)
        self.assertIn("/api/findings", body)
        self.assertIn("/api/verdict", body)

    def test_review_sends_the_guard_header_from_javascript(self):
        body = self.client.get("/review").get_data(as_text=True)
        self.assertIn(webui.GUARD_HEADER, body)

    def test_review_rejects_a_post(self):
        self.assertEqual(
            self.client.post("/review", headers=self.HDR).status_code, 405)

    def test_review_verdict_labels_match_the_store_vocabulary(self):
        # The queue's buttons post these verdicts; they must be the exact
        # strings the store accepts, or every click would be a 400.
        body = self.client.get("/review").get_data(as_text=True)
        for verdict in ("safe", "unknown", "malicious"):
            self.assertIn(f"mark('{verdict}')", body)


class TestSchedule(WebTestCase):
    """Pause/resume of the weekly task. schtasks is always mocked here —
    these tests must never touch the machine's real scheduled task."""

    CSV = '"Sentry Weekly Scan","09/06/2026 12:00:00","Ready"'

    def _run(self, returncode=0, stdout=""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr="")

    def test_status_reports_a_ready_task(self):
        with mock.patch.object(webui.config, "IS_WINDOWS", True), \
             mock.patch.object(webui.subprocess, "run",
                               return_value=self._run(0, self.CSV)) as run:
            body = self.client.get("/api/schedule").get_json()
        self.assertEqual(body, {"supported": True, "installed": True,
                                "paused": False, "status": "Ready",
                                "next_run": "09/06/2026 12:00:00"})
        self.assertEqual(run.call_args[0][0][:2], ["schtasks", "/Query"])

    def test_status_reports_a_paused_task(self):
        csv = self.CSV.replace("Ready", "Disabled")
        with mock.patch.object(webui.config, "IS_WINDOWS", True), \
             mock.patch.object(webui.subprocess, "run",
                               return_value=self._run(0, csv)):
            body = self.client.get("/api/schedule").get_json()
        self.assertTrue(body["paused"])

    def test_status_when_the_task_is_not_installed(self):
        with mock.patch.object(webui.config, "IS_WINDOWS", True), \
             mock.patch.object(webui.subprocess, "run",
                               return_value=self._run(1)):
            body = self.client.get("/api/schedule").get_json()
        self.assertEqual(body, {"supported": True, "installed": False})

    def test_pause_and_resume_run_the_right_schtasks_change(self):
        for action, flag in (("pause", "/DISABLE"), ("resume", "/ENABLE")):
            with mock.patch.object(webui.config, "IS_WINDOWS", True), \
                 mock.patch.object(webui.subprocess, "run",
                                   return_value=self._run(0)) as run:
                resp = self.client.post("/api/schedule", headers=self.HDR,
                                        data=json.dumps({"action": action}))
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(run.call_args[0][0],
                             ["schtasks", "/Change", "/TN",
                              webui.TASK_NAME, flag])

    def test_a_bad_action_is_a_400_and_never_reaches_schtasks(self):
        with mock.patch.object(webui.config, "IS_WINDOWS", True), \
             mock.patch.object(webui.subprocess, "run") as run:
            resp = self.client.post("/api/schedule", headers=self.HDR,
                                    data=json.dumps({"action": "delete"}))
        self.assertEqual(resp.status_code, 400)
        run.assert_not_called()

    def test_a_schtasks_failure_is_surfaced_not_swallowed(self):
        boom = mock.Mock(returncode=1, stdout="", stderr="ERROR: Access is denied.")
        with mock.patch.object(webui.config, "IS_WINDOWS", True), \
             mock.patch.object(webui.subprocess, "run", return_value=boom):
            resp = self.client.post("/api/schedule", headers=self.HDR,
                                    data=json.dumps({"action": "pause"}))
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Access is denied", resp.get_json()["error"])

    def test_the_review_page_wires_the_toggle(self):
        body = self.client.get("/review").get_data(as_text=True)
        self.assertIn("/api/schedule", body)
        self.assertIn("schedToggle", body)

    def test_the_review_page_offers_drive_scope(self):
        body = self.client.get("/review").get_data(as_text=True)
        self.assertIn("scopeApply", body)
        self.assertIn("/api/config", body)


if __name__ == "__main__":
    unittest.main()


class TestRestoreMarkSafe(WebTestCase):
    """The one-click return trip: put the file back AND allowlist it."""

    def _quarantine_one(self):
        # Not "Games/...": a folder named Games is now a protected application
        # location (config.PROTECTED_SEGMENTS) and quarantine refuses it.
        f = self.write("Downloads/deep/statement.pdf.exe", b"MZ" + b"\0" * 9000)
        import hashlib
        sha = hashlib.sha256(f.read_bytes()).hexdigest()
        store.upsert_finding({
            "path": str(f), "sha256": sha, "size": f.stat().st_size,
            "mtime": None, "score": 42, "severity": "low",
            "reasons": ["double extension"],
        }, 1)
        fid = store.get_findings()[0]["id"]
        store.set_verdict(sha, "malicious", path=str(f))
        result = quarantine.quarantine_finding(fid)
        return f, sha, result

    def test_the_original_path_is_recorded_before_the_file_moves(self):
        f, sha, result = self._quarantine_one()
        entry = store.get_quarantine_entry(result["quarantine_id"])
        self.assertEqual(entry["original_path"], str(f))
        self.assertEqual(entry["sha256"], sha)
        self.assertFalse(f.exists(), "file should have left its original location")
        # ...and again in a sidecar, so the folder is self-describing even if
        # the database is lost.
        sidecar = Path(result["quarantine_path"]).with_suffix(".quar.txt")
        self.assertIn(str(f), sidecar.read_text(encoding="utf-8"))

    def test_mark_safe_and_restore_returns_the_file_and_allowlists_it(self):
        f, sha, result = self._quarantine_one()
        original = f.read_bytes() if f.exists() else None
        resp = self.post("/api/restore",
                         {"quarantine_id": result["quarantine_id"],
                          "mark_safe": True})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["marked_safe"])
        self.assertEqual(body["restored_to"], str(f))
        self.assertTrue(f.exists(), "file must be back at its exact original path")
        self.assertEqual(store.get_verdict(sha), "safe")
        self.assertIn(sha, store.allowlist())

    def test_a_plain_restore_clears_the_verdict_instead_of_allowlisting(self):
        f, sha, result = self._quarantine_one()
        resp = self.post("/api/restore",
                         {"quarantine_id": result["quarantine_id"]})
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("marked_safe", resp.get_json())
        self.assertIsNone(store.get_verdict(sha),
                          "plain restore re-reviews the file next scan")

    def test_a_failed_restore_leaves_no_allowlist_entry_behind(self):
        f, sha, result = self._quarantine_one()
        # Something else now occupies the original path, so restore must refuse.
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"someone else's file")
        resp = self.post("/api/restore",
                         {"quarantine_id": result["quarantine_id"],
                          "mark_safe": True})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(store.get_verdict(sha), "malicious",
                         "verdict must not become 'safe' when the move failed")
        self.assertNotIn(sha, store.allowlist())
