"""Light coverage for sentry.engine: the gating predicates that decide whether
a file is looked at. The full pipeline is already exercised by selftest.py."""
from __future__ import annotations

import os
import unittest
from unittest import mock

from sentry import config, engine, store
from tests.support import (FakeNtOs, TempEnvMixin, benign_pe,
                           deny_directory_listing, is_listable)


# ==========================================================================
# _should_inspect
# ==========================================================================

class TestShouldInspect(unittest.TestCase):

    CFG = {"max_file_mb": 128}
    MAX = 128 * 1024 * 1024

    def test_ordinary_file_is_inspected(self):
        self.assertEqual(engine._should_inspect("/x/a.exe", 4096, self.CFG),
                         (True, ""))

    def test_every_skip_extension_is_gated_out(self):
        for ext in sorted(config.SKIP_EXT):
            with self.subTest(ext=ext):
                ok, why = engine._should_inspect("/x/movie" + ext, 4096, self.CFG)
                self.assertFalse(ok)
                self.assertEqual(why, "media/disk-image type")

    def test_skip_extension_matching_is_case_insensitive(self):
        ok, why = engine._should_inspect("/x/MOVIE.MP4", 4096, self.CFG)
        self.assertFalse(ok)
        self.assertEqual(why, "media/disk-image type")

    def test_size_limit_boundary_is_inclusive(self):
        self.assertEqual(engine._should_inspect("/x/a.exe", self.MAX, self.CFG),
                         (True, ""))
        self.assertEqual(engine._should_inspect("/x/a.exe", self.MAX + 1, self.CFG),
                         (False, "over size limit"))

    def test_size_limit_follows_the_configured_value(self):
        cfg = {"max_file_mb": 1}
        self.assertEqual(engine._should_inspect("/x/a.exe", 1024 * 1024, cfg),
                         (True, ""))
        self.assertEqual(engine._should_inspect("/x/a.exe", 1024 * 1024 + 1, cfg),
                         (False, "over size limit"))

    def test_size_limit_default_is_128mb_when_unset(self):
        self.assertEqual(engine._should_inspect("/x/a.exe", self.MAX, {}),
                         (True, ""))
        self.assertEqual(engine._should_inspect("/x/a.exe", self.MAX + 1, {}),
                         (False, "over size limit"))

    def test_string_size_limit_from_json_config_is_coerced(self):
        cfg = {"max_file_mb": "2"}
        self.assertEqual(engine._should_inspect("/x/a.exe", 1024, cfg), (True, ""))
        self.assertEqual(engine._should_inspect("/x/a.exe", 3 * 1024 * 1024, cfg),
                         (False, "over size limit"))

    def test_empty_files_are_gated_out(self):
        self.assertEqual(engine._should_inspect("/x/a.exe", 0, self.CFG),
                         (False, "empty file"))

    def test_one_byte_is_inspected(self):
        self.assertEqual(engine._should_inspect("/x/a.exe", 1, self.CFG),
                         (True, ""))

    def test_extension_gate_is_checked_before_the_size_gate(self):
        # A 0-byte .mp4 is reported as a media type, not as an empty file.
        self.assertEqual(engine._should_inspect("/x/a.mp4", 0, self.CFG),
                         (False, "media/disk-image type"))
        self.assertEqual(engine._should_inspect("/x/a.mp4", 10 ** 12, self.CFG),
                         (False, "media/disk-image type"))

    def test_extensionless_files_are_inspected(self):
        self.assertEqual(engine._should_inspect("/x/svchost", 100, self.CFG),
                         (True, ""))

    def test_a_reason_string_is_always_supplied_when_gated_out(self):
        for path, size in (("/x/a.mp4", 10), ("/x/a.exe", 0),
                           ("/x/a.exe", 10 ** 12)):
            ok, why = engine._should_inspect(path, size, self.CFG)
            self.assertFalse(ok)
            self.assertTrue(why.strip(), f"{path} {size}")


# ==========================================================================
# _is_excluded
# ==========================================================================

class TestIsExcluded(unittest.TestCase):

    def test_no_exclusions_never_excludes(self):
        self.assertFalse(engine._is_excluded("/anything", []))

    def test_exact_match_is_excluded(self):
        self.assertTrue(engine._is_excluded("/foo", ["/foo"]))

    def test_descendant_is_excluded(self):
        self.assertTrue(engine._is_excluded("/foo/bar", ["/foo"]))
        self.assertTrue(engine._is_excluded("/foo/bar/baz/x.exe", ["/foo"]))

    def test_prefix_sibling_is_NOT_excluded(self):
        self.assertFalse(engine._is_excluded("/foobar", ["/foo"]))
        self.assertFalse(engine._is_excluded("/foobar/baz", ["/foo"]))
        self.assertFalse(engine._is_excluded("/foo-backup/x", ["/foo"]))
        self.assertFalse(engine._is_excluded("/tmp/data2", ["/tmp/data"]))

    def test_ancestor_of_an_exclusion_is_not_excluded(self):
        self.assertFalse(engine._is_excluded("/foo", ["/foo/bar"]))

    def test_unrelated_path_is_not_excluded(self):
        self.assertFalse(engine._is_excluded("/var/log", ["/usr", "/opt"]))

    def test_any_matching_exclusion_wins(self):
        self.assertTrue(engine._is_excluded("/opt/x", ["/usr", "/opt", "/var"]))

    def test_trailing_separators_on_the_exclusion_are_tolerated(self):
        for ex in ("/foo", "/foo/", "/foo//", "/foo/."):
            with self.subTest(ex=ex):
                self.assertTrue(engine._is_excluded("/foo/bar", [ex]))
                self.assertFalse(engine._is_excluded("/foobar", [ex]))

    def test_redundant_separators_in_the_path_are_normalised(self):
        self.assertTrue(engine._is_excluded("/foo//bar/./baz", ["/foo"]))

    def test_root_exclusion_excludes_everything(self):
        self.assertTrue(engine._is_excluded("/anywhere/at/all", ["/"]))

    def test_environment_variables_in_exclusions_are_expanded(self):
        with mock.patch.dict(os.environ, {"SENTRY_UT_EX": "/skipme"}):
            self.assertTrue(engine._is_excluded("/skipme/x", ["$SENTRY_UT_EX"]))
            self.assertFalse(engine._is_excluded("/keepme/x", ["$SENTRY_UT_EX"]))

    def test_undefined_environment_variables_do_not_crash(self):
        self.assertFalse(engine._is_excluded("/x", ["$NO_SUCH_VAR_HERE/y"]))

    @unittest.skipIf(config.IS_WINDOWS, "POSIX paths are case-sensitive")
    def test_case_matters_on_posix(self):
        self.assertFalse(engine._is_excluded("/Foo/bar", ["/foo"]))


class TestIsExcludedWindows(unittest.TestCase):
    """Windows path semantics, simulated so the behaviour is not left untested."""

    def setUp(self):
        patcher = mock.patch.object(engine, "os", FakeNtOs())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_matching_is_case_insensitive(self):
        self.assertTrue(engine._is_excluded(r"C:\Windows\WinSxS\x",
                                            [r"c:\windows\winsxs"]))
        self.assertTrue(engine._is_excluded(r"c:\windows\winsxs\x",
                                            [r"C:\Windows\WinSxS"]))

    def test_prefix_siblings_are_excluded_correctly(self):
        self.assertTrue(engine._is_excluded(r"C:\Windows\Installer\a.msi",
                                            [r"C:\Windows\Installer"]))
        self.assertFalse(engine._is_excluded(r"C:\Windows\InstallerCache\a.msi",
                                             [r"C:\Windows\Installer"]))

    def test_every_default_windows_exclusion_matches_its_own_subtree(self):
        for ex in config.DEFAULT_EXCLUSIONS_WIN:
            with self.subTest(ex=ex):
                # _is_excluded expands %SystemRoot% & co. in the *exclusion*.
                # On a real Windows host those variables exist, so the path
                # under test must be expanded the same way; on Linux they are
                # unset and the literal survives on both sides as before.
                path = os.path.expandvars(ex)
                self.assertTrue(engine._is_excluded(path, config.DEFAULT_EXCLUSIONS_WIN))
                self.assertTrue(engine._is_excluded(path + r"\child",
                                                    config.DEFAULT_EXCLUSIONS_WIN))

    def test_default_windows_exclusions_leave_user_folders_alone(self):
        for path in (r"C:\Users\Me\Downloads\a.exe", r"C:\Users\Me\Desktop\b.ps1",
                     r"C:\Program Files\App\app.exe", r"D:\Data\x.docm"):
            with self.subTest(path=path):
                self.assertFalse(
                    engine._is_excluded(path, config.DEFAULT_EXCLUSIONS_WIN))

    def test_drive_root_exclusion(self):
        self.assertTrue(engine._is_excluded(r"C:\anything", ["C:\\"]))
        self.assertFalse(engine._is_excluded(r"D:\anything", ["C:\\"]))


class TestPosixDefaultExclusions(unittest.TestCase):

    def test_every_default_posix_exclusion_matches_its_own_subtree(self):
        for ex in config.DEFAULT_EXCLUSIONS_NIX:
            with self.subTest(ex=ex):
                self.assertTrue(engine._is_excluded(ex + "/child",
                                                    config.DEFAULT_EXCLUSIONS_NIX))

    def test_default_posix_exclusions_leave_home_alone(self):
        for path in ("/home/u/Downloads/a.exe", "/tmp/x.sh", "/opt/app/a"):
            with self.subTest(path=path):
                self.assertFalse(
                    engine._is_excluded(path, config.DEFAULT_EXCLUSIONS_NIX))

    def test_proc_is_excluded_but_process_is_not(self):
        self.assertTrue(engine._is_excluded("/proc/1/mem",
                                            config.DEFAULT_EXCLUSIONS_NIX))
        self.assertFalse(engine._is_excluded("/procedures/notes.txt",
                                             config.DEFAULT_EXCLUSIONS_NIX))


# ==========================================================================
# iter_candidate_files -- pruning behaviour
# ==========================================================================

class TestIterCandidateFiles(TempEnvMixin, unittest.TestCase):

    def collect(self, roots=None, **cfg):
        params = {"exclusions": [], "follow_symlinks": False}
        params.update(cfg)
        roots = roots if roots is not None else [str(self.sandbox)]
        return sorted(engine.iter_candidate_files(roots, params))

    def test_walks_nested_directories(self):
        a = self.write("a.txt", "a")
        b = self.write("sub/deep/b.txt", "b")
        self.assertEqual(self.collect(), sorted([str(a), str(b)]))

    def test_a_file_given_as_a_root_is_yielded_directly(self):
        f = self.write("solo.exe", b"MZ")
        self.assertEqual(self.collect([str(f)]), [str(f)])

    def test_a_nonexistent_root_yields_nothing(self):
        self.assertEqual(self.collect(["/no/such/dir"]), [])

    @unittest.skipUnless(config.IS_WINDOWS, "exercises the real Win32 \\\\?\\ prefix")
    def test_files_beyond_max_path_are_found_from_a_short_root(self):
        """Regression for a real miss on Windows (LongPathsEnabled=0).

        long_path() only prefixed a root that was itself >= 240 characters, so
        the usual short root (D:\\, a temp dir) walked bare and every directory
        past 260 characters failed inside scandir(), swallowed by onerror. A
        316-character decoy scanned as '0 files, clean'.
        """
        import shutil
        seg = "segment_" + "x" * 40
        deep = str(self.sandbox)
        while len(deep) < 300:
            deep = os.path.join(deep, seg)
        os.makedirs("\\\\?\\" + deep, exist_ok=True)
        # rmtree on the bare path cannot reach this far either.
        self.addCleanup(shutil.rmtree, "\\\\?\\" + str(self.sandbox), ignore_errors=True)
        target = os.path.join(deep, "invoice.pdf.exe")
        with open("\\\\?\\" + target, "wb") as fh:
            fh.write(b"MZ")
        got = self.collect()
        self.assertIn(target, got)
        self.assertFalse(any(p.startswith("\\\\?\\") for p in got),
                         "yielded paths must be plain, never prefixed")

    def test_excluded_directories_are_pruned(self):
        keep = self.write("keep/a.txt", "a")
        self.write("skip/b.txt", "b")
        self.write("skip/deeper/c.txt", "c")
        got = self.collect(exclusions=[str(self.sandbox / "skip")])
        self.assertEqual(got, [str(keep)])

    def test_the_sentry_data_root_is_never_walked(self):
        (config.DATA_ROOT / "quarantine").mkdir(parents=True, exist_ok=True)
        (config.DATA_ROOT / "quarantine" / "x.quar").write_bytes(b"MZ")
        self.assertEqual(self.collect([str(config.DATA_ROOT)]), [])

    def test_an_excluded_root_yields_nothing(self):
        self.write("a.txt", "a")
        self.assertEqual(self.collect(exclusions=[str(self.sandbox)]), [])

    def test_symlinked_directories_are_not_followed_by_default(self):
        real = self.sandbox / "real"
        real.mkdir()
        (real / "a.txt").write_text("a")
        link = self.sandbox / "link"
        try:
            link.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are unavailable here")
        got = self.collect()
        self.assertIn(str(real / "a.txt"), got)
        self.assertNotIn(str(link / "a.txt"), got)

    def test_unreadable_directories_do_not_abort_the_walk(self):
        good = self.write("good/a.txt", "a")
        bad = self.sandbox / "bad"
        bad.mkdir()
        (bad / "b.txt").write_text("b")
        self.addCleanup(deny_directory_listing(bad))
        if is_listable(bad):
            self.skipTest("running as root; permissions are not enforced")
        self.assertIn(str(good), self.collect())


# ==========================================================================
# scan_file -- gating and scoring integration (offline, no YARA, no feed)
# ==========================================================================

class TestScanFile(TempEnvMixin, unittest.TestCase):

    def scan(self, path, *, known_bad=None, allow=None, **cfg):
        return engine.scan_file(str(path), known_bad=known_bad or {},
                                yara_rules=None, cfg=self.offline_cfg(**cfg),
                                allow=allow or set())

    def test_plain_text_file_is_not_reported(self):
        self.assertIsNone(self.scan(self.write("notes.txt", "shopping list\n" * 50)))

    def test_normal_csv_is_not_reported(self):
        body = "date,amount\n" + "\n".join(f"2026-01-{i:02d},{i}" for i in range(1, 29))
        self.assertIsNone(self.scan(self.write("data.csv", body)))

    def test_real_jpeg_is_not_reported(self):
        self.assertIsNone(self.scan(
            self.write("photo.jpg", b"\xff\xd8\xff\xe0" + b"\x11" * 5000)))

    def test_empty_file_is_not_reported(self):
        self.assertIsNone(self.scan(self.write("empty.exe", b"")))

    def test_media_extension_is_not_reported_even_with_a_pe_header(self):
        self.assertIsNone(self.scan(self.write("clip.mp4", b"MZ" + b"\x00" * 9000)))

    def test_missing_file_returns_none(self):
        self.assertIsNone(self.scan(self.sandbox / "ghost.exe"))

    def test_oversize_file_is_not_reported(self):
        p = self.write("big.exe", b"MZ" + b"\x00" * 20000)
        self.assertIsNone(self.scan(p, max_file_mb=0))

    def test_double_extension_pe_is_reported_with_a_severity_and_hash(self):
        p = benign_pe().write(self.sandbox / "invoice.pdf.exe")
        got = self.scan(p)
        self.assertIsNotNone(got)
        self.assertEqual(got["path"], str(p))
        self.assertEqual(len(got["sha256"]), 64)
        self.assertEqual(got["size"], p.stat().st_size)
        self.assertGreaterEqual(got["score"], 32)
        self.assertIn(got["severity"], {"low", "medium", "high"})
        self.assertTrue(any("Double extension" in r for r in got["reasons"]))

    def test_pe_behind_a_txt_extension_is_reported(self):
        p = benign_pe().write(self.sandbox / "meeting_notes.txt")
        got = self.scan(p)
        self.assertIsNotNone(got)
        self.assertTrue(any("content is a Windows PE" in r for r in got["reasons"]))

    def test_score_is_capped_at_100(self):
        p = benign_pe().write(self.sandbox / "invoice.pdf.exe")
        sha = self.scan(p)["sha256"]
        got = self.scan(p, known_bad={sha: "TestFamily"})
        self.assertEqual(got["score"], 100)
        self.assertEqual(got["severity"], "high")
        self.assertTrue(any("known-malicious hash feed" in r for r in got["reasons"]))
        self.assertTrue(any("TestFamily" in r for r in got["reasons"]))

    def test_allowlisted_hash_is_skipped_entirely(self):
        p = benign_pe().write(self.sandbox / "invoice.pdf.exe")
        sha = self.scan(p)["sha256"]
        self.assertIsNone(self.scan(p, allow={sha}))

    def test_report_threshold_gates_the_result(self):
        p = benign_pe().write(self.sandbox / "invoice.pdf.exe")
        self.assertIsNotNone(self.scan(p, report_threshold=32))
        self.assertIsNone(self.scan(p, report_threshold=99))

    def test_reported_mtime_is_iso8601_utc(self):
        p = benign_pe().write(self.sandbox / "invoice.pdf.exe")
        self.assertRegex(self.scan(p)["mtime"],
                         r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00$")

    def test_pe_metadata_is_attached_for_pe_files(self):
        p = benign_pe().write(self.sandbox / "invoice.pdf.exe")
        meta = self.scan(p)["meta"]
        self.assertEqual(meta.get("machine"), "0x8664")
        self.assertGreater(meta.get("imports", 0), 0)

    def test_obfuscated_powershell_is_reported(self):
        body = ("# decoy\n"
                "powershell -nop -w hidden -enc "
                + "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQ" * 3 + "\n"
                'Add-MpPreference -ExclusionPath "C:\\Temp"\n')
        got = self.scan(self.write("update.ps1", body))
        self.assertIsNotNone(got)
        self.assertGreaterEqual(got["score"], 45)
        self.assertTrue(any("Defender exclusions" in r for r in got["reasons"]))

    def test_macro_document_is_reported(self):
        body = (b"PK\x03\x04word/vbaProject.bin\x00Sub AutoOpen()\n"
                b'Shell("powershell -w hidden")\nEnd Sub\n')
        got = self.scan(self.write("invoice.docm", body))
        self.assertIsNotNone(got)
        self.assertTrue(any("VBA auto-execution" in r for r in got["reasons"]))

    def test_a_directory_passed_as_a_path_is_ignored(self):
        d = self.sandbox / "adir"
        d.mkdir()
        self.assertIsNone(self.scan(d))


# ==========================================================================
# ScanProgress
# ==========================================================================

class TestWeeklyCommand(TempEnvMixin, unittest.TestCase):

    def test_weekly_uses_its_own_scan_row_not_the_latest(self):
        """Regression: cmd_weekly read store.last_scan() after the scan. On a
        real Windows run a 4-file dashboard scan finished during the 83,000-
        file weekly scan and became 'last', so the weekly report and row
        said '4 files checked'."""
        from types import SimpleNamespace
        from sentry import __main__ as m
        for i in range(3):
            self.write(f"f{i}.txt", "plain")
        config.save_config({"enabled_presets": [], "custom_paths": [str(self.sandbox)],
                            "use_hash_feed": False, "use_yara": False,
                            "notify_on_scheduled_scan": False, "exclusions": []})
        with mock.patch.object(store, "last_scan",
                               side_effect=AssertionError("last_scan() must not decide the row")), \
                mock.patch.object(m.behavior, "sweep", return_value=[]):
            rc = m.cmd_weekly(SimpleNamespace(open_report=False))
        self.assertEqual(rc, 0)
        row = store.scan_history(1)[0]
        self.assertEqual(row["files_scanned"], 3)
        self.assertTrue(row["report_path"])


class TestScanProgress(unittest.TestCase):

    def test_snapshot_hides_the_cancel_flag(self):
        p = engine.ScanProgress(running=True, files_scanned=3)
        snap = p.snapshot()
        self.assertNotIn("cancel", snap)
        self.assertEqual(snap["files_scanned"], 3)
        self.assertTrue(snap["running"])

    def test_snapshot_is_a_copy_not_a_view(self):
        p = engine.ScanProgress()
        snap = p.snapshot()
        snap["files_scanned"] = 99
        self.assertEqual(p.files_scanned, 0)

    def test_notes_default_to_a_fresh_list_per_instance(self):
        a, b = engine.ScanProgress(), engine.ScanProgress()
        a.notes.append("x")
        self.assertEqual(b.notes, [])

    def test_snapshot_is_json_serialisable(self):
        import json
        json.dumps(engine.ScanProgress(notes=["a"]).snapshot())


class TestSha256File(TempEnvMixin, unittest.TestCase):

    def test_matches_hashlib_and_reports_the_byte_count(self):
        import hashlib
        body = os.urandom(3 * 1024 * 1024 + 17)   # spans several CHUNK reads
        p = self.write("blob.bin", body)
        sha, size = engine.sha256_file(str(p))
        self.assertEqual(sha, hashlib.sha256(body).hexdigest())
        self.assertEqual(size, len(body))

    def test_empty_file_hashes_to_the_known_empty_digest(self):
        p = self.write("empty.bin", b"")
        self.assertEqual(engine.sha256_file(str(p)),
                         ("e3b0c44298fc1c149afbf4c8996fb924"
                          "27ae41e4649b934ca495991b7852b855", 0))


if __name__ == "__main__":
    unittest.main()


class TestProtectedDamping(TempEnvMixin, unittest.TestCase):
    """Structural findings are damped in app folders; malice is not."""

    STRUCTURAL = ["Known packer signature: UPX",
                  "High-entropy section(s) suggesting packed or encrypted code",
                  "Section marked both writable and executable: UPX1"]

    def test_structural_only_findings_are_damped(self):
        score, reasons = engine.damp_protected(
            80, list(self.STRUCTURAL), "inside a protected application folder (steamapps)")
        self.assertLess(score, 80)
        self.assertEqual(score, int(round(80 * engine.PROTECTED_DAMPING)))
        self.assertTrue(any("Score reduced from 80" in r for r in reasons))
        self.assertTrue(any("Quarantine is blocked" in r for r in reasons))

    def test_a_known_bad_hash_is_never_damped(self):
        reasons = self.STRUCTURAL + [
            "SHA-256 matches known-malicious hash feed (family: Emotet)"]
        score, out = engine.damp_protected(90, reasons, "inside a protected folder (steamapps)")
        self.assertEqual(score, 90, "a hash-feed match must keep full score")
        self.assertTrue(any(r.startswith("NOTE:") for r in out))

    def test_behavioural_script_evidence_is_never_damped(self):
        for signal in ("Attempts to add Windows Defender exclusions",
                       "Deletes shadow copies / tampers with recovery",
                       "YARA rule matched: Trojan_Generic",
                       "File extension is .txt but content is a Windows PE executable"):
            with self.subTest(signal=signal):
                score, _ = engine.damp_protected(75, [signal], "protected (steamapps)")
                self.assertEqual(score, 75, f"{signal!r} must not be damped")

    def test_damping_keeps_the_original_score_visible(self):
        _score, reasons = engine.damp_protected(60, ["Known packer signature: UPX"],
                                                "protected (steamapps)")
        joined = " ".join(reasons)
        self.assertIn("60", joined, "the pre-damping score must stay auditable")
