"""Unit tests for sentry.config -- path containment, pruning, config I/O."""
from __future__ import annotations

import json
import ntpath
import os
import unittest
from pathlib import Path
from unittest import mock

from sentry import config
from tests.support import CONFIG_PATH_ATTRS, FakeNtOs, TempEnvMixin


class TestIsWithinPosix(unittest.TestCase):
    """Boundary correctness of the parent/child test on POSIX semantics."""

    def test_exact_match_is_within(self):
        self.assertTrue(config._is_within("/foo", "/foo"))
        self.assertTrue(config._is_within("/foo/bar", "/foo/bar"))
        self.assertTrue(config._is_within("/", "/"))

    def test_real_child_is_within(self):
        self.assertTrue(config._is_within("/foo/bar", "/foo"))
        self.assertTrue(config._is_within("/foo/bar/baz/qux.txt", "/foo"))
        self.assertTrue(config._is_within("/home/u/Downloads/x", "/home/u"))

    def test_sibling_sharing_a_name_prefix_is_NOT_within(self):
        """The classic prefix bug: /foobar must not be inside /foo."""
        self.assertFalse(config._is_within("/foobar", "/foo"))
        self.assertFalse(config._is_within("/foobar/baz", "/foo"))
        self.assertFalse(config._is_within("/foo2", "/foo"))
        self.assertFalse(config._is_within("/home/user2/x", "/home/user"))
        self.assertFalse(config._is_within("/tmp/scan-data", "/tmp/scan"))

    def test_parent_is_not_within_its_own_child(self):
        self.assertFalse(config._is_within("/foo", "/foo/bar"))

    def test_unrelated_paths_are_not_within(self):
        self.assertFalse(config._is_within("/var/log", "/usr/lib"))

    def test_trailing_separator_on_the_parent_is_tolerated(self):
        for parent in ("/foo", "/foo/", "/foo//", "/foo/."):
            with self.subTest(parent=parent):
                self.assertTrue(config._is_within("/foo/bar", parent))
                self.assertTrue(config._is_within("/foo", parent))
                self.assertFalse(config._is_within("/foobar", parent))

    def test_trailing_separator_on_the_child_is_tolerated(self):
        self.assertTrue(config._is_within("/foo/bar/", "/foo"))
        self.assertTrue(config._is_within("/foo/", "/foo"))

    def test_redundant_separators_and_dots_are_normalised(self):
        self.assertTrue(config._is_within("/foo//bar", "/foo"))
        self.assertTrue(config._is_within("/foo/./bar", "/foo"))
        self.assertTrue(config._is_within("/foo/baz/../bar", "/foo"))

    def test_root_contains_everything(self):
        self.assertTrue(config._is_within("/anything/at/all", "/"))

    @unittest.skipIf(config.IS_WINDOWS, "POSIX paths are case-sensitive")
    def test_case_matters_on_posix(self):
        self.assertFalse(config._is_within("/Foo/bar", "/foo"))


class TestIsWithinWindows(unittest.TestCase):
    """Same function, Windows path semantics, simulated so it runs on Linux."""

    def setUp(self):
        patcher = mock.patch.object(config, "os", FakeNtOs())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_windows_paths_are_case_insensitive(self):
        self.assertTrue(config._is_within(r"C:\Users\Me\Downloads", r"c:\users\me"))
        self.assertTrue(config._is_within(r"c:\USERS\me\x", r"C:\Users\Me"))
        self.assertTrue(config._is_within(r"C:\FOO", r"c:\foo"))

    def test_prefix_siblings_are_still_excluded_case_insensitively(self):
        self.assertFalse(config._is_within(r"C:\FooBar", r"c:\foo"))
        self.assertFalse(config._is_within(r"C:\Windows2\x", r"C:\Windows"))

    def test_backslash_trailing_separator_is_tolerated(self):
        self.assertTrue(config._is_within(r"C:\foo\bar", "C:\\foo\\"))
        self.assertTrue(config._is_within(r"C:\foo\bar", "C:\\foo"))

    def test_drive_root_contains_everything_on_that_drive(self):
        self.assertTrue(config._is_within(r"C:\Users\x", "C:\\"))
        self.assertFalse(config._is_within(r"D:\Users\x", "C:\\"))

    def test_forward_slashes_are_normalised_to_backslashes(self):
        self.assertTrue(config._is_within("C:/foo/bar", r"C:\foo"))
        self.assertFalse(config._is_within("C:/foobar", r"C:\foo"))

    def test_unc_paths(self):
        self.assertTrue(config._is_within(r"\\srv\share\dir\f", r"\\srv\share"))
        self.assertFalse(config._is_within(r"\\srv\share2", r"\\srv\share"))

    def test_normcase_is_actually_being_applied(self):
        # Sanity check the simulation itself, so a green suite means something.
        self.assertEqual(config.os.path, ntpath)
        self.assertEqual(config.os.path.normcase(r"C:\Foo"), r"c:\foo")


class TestResolvedScanPaths(TempEnvMixin, unittest.TestCase):

    def cfg(self, custom):
        return {"enabled_presets": [], "custom_paths": custom}

    def test_child_is_dropped_when_its_parent_is_present(self):
        parent = self.sandbox / "top"
        child = parent / "nested" / "deep"
        child.mkdir(parents=True)
        got = config.resolved_scan_paths(self.cfg([str(parent), str(child)]))
        self.assertEqual(got, [str(parent)])

    def test_pruning_is_order_independent(self):
        parent = self.sandbox / "top"
        child = parent / "nested"
        child.mkdir(parents=True)
        for order in ([str(parent), str(child)], [str(child), str(parent)]):
            with self.subTest(order=order):
                self.assertEqual(config.resolved_scan_paths(self.cfg(order)),
                                 [str(parent)])

    def test_grandchild_and_child_both_dropped_under_one_parent(self):
        top = self.sandbox / "top"
        (top / "a" / "b").mkdir(parents=True)
        got = config.resolved_scan_paths(self.cfg(
            [str(top / "a" / "b"), str(top / "a"), str(top)]))
        self.assertEqual(got, [str(top)])

    def test_prefix_sibling_directories_are_both_kept(self):
        a = self.sandbox / "data"
        b = self.sandbox / "data-backup"
        a.mkdir()
        b.mkdir()
        got = config.resolved_scan_paths(self.cfg([str(a), str(b)]))
        self.assertEqual(sorted(got), sorted([str(a), str(b)]))

    def test_unrelated_siblings_are_both_kept(self):
        a = self.sandbox / "one"
        b = self.sandbox / "two"
        a.mkdir()
        b.mkdir()
        self.assertEqual(sorted(config.resolved_scan_paths(self.cfg(
            [str(a), str(b)]))), sorted([str(a), str(b)]))

    def test_nonexistent_paths_are_dropped(self):
        real = self.sandbox / "real"
        real.mkdir()
        got = config.resolved_scan_paths(self.cfg(
            [str(real), str(self.sandbox / "ghost"), "/definitely/not/here"]))
        self.assertEqual(got, [str(real)])

    def test_all_paths_nonexistent_yields_an_empty_list(self):
        self.assertEqual(config.resolved_scan_paths(
            self.cfg(["/no/such/dir", "/also/missing"])), [])

    def test_exact_duplicates_are_collapsed(self):
        d = self.sandbox / "dup"
        d.mkdir()
        got = config.resolved_scan_paths(self.cfg([str(d), str(d), str(d)]))
        self.assertEqual(got, [str(d)])

    def test_equivalent_spellings_of_one_path_are_collapsed(self):
        d = self.sandbox / "dup"
        (d / "sub").mkdir(parents=True)
        spellings = [str(d), str(d) + "/", str(d) + "/.",
                     str(d / "sub" / ".."), str(d) + "//"]
        got = config.resolved_scan_paths(self.cfg(spellings))
        self.assertEqual(got, [str(d)])

    def test_relative_paths_are_made_absolute(self):
        d = self.sandbox / "rel"
        d.mkdir()
        cwd = os.getcwd()
        os.chdir(self.sandbox)
        self.addCleanup(os.chdir, cwd)
        got = config.resolved_scan_paths(self.cfg(["rel"]))
        self.assertEqual(got, [str(d)])
        self.assertTrue(os.path.isabs(got[0]))

    def test_environment_variables_in_custom_paths_are_expanded(self):
        d = self.sandbox / "envdir"
        d.mkdir()
        with mock.patch.dict(os.environ, {"SENTRY_UT_DIR": str(d)}):
            self.assertEqual(config.resolved_scan_paths(
                self.cfg(["$SENTRY_UT_DIR"])), [str(d)])

    def test_tilde_in_custom_paths_is_expanded(self):
        # ntpath.expanduser reads USERPROFILE, never HOME.
        with mock.patch.dict(os.environ, {"HOME": str(self.sandbox),
                                          "USERPROFILE": str(self.sandbox)}):
            self.assertEqual(config.resolved_scan_paths(self.cfg(["~"])),
                             [str(self.sandbox)])

    def test_a_file_path_survives_because_it_exists(self):
        f = self.write("thing.exe", b"MZ")
        self.assertEqual(config.resolved_scan_paths(self.cfg([str(f)])), [str(f)])

    def test_enabled_preset_paths_are_included(self):
        d = self.sandbox / "preset_target"
        d.mkdir()
        with mock.patch.object(config, "preset_paths",
                               return_value={"fake": [str(d)]}):
            got = config.resolved_scan_paths(
                {"enabled_presets": ["fake"], "custom_paths": []})
        self.assertEqual(got, [str(d)])

    def test_unknown_preset_names_are_ignored(self):
        got = config.resolved_scan_paths(
            {"enabled_presets": ["no_such_preset"], "custom_paths": []})
        self.assertEqual(got, [])

    def test_preset_and_custom_paths_are_deduplicated_against_each_other(self):
        d = self.sandbox / "shared"
        d.mkdir()
        with mock.patch.object(config, "preset_paths",
                              return_value={"fake": [str(d)]}):
            got = config.resolved_scan_paths(
                {"enabled_presets": ["fake"], "custom_paths": [str(d)]})
        self.assertEqual(got, [str(d)])

    def test_missing_keys_in_a_nonempty_config_dict_are_tolerated(self):
        self.assertEqual(config.resolved_scan_paths({"custom_paths": []}), [])
        self.assertEqual(config.resolved_scan_paths({"enabled_presets": []}), [])

    def test_BUG_empty_config_dict_silently_reloads_from_disk(self):
        """REGRESSION TEST (fixed): an empty cfg dict is no longer reloaded from disk.

        The bug described below is fixed in this build; this test now guards
        against a regression.

        Original report: BUG config.py:148 -- `cfg = cfg or load_config()`.

        An explicitly-passed empty dict is falsy, so the caller's "scan
        nothing" intent is replaced by whatever is in ~/.sentry/config.json (or
        the defaults, which enable the high_risk and persistence presets). A
        caller asking for an empty scope silently gets Downloads, Desktop,
        Documents and /tmp instead. Should be
        `cfg = load_config() if cfg is None else cfg`. The same idiom appears in
        engine.run_scan (`cfg = cfg or config.load_config()`).
        """
        config.CONFIG_PATH.write_text(json.dumps(
            {"enabled_presets": ["high_risk"], "custom_paths": []}),
            encoding="utf-8")
        self.assertEqual(config.resolved_scan_paths({}), [])

    def test_falls_back_to_the_saved_config_when_none_is_passed(self):
        d = self.sandbox / "from_file"
        d.mkdir()
        config.CONFIG_PATH.write_text(json.dumps(
            {"enabled_presets": [], "custom_paths": [str(d)]}), encoding="utf-8")
        self.assertEqual(config.resolved_scan_paths(), [str(d)])


class TestPresetPaths(TempEnvMixin, unittest.TestCase):

    def test_posix_presets_contain_the_documented_keys(self):
        with mock.patch.object(config, "IS_WINDOWS", False):
            presets = config.preset_paths()
        self.assertEqual(set(presets), {"high_risk", "persistence",
                                        "user_profile", "whole_drive"})
        self.assertEqual(presets["whole_drive"], ["/"])

    def test_windows_presets_use_the_environment(self):
        env = {"USERPROFILE": r"C:\Users\Tester", "APPDATA": r"C:\Users\Tester\AppData\Roaming",
               "LOCALAPPDATA": r"C:\Users\Tester\AppData\Local",
               "WINDIR": r"C:\Windows", "SystemDrive": "C:", "TEMP": r"C:\Temp"}
        with mock.patch.object(config, "IS_WINDOWS", True), \
                mock.patch.dict(os.environ, env, clear=False):
            presets = config.preset_paths()
        self.assertIn(os.path.join(r"C:\Users\Tester", "Downloads"),
                      presets["high_risk"])
        self.assertIn(os.path.join(r"C:\Users\Tester", "Desktop"),
                      presets["high_risk"])
        self.assertEqual(presets["user_profile"], [r"C:\Users\Tester"])
        # The Windows branch is literal about the separator (it must not depend
        # on the host's os.sep, which is '/' when these tests run on Linux).
        self.assertEqual(presets["whole_drive"], ["C:" + "\\"])

    def test_empty_environment_entries_are_filtered_out(self):
        with mock.patch.object(config, "IS_WINDOWS", True), \
                mock.patch.dict(os.environ, {"USERPROFILE": r"C:\U", "APPDATA": "",
                                             "LOCALAPPDATA": "", "WINDIR": "",
                                             "SystemDrive": "C:"}, clear=False):
            presets = config.preset_paths()
        for name, paths in presets.items():
            self.assertNotIn("", paths, name)

    def test_every_preset_has_a_human_readable_label(self):
        with mock.patch.object(config, "IS_WINDOWS", False):
            for name in config.preset_paths():
                self.assertIn(name, config.PRESET_LABELS)
                self.assertTrue(config.PRESET_LABELS[name].strip())


class TestDataRoot(unittest.TestCase):

    def test_posix_data_root_is_dot_sentry_under_home(self):
        # USERPROFILE too: on a Windows host expanduser() ignores HOME.
        with mock.patch.object(config, "IS_WINDOWS", False), \
                mock.patch.dict(os.environ, {"HOME": "/home/tester",
                                             "USERPROFILE": "/home/tester"}):
            self.assertEqual(config._data_root(), Path("/home/tester/.sentry"))

    def test_windows_data_root_prefers_localappdata(self):
        with mock.patch.object(config, "IS_WINDOWS", True), \
                mock.patch.dict(os.environ, {"LOCALAPPDATA": "/appdata/local"}):
            self.assertEqual(config._data_root(), Path("/appdata/local/Sentry"))

    def test_windows_data_root_falls_back_to_home(self):
        env = dict(os.environ)
        env.pop("LOCALAPPDATA", None)
        env["HOME"] = "/home/tester"
        env["USERPROFILE"] = "/home/tester"   # what expanduser reads on Windows
        with mock.patch.object(config, "IS_WINDOWS", True), \
                mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(config._data_root(), Path("/home/tester/Sentry"))


class TestConfigLoadSave(TempEnvMixin, unittest.TestCase):

    def test_load_returns_defaults_when_no_file_exists(self):
        self.assertFalse(config.CONFIG_PATH.exists())
        self.assertEqual(config.load_config(), config.DEFAULTS)

    def test_load_does_not_alias_the_defaults_dict(self):
        cfg = config.load_config()
        cfg["report_threshold"] = 999
        cfg["custom_paths"].append("/mutated")
        self.assertEqual(config.DEFAULTS["report_threshold"], 25)
        # Nested mutables are shared (dict(DEFAULTS) is a shallow copy); if this
        # ever changes, tighten the assertion below.
        config.DEFAULTS["custom_paths"] = []

    def test_save_then_load_round_trips_every_value(self):
        payload = {"report_threshold": 61, "max_file_mb": 7,
                   "use_yara": False, "use_hash_feed": False,
                   "follow_symlinks": True, "web_port": 9999,
                   "enabled_presets": ["persistence"],
                   "custom_paths": ["/tmp/a", "/tmp/b"],
                   "exclusions": ["/tmp/skip"]}
        config.save_config(payload)
        loaded = config.load_config()
        for key, value in payload.items():
            self.assertEqual(loaded[key], value, key)

    def test_save_is_a_partial_update_not_a_replacement(self):
        config.save_config({"report_threshold": 40})
        config.save_config({"max_file_mb": 9})
        loaded = config.load_config()
        self.assertEqual(loaded["report_threshold"], 40)
        self.assertEqual(loaded["max_file_mb"], 9)
        self.assertEqual(loaded["web_port"], config.DEFAULTS["web_port"])

    def test_unknown_keys_are_preserved_across_save_and_load(self):
        config.save_config({"future_feature": {"nested": [1, 2, 3]}})
        config.save_config({"report_threshold": 30})
        loaded = config.load_config()
        self.assertEqual(loaded["future_feature"], {"nested": [1, 2, 3]})
        self.assertEqual(loaded["report_threshold"], 30)

    def test_written_file_is_readable_indented_json(self):
        config.save_config({"report_threshold": 33})
        text = config.CONFIG_PATH.read_text(encoding="utf-8")
        self.assertIn("\n  ", text, "expected indent=2 formatting")
        self.assertEqual(json.loads(text)["report_threshold"], 33)

    def test_corrupt_json_falls_back_to_defaults_without_raising(self):
        for junk in ("{not json", "", "[]not-json", "\x00\x01\x02",
                     '{"a": '):
            with self.subTest(junk=junk):
                config.CONFIG_PATH.write_text(junk, encoding="utf-8")
                self.assertEqual(config.load_config(), config.DEFAULTS)

    def test_json_array_at_the_top_level_raises_no_silent_corruption(self):
        # dict.update() with a list of non-pairs raises ValueError/TypeError,
        # which load_config does *not* catch -- documented here so the
        # behaviour is at least known.
        config.CONFIG_PATH.write_text("[1, 2, 3]", encoding="utf-8")
        with self.assertRaises((ValueError, TypeError)):
            config.load_config()

    def test_a_json_object_of_the_wrong_shape_still_loads(self):
        config.CONFIG_PATH.write_text('{"report_threshold": "high"}',
                                      encoding="utf-8")
        self.assertEqual(config.load_config()["report_threshold"], "high")

    def test_unreadable_config_file_falls_back_to_defaults(self):
        config.CONFIG_PATH.write_text('{"report_threshold": 55}', encoding="utf-8")
        with mock.patch.object(Path, "read_text",
                               side_effect=OSError("permission denied")):
            self.assertEqual(config.load_config(), config.DEFAULTS)

    def test_load_creates_the_data_directories(self):
        for d in (config.DATA_ROOT, config.QUARANTINE_DIR, config.REPORTS_DIR,
                  config.RULES_DIR, config.FEED_DIR):
            self.assertTrue(d.is_dir(), d)

    def test_ensure_dirs_is_idempotent(self):
        for _ in range(3):
            config.ensure_dirs()
        self.assertTrue(config.QUARANTINE_DIR.is_dir())


class TestConfigConstants(unittest.TestCase):

    def test_extension_sets_are_lowercase_and_dotted(self):
        for name in ("BINARY_EXT", "SCRIPT_EXT", "MACRO_EXT", "ARCHIVE_EXT",
                     "SKIP_EXT"):
            for ext in getattr(config, name):
                with self.subTest(setname=name, ext=ext):
                    self.assertTrue(ext.startswith("."), ext)
                    self.assertEqual(ext, ext.lower(), ext)

    def test_skip_ext_does_not_overlap_the_inspected_sets(self):
        inspected = config.BINARY_EXT | config.SCRIPT_EXT | config.MACRO_EXT
        self.assertEqual(config.SKIP_EXT & inspected, set(),
                         "an extension is both skipped and inspected")

    def test_defaults_are_internally_consistent(self):
        self.assertIn(config.DEFAULTS["report_threshold"], range(1, 101))
        self.assertFalse(config.DEFAULTS["auto_quarantine"],
                         "auto_quarantine must default to off")
        self.assertFalse(config.DEFAULTS["follow_symlinks"])
        for preset in config.DEFAULTS["enabled_presets"]:
            self.assertIn(preset, config.PRESET_LABELS)

    def test_all_documented_path_attributes_still_exist(self):
        for attr in CONFIG_PATH_ATTRS:
            self.assertIsInstance(getattr(config, attr), Path, attr)

    def test_every_path_attribute_lives_under_the_data_root(self):
        for attr in CONFIG_PATH_ATTRS:
            if attr == "DATA_ROOT":
                continue
            self.assertEqual(getattr(config, attr).parent, config.DATA_ROOT, attr)


if __name__ == "__main__":
    unittest.main()


class TestInstallDirExclusion(TempEnvMixin, unittest.TestCase):
    """Sentry's own folder is excluded by default.

    The test suite deliberately contains the strings the script heuristics look
    for, so scanning the drive Sentry lives on would flag Sentry's own source.
    """

    def test_install_dir_is_the_package_parent(self):
        expected = os.path.dirname(os.path.dirname(
            os.path.abspath(config.__file__)))
        self.assertEqual(config.install_dir(), expected)
        self.assertTrue(os.path.isdir(config.install_dir()))

    def test_install_dir_is_in_the_default_exclusions(self):
        self.assertIn(config.install_dir(), config.DEFAULTS["exclusions"])

    def test_install_dir_is_pruned_even_when_the_saved_exclusions_lack_it(self):
        """Regression: a config.json written by an earlier build (or by the
        dashboard's exclusions editor) has its own exclusions list without the
        install dir, and a real D: scan then reported Sentry's own test
        fixtures as four high- and three medium-severity findings."""
        from sentry import engine
        marker = Path(config.install_dir()) / "requirements.txt"
        if not marker.exists():
            self.skipTest("install dir has no requirements.txt to look for")
        old_style = {"exclusions": [], "follow_symlinks": False}
        self.assertEqual(list(engine.iter_candidate_files([config.install_dir()],
                                                          old_style)), [])
        opted_in = {"exclusions": [], "follow_symlinks": False, "scan_self": True}
        self.assertIn(str(marker),
                      list(engine.iter_candidate_files([config.install_dir()],
                                                       opted_in)))

    def test_games_folder_is_protected(self):
        self.assertTrue(config.is_protected(r"D:\Games\Some Title\game.exe"))
        self.assertFalse(config.is_protected(r"C:\Users\me\Downloads\games.exe"),
                         "the filename itself is not a directory segment")

    def test_a_scan_of_the_parent_drive_skips_the_install_dir(self):
        from sentry import engine
        cfg = dict(config.DEFAULTS)
        marker = Path(config.install_dir()) / "requirements.txt"
        if not marker.exists():
            self.skipTest("install dir has no requirements.txt to look for")
        walked = list(engine.iter_candidate_files([config.install_dir()], cfg))
        self.assertEqual(walked, [],
                         "the install dir must be pruned by its own exclusion")


class TestProtectedLocations(TempEnvMixin, unittest.TestCase):
    """Game and application installs must not be treated as suspicious."""

    PROTECTED = [
        r"D:\SteamLibrary\steamapps\common\Rust\EasyAntiCheat\EasyAntiCheat.exe",
        r"D:\Games\Epic Games\Fortnite\Binaries\Win64\Fortnite.exe",
        r"D:\Riot Games\VALORANT\live\vgc.exe",
        r"C:\Program Files (x86)\Steam\steam.exe",
        r"D:\Battle.net\Overwatch\Overwatch.exe",
        r"D:\GOG Galaxy\Games\Witcher\bin\witcher.exe",
        r"D:\Ubisoft\Ubisoft Game Launcher\upc.exe",
        r"D:\Projects\web\node_modules\.bin\esbuild.exe",
        "/home/u/Games/steamapps/common/x/anticheat.so",
    ]
    ORDINARY = [
        r"D:\Downloads\invoice.pdf.exe",
        r"D:\Desktop\weird.exe",
        r"D:\MySteamNotes\readme.txt",     # substring, not a path segment
        r"D:\steamy\game.exe",
        r"D:\programs\thing.exe",          # not "program files"
    ]

    def test_protected_paths_are_recognised(self):
        for p in self.PROTECTED:
            with self.subTest(path=p):
                self.assertTrue(config.is_protected(p))
                self.assertIn("protected application folder",
                              config.protected_reason(p))

    def test_ordinary_paths_are_not_protected(self):
        for p in self.ORDINARY:
            with self.subTest(path=p):
                self.assertFalse(config.is_protected(p),
                                 f"{p} must not be treated as protected")

    def test_matching_is_on_segments_not_substrings(self):
        # "steamy" contains "steam" but is a different folder entirely.
        self.assertFalse(config.is_protected(r"D:\steamy\x.exe"))
        self.assertTrue(config.is_protected(r"D:\steam\x.exe"))

    def test_a_launcher_name_alone_is_NOT_protective(self):
        """Protecting by filename would let malware immunise itself.

        Anything can name itself EasyAntiCheat.exe; only its location is
        evidence. The real ones all live under a protected directory.
        """
        self.assertFalse(config.is_protected(r"D:\Downloads\EasyAntiCheat.exe"))
        self.assertFalse(config.is_protected(r"D:\Downloads\vgk.sys"))
        self.assertTrue(config.is_protected(
            r"C:\Program Files\Riot Vanguard\vgk.sys"))

    def test_a_launcher_name_outside_an_install_scores_as_a_masquerade(self):
        from sentry import heuristics
        hits = heuristics.check_filename(r"D:\Downloads\EasyAntiCheat.exe")
        self.assertTrue(any("masquerade" in r for _d, r in hits), hits)
        self.assertTrue(any(d >= 25 for d, _r in hits), hits)
        # ...and the genuine one is not scored that way.
        real = heuristics.check_filename(
            r"D:\SteamLibrary\steamapps\common\R\EasyAntiCheat\EasyAntiCheat.exe")
        self.assertFalse(any("masquerade" in r for _d, r in real), real)
