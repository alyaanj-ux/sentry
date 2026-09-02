"""Unit tests for sentry.behavior -- ransom-note naming and the disk sweep."""
from __future__ import annotations

import os
import sys
import types
import unittest
from unittest import mock

from sentry import behavior, config
from tests.support import TempEnvMixin


# ==========================================================================
# is_ransom_note_name
# ==========================================================================

class TestIsRansomNoteName(unittest.TestCase):
    """A two-directional table. The negatives matter more than the positives:
    a false positive here tells a user their machine has been ransomed."""

    POSITIVE = [
        # action + object
        "HOW_TO_DECRYPT_FILES.txt",
        "how to decrypt files.txt",
        "how-to-decrypt-my-files.html",
        "DECRYPT_INSTRUCTIONS.txt",
        "decrypt-info.hta",
        "RECOVERY_INSTRUCTIONS.txt",
        "recovery_instructions.txt",
        "restore-my-files.txt",
        "RESTORE_FILES_INFO.rtf",
        "unlock_your_data.htm",
        "unlock-instructions.rtf",
        "encrypted_files_recovery.txt",
        "DECRYPT_YOUR_KEY.txt",
        "recover_important_data.txt",
        "restore-guide.txt",
        "decrypt.readme.txt",
        # explicit "ransom" token
        "ransom.txt",
        "ransom_note.txt",
        "MY-RANSOM-DEMAND.html",
        # attention-grabbing prefix + action only
        "!recover.txt",
        "!!!RESTORE!!!.txt",
        "#decrypt.txt",
        "000-restore.txt",
        "000_unlock.htm",
        "readme_-_decrypt.txt",
        # case and extension variants
        "How_To_Decrypt_Files.TXT",
        "HOW_TO_DECRYPT_FILES.HTML",
        "how_to_decrypt_files.hta",
    ]

    NEGATIVE = [
        # bare readme variants -- must never fire
        "readme.txt",
        "README.txt",
        "_readme.txt",
        "readme_first.txt",
        "read_me.txt",
        # wrong extension
        "README.md",
        "HOW_TO_DECRYPT_FILES.md",
        "HOW_TO_DECRYPT_FILES.exe",
        "HOW_TO_DECRYPT_FILES.pdf",
        "HOW_TO_DECRYPT_FILES",
        "decrypt_instructions.docx",
        # no action word
        "how_to_use_this_app.txt",
        "instructions.txt",
        "install_instructions.txt",
        "important.txt",
        "info.txt",
        "help.txt",
        "keys.txt",
        "guide.txt",
        "data.txt",
        "release_notes.txt",
        "how_to_contribute.txt",
        # action word but no object and no aggressive prefix
        "decrypt.txt",
        "restore.txt",
        "unlock.txt",
        "recover.txt",
        "encrypted.txt",
        # ordinary documents
        "notes.txt",
        "shopping list.txt",
        "changelog.txt",
        "LICENSE.txt",
        "requirements.txt",
        "index.html",
        "invoice.rtf",
        "server.log.txt",
        # empty / degenerate
        "",
        ".txt",
        "   .txt",
        "___.txt",
    ]

    def test_positive_cases(self):
        for name in self.POSITIVE:
            with self.subTest(name=name):
                self.assertTrue(behavior.is_ransom_note_name(name),
                                f"{name!r} should look like a ransom note")

    def test_negative_cases(self):
        for name in self.NEGATIVE:
            with self.subTest(name=name):
                self.assertFalse(behavior.is_ransom_note_name(name),
                                 f"{name!r} must NOT look like a ransom note")

    def test_bare_readme_never_matches_in_any_note_extension(self):
        for ext in sorted(behavior.NOTE_EXT):
            with self.subTest(ext=ext):
                self.assertFalse(behavior.is_ransom_note_name("readme" + ext))
                self.assertFalse(behavior.is_ransom_note_name("_readme" + ext))

    def test_action_plus_object_matches_in_every_note_extension(self):
        for ext in sorted(behavior.NOTE_EXT):
            with self.subTest(ext=ext):
                self.assertTrue(
                    behavior.is_ransom_note_name("how_to_decrypt_files" + ext))

    def test_action_plus_object_matches_in_no_other_extension(self):
        for ext in (".md", ".doc", ".docx", ".pdf", ".exe", ".png", ".log", ""):
            with self.subTest(ext=ext):
                self.assertFalse(
                    behavior.is_ransom_note_name("how_to_decrypt_files" + ext))

    def test_every_action_prefix_pairs_with_an_object_word(self):
        for action in behavior._ACTION_PREFIXES:
            with self.subTest(action=action):
                self.assertTrue(
                    behavior.is_ransom_note_name(f"{action}_files.txt"))

    def test_every_object_word_pairs_with_an_action(self):
        for obj in sorted(behavior._OBJECT_WORDS):
            with self.subTest(obj=obj):
                self.assertTrue(
                    behavior.is_ransom_note_name(f"decrypt_{obj}.txt"))

    def test_object_word_alone_is_never_enough(self):
        for obj in sorted(behavior._OBJECT_WORDS):
            with self.subTest(obj=obj):
                self.assertFalse(behavior.is_ransom_note_name(f"{obj}.txt"))
                self.assertFalse(behavior.is_ransom_note_name(f"my_{obj}.txt"))

    def test_separator_characters_all_tokenise(self):
        for sep in ("_", "-", " ", ".", "+", "@", "!"):
            name = f"how{sep}to{sep}decrypt{sep}files.txt"
            with self.subTest(sep=sep):
                self.assertTrue(behavior.is_ransom_note_name(name))

    def test_extension_matching_is_case_insensitive(self):
        for ext in (".TXT", ".Txt", ".HTML", ".HtA", ".RTF"):
            with self.subTest(ext=ext):
                self.assertTrue(
                    behavior.is_ransom_note_name("decrypt_files" + ext))

    def test_the_documented_note_extension_set(self):
        self.assertEqual(behavior.NOTE_EXT,
                         {".txt", ".html", ".htm", ".hta", ".rtf"})


# ==========================================================================
# sweep
# ==========================================================================

class SweepTestCase(TempEnvMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        # Keep the sweep away from the real machine's persistence directories.
        for target, kwargs in (("preset_paths", {"return_value": {"persistence": []}}),
                               ("startup_dirs", {"return_value": []})):
            patcher = mock.patch.object(config, target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)
        # sweep() also enumerates the real HKCU/HKLM Run keys on a Windows
        # host, which adds a run_key_inventory indicator to every result and
        # made every "expect []" test fail there. The registry reader has its
        # own tests (TestRegistryRunKeys) against a fake winreg.
        patcher = mock.patch.object(behavior, "_registry_run_keys", return_value=[])
        patcher.start()
        self.addCleanup(patcher.stop)

    def sweep(self, **cfg):
        params = {"exclusions": []}
        params.update(cfg)
        return behavior.sweep([str(self.sandbox)], params)

    def by_kind(self, indicators) -> dict:
        return {i["kind"]: i for i in indicators}

    def make_encrypted(self, n: int, ext: str = ".locked", sub: str = "docs"):
        for i in range(n):
            self.write(f"{sub}/file{i}{ext}", b"encrypted-bytes")


class TestSweepRansomwareExtension(SweepTestCase):

    def test_three_files_reach_the_cluster_threshold(self):
        self.make_encrypted(3)
        got = self.by_kind(self.sweep())
        self.assertIn("ransomware_extension", got)
        ind = got["ransomware_extension"]
        self.assertEqual(ind["severity"], "high")
        self.assertEqual(ind["count"], 3)
        self.assertIn("'.locked'", ind["title"])
        self.assertIn("3 files", ind["title"])
        self.assertIn("nomoreransom.org", ind["detail"])
        self.assertEqual(len(ind["examples"]), 3)

    def test_two_files_are_below_the_cluster_threshold(self):
        self.make_encrypted(2)
        self.assertNotIn("ransomware_extension", self.by_kind(self.sweep()))

    def test_one_file_is_below_the_cluster_threshold(self):
        self.make_encrypted(1)
        self.assertEqual(self.sweep(), [])

    def test_the_three_file_minimum_is_per_extension_not_overall(self):
        self.make_encrypted(2, ".locked")
        self.make_encrypted(2, ".crypted")
        self.assertNotIn("ransomware_extension", self.by_kind(self.sweep()))

    def test_two_extensions_each_over_the_threshold_yield_two_indicators(self):
        self.make_encrypted(3, ".locked")
        self.make_encrypted(4, ".wncry")
        inds = [i for i in self.sweep() if i["kind"] == "ransomware_extension"]
        self.assertEqual(len(inds), 2)
        self.assertEqual({i["count"] for i in inds}, {3, 4})

    def test_examples_are_capped_at_eight_while_count_is_exact(self):
        self.make_encrypted(20)
        ind = self.by_kind(self.sweep())["ransomware_extension"]
        self.assertEqual(ind["count"], 20)
        self.assertEqual(len(ind["examples"]), 8)

    def test_examples_are_absolute_paths_that_exist(self):
        self.make_encrypted(3)
        ind = self.by_kind(self.sweep())["ransomware_extension"]
        for path in ind["examples"]:
            self.assertTrue(os.path.isabs(path), path)
            self.assertTrue(os.path.exists(path), path)

    def test_extension_matching_is_case_insensitive(self):
        for i in range(3):
            self.write(f"docs/f{i}.LOCKED", b"x")
        self.assertIn("ransomware_extension", self.by_kind(self.sweep()))

    def test_a_sample_of_known_extensions_all_cluster(self):
        for ext in (".locked", ".encrypted", ".wncry", ".lockbit", ".phobos",
                    ".djvu", ".conti", ".ryuk"):
            with self.subTest(ext=ext):
                box = self.sandbox / ext.strip(".")
                box.mkdir()
                for i in range(3):
                    (box / f"f{i}{ext}").write_bytes(b"x")
                found = [i for i in behavior.sweep([str(box)], {"exclusions": []})
                         if i["kind"] == "ransomware_extension"]
                self.assertEqual(len(found), 1)
                self.assertIn(f"'{ext}'", found[0]["title"])

    def test_ordinary_files_produce_no_indicators(self):
        self.write("docs/report.pdf", b"%PDF-1.7")
        self.write("docs/notes.txt", b"hello")
        self.write("docs/photo.jpg", b"\xff\xd8\xff\xe0")
        self.write("docs/backup.tar.gz", b"\x1f\x8b")
        self.assertEqual(self.sweep(), [])


class TestSweepRansomNote(SweepTestCase):

    def test_single_note_with_no_encrypted_files_is_medium(self):
        self.write("docs/HOW_TO_DECRYPT_FILES.txt", "pay us")
        ind = self.by_kind(self.sweep())["ransom_note"]
        self.assertEqual(ind["severity"], "medium")
        self.assertEqual(ind["count"], 1)
        self.assertIn("may be a legitimate", ind["detail"])
        self.assertIn("recovery-instructions", ind["detail"])

    def test_note_plus_a_locked_cluster_is_high(self):
        self.write("docs/HOW_TO_DECRYPT_FILES.txt", "pay us")
        self.make_encrypted(3)
        got = self.by_kind(self.sweep())
        self.assertEqual(got["ransom_note"]["severity"], "high")
        self.assertEqual(got["ransomware_extension"]["severity"], "high")
        self.assertIn("Ransomware drops these", got["ransom_note"]["detail"])

    def test_three_notes_corroborate_each_other_without_encrypted_files(self):
        for i in range(3):
            self.write(f"d{i}/HOW_TO_DECRYPT_FILES.txt", "pay us")
        ind = self.by_kind(self.sweep())["ransom_note"]
        self.assertEqual(ind["severity"], "high")
        self.assertEqual(ind["count"], 3)

    def test_two_notes_alone_stay_medium(self):
        for i in range(2):
            self.write(f"d{i}/HOW_TO_DECRYPT_FILES.txt", "pay us")
        self.assertEqual(self.by_kind(self.sweep())["ransom_note"]["severity"],
                         "medium")

    def test_a_single_encrypted_file_is_enough_to_corroborate_a_note(self):
        """Documents the intended asymmetry: corroboration keys off *any*
        ransomware-extension sighting, not the 3-file cluster indicator."""
        self.write("docs/HOW_TO_DECRYPT_FILES.txt", "pay us")
        self.make_encrypted(1)
        got = self.by_kind(self.sweep())
        self.assertEqual(got["ransom_note"]["severity"], "high")
        self.assertNotIn("ransomware_extension", got,
                         "one file is still below the cluster threshold")

    def test_note_examples_are_capped_at_eight(self):
        for i in range(12):
            self.write(f"d{i}/HOW_TO_DECRYPT_FILES.txt", "pay us")
        ind = self.by_kind(self.sweep())["ransom_note"]
        self.assertEqual(ind["count"], 12)
        self.assertEqual(len(ind["examples"]), 8)

    def test_a_legitimate_readme_produces_no_note_indicator(self):
        self.write("docs/README.txt", "how to use this program")
        self.write("docs/_readme.txt", "hello")
        self.write("docs/how_to_use_this_app.txt", "hello")
        self.assertEqual(self.sweep(), [])


class TestSweepAutostart(SweepTestCase):

    def autostart_sweep(self, autostart_dir):
        # Only the real Start Menu Startup folders count as autostart now; the
        # 'persistence' preset also holds %TEMP%, which must not.
        with mock.patch.object(config, "startup_dirs",
                               return_value=[str(autostart_dir)]):
            return behavior.sweep([str(self.sandbox)], {"exclusions": []})

    def test_executable_in_an_autostart_directory_is_medium(self):
        d = self.sandbox / "Startup"
        d.mkdir()
        (d / "updater.exe").write_bytes(b"MZ")
        got = self.by_kind(self.autostart_sweep(d))
        ind = got["autostart_entry"]
        self.assertEqual(ind["severity"], "medium")
        self.assertEqual(ind["count"], 1)
        self.assertIn("runs automatically at logon", ind["detail"])
        self.assertEqual(ind["examples"], [str(d / "updater.exe")])

    def test_every_suspicious_autostart_extension_is_reported(self):
        d = self.sandbox / "Startup"
        d.mkdir()
        for ext in sorted(behavior.SUSPICIOUS_AUTOSTART_EXT):
            (d / f"thing{ext}").write_bytes(b"x")
        ind = self.by_kind(self.autostart_sweep(d))["autostart_entry"]
        self.assertEqual(ind["count"], len(behavior.SUSPICIOUS_AUTOSTART_EXT))

    def test_harmless_files_in_an_autostart_directory_are_ignored(self):
        d = self.sandbox / "Startup"
        d.mkdir()
        for name in ("desktop.ini", "notes.txt", "shortcut.url", "readme.md"):
            (d / name).write_bytes(b"x")
        self.assertEqual(self.autostart_sweep(d), [])

    def test_executables_outside_an_autostart_directory_are_ignored(self):
        d = self.sandbox / "Startup"
        d.mkdir()
        other = self.sandbox / "Elsewhere"
        other.mkdir()
        (other / "updater.exe").write_bytes(b"MZ")
        self.assertEqual(self.autostart_sweep(d), [])

    def test_subdirectories_of_an_autostart_directory_are_not_autostart(self):
        d = self.sandbox / "Startup"
        (d / "sub").mkdir(parents=True)
        (d / "sub" / "updater.exe").write_bytes(b"MZ")
        self.assertEqual(self.autostart_sweep(d), [])

    def test_examples_are_capped_at_ten(self):
        d = self.sandbox / "Startup"
        d.mkdir()
        for i in range(15):
            (d / f"p{i}.exe").write_bytes(b"MZ")
        ind = self.by_kind(self.autostart_sweep(d))["autostart_entry"]
        self.assertEqual(ind["count"], 15)
        self.assertEqual(len(ind["examples"]), 10)


class TestSweepTraversal(SweepTestCase):

    def test_nonexistent_root_paths_are_skipped(self):
        self.assertEqual(behavior.sweep(
            ["/no/such/place", str(self.sandbox / "ghost")], {"exclusions": []}), [])

    def test_a_file_passed_as_a_root_is_skipped(self):
        f = self.write("a.locked", b"x")
        self.assertEqual(behavior.sweep([str(f)], {"exclusions": []}), [])

    def test_no_roots_yields_no_indicators(self):
        self.assertEqual(behavior.sweep([], {"exclusions": []}), [])

    @unittest.skipUnless(config.IS_WINDOWS, "exercises the real Win32 \\\\?\\ prefix")
    def test_evidence_beyond_max_path_is_still_swept(self):
        """Same walk bug as engine.iter_candidate_files: a bare root lost every
        directory past 260 characters, which is where ransomware evidence in a
        deep project or backup tree would live."""
        import shutil
        seg = "segment_" + "x" * 40
        deep = str(self.sandbox)
        while len(deep) < 300:
            deep = os.path.join(deep, seg)
        os.makedirs("\\\\?\\" + deep, exist_ok=True)
        self.addCleanup(shutil.rmtree, "\\\\?\\" + str(self.sandbox), ignore_errors=True)
        for i in range(3):
            with open("\\\\?\\" + os.path.join(deep, f"f{i}.locked"), "wb") as fh:
                fh.write(b"x")
        got = self.by_kind(self.sweep())
        self.assertIn("ransomware_extension", got)
        self.assertFalse(any(e.startswith("\\\\?\\")
                             for e in got["ransomware_extension"]["examples"]))

    def test_nested_directories_are_walked(self):
        for i in range(3):
            self.write(f"a/b/c/d/f{i}.locked", b"x")
        self.assertIn("ransomware_extension", self.by_kind(self.sweep()))

    def test_the_sentry_data_root_is_never_swept(self):
        (config.DATA_ROOT / "quarantine").mkdir(parents=True, exist_ok=True)
        for i in range(5):
            (config.DATA_ROOT / "quarantine" / f"f{i}.locked").write_bytes(b"x")
        got = behavior.sweep([str(config.DATA_ROOT)], {"exclusions": []})
        self.assertEqual(got, [], "quarantined evidence must not re-alert")

    def test_an_excluded_subtree_is_skipped(self):
        skip = self.sandbox / "skipme"
        skip.mkdir()
        for i in range(3):
            (skip / f"f{i}.locked").write_bytes(b"x")
        self.assertEqual(self.sweep(exclusions=[str(skip)]), [])

    def test_excluding_a_subtree_leaves_its_siblings_alone(self):
        skip = self.sandbox / "skipme"
        keep = self.sandbox / "keepme"
        skip.mkdir()
        keep.mkdir()
        for i in range(3):
            (skip / f"f{i}.locked").write_bytes(b"x")
            (keep / f"g{i}.crypted").write_bytes(b"x")
        ind = self.by_kind(self.sweep(exclusions=[str(skip)]))
        self.assertIn("ransomware_extension", ind)
        self.assertEqual(ind["ransomware_extension"]["count"], 3)
        self.assertIn("'.crypted'", ind["ransomware_extension"]["title"])

    def test_exclusions_expand_no_variables_but_do_not_crash(self):
        self.make_encrypted(3)
        got = self.by_kind(self.sweep(exclusions=["$NO_SUCH_VAR/x"]))
        self.assertIn("ransomware_extension", got)

    def test_missing_exclusions_key_is_tolerated(self):
        self.make_encrypted(3)
        got = behavior.sweep([str(self.sandbox)], {})
        self.assertEqual(len(got), 1)

    # ---- regression tests for fixed bugs --------------------------------

    def test_BUG_exclusion_prefix_match_swallows_sibling_directories(self):
        """REGRESSION TEST (fixed): exclusion match now has a separator boundary.

        The bug described below is fixed in this build; this test now guards
        against a regression.

        Original report: BUG behavior.py:80 -- exclusion match has no path-separator boundary.

        `nc.startswith(normcase(normpath(e)))` treats any directory whose name
        merely *starts with* an exclusion as excluded, so excluding
        `.../foo` also silently excludes `.../foobar`, `.../foo-backup`, and
        `C:\\Windows\\Installer` excludes `C:\\Windows\\InstallerCache`. Real
        ransomware evidence in those siblings is never reported. engine.py:61
        gets this right (`e.rstrip(os.sep) + os.sep`); this line needs the same
        treatment.
        """
        foo = self.sandbox / "foo"
        foobar = self.sandbox / "foobar"
        foo.mkdir()
        foobar.mkdir()
        for i in range(3):
            (foobar / f"f{i}.locked").write_bytes(b"x")
        got = self.by_kind(self.sweep(exclusions=[str(foo)]))
        self.assertIn("ransomware_extension", got,
                      "excluding .../foo must not exclude .../foobar")


# ==========================================================================
# _registry_run_keys
# ==========================================================================

class FakeWinregKey:
    def __init__(self, values):
        self.values = values

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def make_fake_winreg(keys: dict):
    """`keys` maps (hive, subkey) -> [(name, value, type), ...]."""
    mod = types.ModuleType("winreg")
    mod.HKEY_CURRENT_USER = 0x80000001
    mod.HKEY_LOCAL_MACHINE = 0x80000002

    # sentry.behavior enumerates both registry views, so the double has to
    # accept OpenKey(hive, subkey, reserved, access) as well as the 2-arg form
    # and expose the access-flag constants.
    mod.KEY_READ = 0x20019
    mod.KEY_WOW64_64KEY = 0x0100
    mod.KEY_WOW64_32KEY = 0x0200

    def open_key(hive, subkey, reserved=0, access=None):
        if (hive, subkey) not in keys:
            raise OSError("key not found")
        if access is not None and access & mod.KEY_WOW64_32KEY:
            # The 32-bit view of these keys is the Wow6432Node copy, which the
            # fake registry does not contain.
            raise OSError("key not found")
        return FakeWinregKey(keys[(hive, subkey)])

    def enum_value(key, index):
        try:
            return key.values[index]
        except IndexError:
            raise OSError("no more values") from None

    mod.OpenKey = open_key
    mod.EnumValue = enum_value
    return mod


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
HKCU = 0x80000001


class TestRegistryRunKeys(unittest.TestCase):

    def run_with(self, keys):
        fake = make_fake_winreg(keys)
        with mock.patch.object(config, "IS_WINDOWS", True), \
                mock.patch.dict(sys.modules, {"winreg": fake}):
            return behavior._registry_run_keys()

    def by_kind(self, indicators):
        return {i["kind"]: i for i in indicators}

    def test_returns_nothing_on_non_windows(self):
        with mock.patch.object(config, "IS_WINDOWS", False):
            self.assertEqual(behavior._registry_run_keys(), [])

    def test_no_readable_keys_yields_no_indicators(self):
        self.assertEqual(self.run_with({}), [])

    def test_benign_entries_produce_an_inventory_only(self):
        got = self.by_kind(self.run_with({(HKCU, RUN_KEY): [
            ("OneDrive", r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", 1),
            ("Steam", r"D:\Steam\steam.exe -silent", 1),
        ]}))
        self.assertNotIn("suspicious_run_key", got)
        self.assertEqual(got["run_key_inventory"]["severity"], "info")
        self.assertEqual(got["run_key_inventory"]["count"], 2)

    def test_each_suspicious_token_is_flagged(self):
        tokens = ["powershell -c x", "cmd /c app.exe -enc AAAA",
                  "x FromBase64String(y)", "mshta http://h/a",
                  "rundll32 javascript:x", "certutil -urlcache http://h",
                  "wscript x.vbs", r"C:\Users\u\AppData\Local\Temp\a.exe",
                  r"C:\Users\u\AppData\Roaming\Temp\b.exe"]
        for value in tokens:
            with self.subTest(value=value):
                got = self.by_kind(self.run_with(
                    {(HKCU, RUN_KEY): [("Entry", value, 1)]}))
                self.assertIn("suspicious_run_key", got, value)
                self.assertEqual(got["suspicious_run_key"]["severity"], "high")

    def test_token_matching_is_case_insensitive(self):
        got = self.by_kind(self.run_with(
            {(HKCU, RUN_KEY): [("E", "POWERSHELL.EXE -File a.ps1", 1)]}))
        self.assertIn("suspicious_run_key", got)

    def test_inventory_includes_both_flagged_and_benign_entries(self):
        got = self.by_kind(self.run_with({(HKCU, RUN_KEY): [
            ("Good", r"C:\App\app.exe", 1),
            ("Bad", "powershell -enc AAAA", 1),
        ]}))
        self.assertEqual(got["suspicious_run_key"]["count"], 1)
        self.assertEqual(got["run_key_inventory"]["count"], 2)

    def test_entry_labels_name_the_hive_and_value(self):
        got = self.by_kind(self.run_with(
            {(HKCU, RUN_KEY): [("Updater", "powershell -enc AA", 1)]}))
        example = got["suspicious_run_key"]["examples"][0]
        self.assertIn("HKCU", example)
        self.assertIn(RUN_KEY, example)
        self.assertIn("Updater", example)
        self.assertIn("powershell", example)

    def test_inventory_examples_are_capped_at_25(self):
        got = self.by_kind(self.run_with({(HKCU, RUN_KEY): [
            (f"E{i}", rf"C:\App\a{i}.exe", 1) for i in range(40)]}))
        self.assertEqual(got["run_key_inventory"]["count"], 40)
        self.assertEqual(len(got["run_key_inventory"]["examples"]), 25)

    def test_a_missing_winreg_module_is_tolerated(self):
        with mock.patch.object(config, "IS_WINDOWS", True), \
                mock.patch.dict(sys.modules, {"winreg": None}):
            self.assertEqual(behavior._registry_run_keys(), [])

    def test_sweep_appends_registry_indicators(self):
        fake = make_fake_winreg({(HKCU, RUN_KEY): [("E", "powershell -enc A", 1)]})
        with mock.patch.object(config, "IS_WINDOWS", True), \
                mock.patch.object(config, "startup_dirs", return_value=[]), \
                mock.patch.dict(sys.modules, {"winreg": fake}):
            kinds = [i["kind"] for i in behavior.sweep([], {"exclusions": []})]
        self.assertEqual(kinds, ["suspicious_run_key", "run_key_inventory"])


class TestIndicatorShape(SweepTestCase):
    """Every indicator must carry the keys report.py and webui.py rely on."""

    REQUIRED = {"kind", "severity", "title", "detail", "examples", "count"}

    def test_all_indicator_kinds_have_the_required_keys(self):
        self.write("docs/HOW_TO_DECRYPT_FILES.txt", "pay")
        self.make_encrypted(3)
        d = self.sandbox / "Startup"
        d.mkdir()
        (d / "x.exe").write_bytes(b"MZ")
        with mock.patch.object(config, "startup_dirs", return_value=[str(d)]):
            indicators = behavior.sweep([str(self.sandbox)], {"exclusions": []})
        self.assertEqual({i["kind"] for i in indicators},
                         {"ransomware_extension", "ransom_note",
                          "autostart_entry"})
        for ind in indicators:
            with self.subTest(kind=ind["kind"]):
                self.assertLessEqual(self.REQUIRED, set(ind))
                self.assertIn(ind["severity"], {"info", "low", "medium", "high"})
                self.assertIsInstance(ind["examples"], list)
                self.assertIsInstance(ind["count"], int)
                self.assertTrue(ind["title"].strip())
                self.assertTrue(ind["detail"].strip())


if __name__ == "__main__":
    unittest.main()
