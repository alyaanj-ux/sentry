"""Light coverage for sentry.quarantine: the verdict gate, error paths and the
Windows-only hardening branch. The happy-path round-trip lives in selftest.py."""
from __future__ import annotations

import os
import stat
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from sentry import config, quarantine, store
from tests.support import TempEnvMixin

SHA = "f" * 64


class QuarantineTestCase(TempEnvMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        store.init_db()

    def make_finding(self, *, name="target.exe", body=b"MZ payload bytes",
                     score=60, severity="medium",
                     reasons=("double extension",)) -> dict:
        path = self.write(name, body)
        import hashlib
        sha = hashlib.sha256(body).hexdigest()
        store.upsert_finding({"sha256": sha, "path": str(path),
                              "size": len(body), "mtime": None, "score": score,
                              "severity": severity, "reasons": list(reasons)},
                             scan_id=1)
        return next(f for f in store.get_findings(include_safe=True)
                    if f["path"] == str(path))


class TestVerdictGate(QuarantineTestCase):

    def test_unmarked_file_cannot_be_quarantined(self):
        f = self.make_finding()
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.quarantine_finding(f["id"])
        self.assertIn("marked 'malicious' or 'unknown'", str(ctx.exception))
        self.assertIn("current verdict: none", str(ctx.exception))
        self.assertTrue(Path(f["path"]).exists(), "the file must not be moved")

    def test_safe_verdict_cannot_be_quarantined(self):
        f = self.make_finding()
        store.set_verdict(f["sha256"], "safe")
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.quarantine_finding(f["id"])
        self.assertIn("current verdict: safe", str(ctx.exception))
        self.assertTrue(Path(f["path"]).exists())

    def test_malicious_and_unknown_are_the_only_quarantinable_verdicts(self):
        self.assertEqual(quarantine.QUARANTINABLE, {"malicious", "unknown"})

    def test_each_quarantinable_verdict_is_accepted(self):
        for i, verdict in enumerate(sorted(quarantine.QUARANTINABLE)):
            with self.subTest(verdict=verdict):
                f = self.make_finding(name=f"t{i}.exe", body=f"MZ{i}".encode())
                store.set_verdict(f["sha256"], verdict)
                result = quarantine.quarantine_finding(f["id"])
                self.assertTrue(Path(result["quarantine_path"]).exists())
                self.assertFalse(Path(f["path"]).exists())
                entry = store.get_quarantine_entry(result["quarantine_id"])
                self.assertEqual(entry["verdict"], verdict)

    def test_unknown_finding_id_is_rejected(self):
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.quarantine_finding(4242)
        self.assertIn("No finding with id 4242", str(ctx.exception))

    def test_a_finding_whose_file_has_vanished_is_rejected(self):
        f = self.make_finding()
        store.set_verdict(f["sha256"], "malicious")
        os.unlink(f["path"])
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.quarantine_finding(f["id"])
        self.assertIn("no longer exists", str(ctx.exception))
        self.assertEqual(store.quarantine_list(), [])

    def test_a_failed_move_raises_an_actionable_message(self):
        f = self.make_finding()
        store.set_verdict(f["sha256"], "malicious")
        with mock.patch("shutil.move", side_effect=OSError("locked by process")):
            with self.assertRaises(quarantine.QuarantineError) as ctx:
                quarantine.quarantine_finding(f["id"])
        msg = str(ctx.exception)
        self.assertIn("locked or in use", msg)
        self.assertIn("locked by process", msg)
        self.assertEqual(store.quarantine_list(), [],
                         "no manifest row may be written for a failed move")


class TestUniqueDestination(TempEnvMixin, unittest.TestCase):

    def test_first_destination_is_sha_dot_quar(self):
        self.assertEqual(quarantine._unique_dest(SHA).name, f"{SHA}.quar")

    def test_collisions_get_a_numeric_suffix(self):
        (config.QUARANTINE_DIR / f"{SHA}.quar").write_bytes(b"a")
        self.assertEqual(quarantine._unique_dest(SHA).name, f"{SHA}.1.quar")
        (config.QUARANTINE_DIR / f"{SHA}.1.quar").write_bytes(b"a")
        self.assertEqual(quarantine._unique_dest(SHA).name, f"{SHA}.2.quar")

    def test_destinations_live_inside_the_quarantine_directory(self):
        self.assertEqual(quarantine._unique_dest(SHA).parent,
                         config.QUARANTINE_DIR)

    def test_the_sidecar_name_derived_from_a_suffixed_destination_is_distinct(self):
        (config.QUARANTINE_DIR / f"{SHA}.quar").write_bytes(b"a")
        dest = quarantine._unique_dest(SHA)
        self.assertEqual(dest.with_suffix(".quar.txt").name,
                         f"{SHA}.1.quar.txt")


class TestSidecarAndManifest(QuarantineTestCase):

    def test_sidecar_records_everything_needed_to_restore_without_the_db(self):
        f = self.make_finding(reasons=["reason one", "reason two"])
        store.set_verdict(f["sha256"], "malicious")
        result = quarantine.quarantine_finding(f["id"])
        sidecar = Path(result["quarantine_path"]).with_suffix(".quar.txt")
        self.assertTrue(sidecar.exists())
        text = sidecar.read_text(encoding="utf-8")
        for expected in (f["path"], f["sha256"], "malicious", str(f["score"]),
                         "reason one", "reason two",
                         str(result["quarantine_id"])):
            self.assertIn(expected, text)

    def test_a_failed_sidecar_write_does_not_abort_the_quarantine(self):
        f = self.make_finding()
        store.set_verdict(f["sha256"], "unknown")
        with mock.patch.object(Path, "write_text", side_effect=OSError("full")):
            result = quarantine.quarantine_finding(f["id"])
        self.assertTrue(Path(result["quarantine_path"]).exists())
        self.assertIsNotNone(store.get_quarantine_entry(result["quarantine_id"]))

    def test_quarantine_bytes_are_identical_and_the_original_is_gone(self):
        body = os.urandom(4096)
        f = self.make_finding(body=body)
        store.set_verdict(f["sha256"], "malicious")
        result = quarantine.quarantine_finding(f["id"])
        self.assertEqual(Path(result["quarantine_path"]).read_bytes(), body)
        self.assertFalse(Path(f["path"]).exists())

    def test_an_event_is_logged(self):
        f = self.make_finding()
        store.set_verdict(f["sha256"], "malicious")
        quarantine.quarantine_finding(f["id"])
        import sqlite3
        conn = sqlite3.connect(config.DB_PATH)
        self.addCleanup(conn.close)
        kinds = [r[0] for r in conn.execute("SELECT kind FROM events")]
        self.assertIn("quarantine", kinds)


class TestRestoreErrors(QuarantineTestCase):

    def quarantined(self, name="target.exe"):
        f = self.make_finding(name=name, body=os.urandom(512))
        store.set_verdict(f["sha256"], "malicious")
        return f, quarantine.quarantine_finding(f["id"])

    def test_unknown_id_is_rejected(self):
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.restore(999)
        self.assertIn("No quarantine entry with id 999", str(ctx.exception))

    def test_double_restore_is_rejected(self):
        _f, q = self.quarantined()
        quarantine.restore(q["quarantine_id"])
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.restore(q["quarantine_id"])
        self.assertIn("Already restored", str(ctx.exception))

    def test_restoring_a_purged_entry_is_rejected(self):
        _f, q = self.quarantined()
        quarantine.purge(q["quarantine_id"], confirm=True)
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.restore(q["quarantine_id"])
        self.assertIn("permanently deleted", str(ctx.exception))

    def test_a_missing_quarantine_file_is_reported(self):
        _f, q = self.quarantined()
        # The hardened file is read-only on Windows; a plain unlink is denied.
        quarantine._unharden(Path(q["quarantine_path"]))
        os.unlink(q["quarantine_path"])
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.restore(q["quarantine_id"])
        self.assertIn("missing from", str(ctx.exception))

    def test_restore_refuses_to_overwrite_something_at_the_original_path(self):
        f, q = self.quarantined()
        Path(f["path"]).write_bytes(b"a different file now lives here")
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.restore(q["quarantine_id"])
        self.assertIn("already exists at the original path", str(ctx.exception))
        self.assertEqual(Path(f["path"]).read_bytes(),
                         b"a different file now lives here")
        self.assertTrue(Path(q["quarantine_path"]).exists(),
                        "the quarantined copy must be left in place")

    def test_restore_recreates_a_deleted_parent_directory(self):
        f = self.make_finding(name="sub/dir/target.exe", body=b"MZ deep")
        store.set_verdict(f["sha256"], "malicious")
        q = quarantine.quarantine_finding(f["id"])
        os.rmdir(self.sandbox / "sub" / "dir")
        os.rmdir(self.sandbox / "sub")
        quarantine.restore(q["quarantine_id"])
        self.assertTrue(Path(f["path"]).exists())

    def test_restore_clears_the_verdict_so_the_file_is_re_reviewed(self):
        f, q = self.quarantined()
        quarantine.restore(q["quarantine_id"])
        self.assertIsNone(store.get_verdict(f["sha256"]))

    def test_restore_removes_the_sidecar(self):
        _f, q = self.quarantined()
        sidecar = Path(q["quarantine_path"]).with_suffix(".quar.txt")
        self.assertTrue(sidecar.exists())
        quarantine.restore(q["quarantine_id"])
        self.assertFalse(sidecar.exists())

    @unittest.skipIf(config.IS_WINDOWS, "POSIX permission bits")
    def test_restore_puts_the_original_permission_bits_back(self):
        f = self.make_finding(body=b"MZ mode test")
        os.chmod(f["path"], 0o640)
        store.set_verdict(f["sha256"], "malicious")
        q = quarantine.quarantine_finding(f["id"])
        self.assertEqual(stat.S_IMODE(Path(q["quarantine_path"]).stat().st_mode),
                         0o400, "quarantined files must be read-only")
        quarantine.restore(q["quarantine_id"])
        self.assertEqual(stat.S_IMODE(Path(f["path"]).stat().st_mode), 0o640)


class TestPurge(QuarantineTestCase):

    def quarantined(self):
        f = self.make_finding(body=os.urandom(256))
        store.set_verdict(f["sha256"], "malicious")
        return f, quarantine.quarantine_finding(f["id"])

    def test_confirmation_is_required(self):
        _f, q = self.quarantined()
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.purge(q["quarantine_id"])
        self.assertIn("explicit confirmation", str(ctx.exception))
        self.assertTrue(Path(q["quarantine_path"]).exists())

    def test_confirmation_is_checked_before_the_id_is_looked_up(self):
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.purge(999, confirm=False)
        self.assertIn("explicit confirmation", str(ctx.exception))

    def test_unknown_id_is_rejected(self):
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.purge(999, confirm=True)
        self.assertIn("No quarantine entry with id 999", str(ctx.exception))

    def test_purge_removes_the_file_and_its_sidecar(self):
        _f, q = self.quarantined()
        sidecar = Path(q["quarantine_path"]).with_suffix(".quar.txt")
        result = quarantine.purge(q["quarantine_id"], confirm=True)
        self.assertFalse(Path(q["quarantine_path"]).exists())
        self.assertFalse(sidecar.exists())
        self.assertEqual(result["deleted"], q["original_path"])

    def test_purge_records_a_deletion_timestamp(self):
        _f, q = self.quarantined()
        quarantine.purge(q["quarantine_id"], confirm=True)
        self.assertIsNotNone(
            store.get_quarantine_entry(q["quarantine_id"])["deleted_at"])

    def test_double_purge_is_rejected(self):
        _f, q = self.quarantined()
        quarantine.purge(q["quarantine_id"], confirm=True)
        with self.assertRaises(quarantine.QuarantineError) as ctx:
            quarantine.purge(q["quarantine_id"], confirm=True)
        self.assertIn("Already deleted", str(ctx.exception))

    def test_purge_of_an_already_missing_file_still_marks_the_row(self):
        _f, q = self.quarantined()
        quarantine._unharden(Path(q["quarantine_path"]))
        os.unlink(q["quarantine_path"])
        quarantine.purge(q["quarantine_id"], confirm=True)
        self.assertIsNotNone(
            store.get_quarantine_entry(q["quarantine_id"])["deleted_at"])

    def test_a_failed_unlink_is_reported_and_the_row_is_not_marked(self):
        _f, q = self.quarantined()
        with mock.patch.object(Path, "unlink", side_effect=OSError("busy")):
            with self.assertRaises(quarantine.QuarantineError) as ctx:
                quarantine.purge(q["quarantine_id"], confirm=True)
        self.assertIn("Delete failed", str(ctx.exception))
        self.assertIsNone(
            store.get_quarantine_entry(q["quarantine_id"])["deleted_at"])

    def test_purge_does_not_clear_the_verdict(self):
        f, q = self.quarantined()
        quarantine.purge(q["quarantine_id"], confirm=True)
        self.assertEqual(store.get_verdict(f["sha256"]), "malicious",
                         "a deleted file should stay marked malicious")


class TestHardeningPosix(TempEnvMixin, unittest.TestCase):

    @unittest.skipIf(config.IS_WINDOWS, "POSIX permission bits")
    def test_harden_sets_mode_0400_and_says_so(self):
        p = self.write("x.quar", b"data")
        notes = quarantine._harden(p)
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o400)
        self.assertEqual(notes, ["mode set to 0400"])

    @unittest.skipIf(config.IS_WINDOWS, "POSIX permission bits")
    def test_unharden_restores_write_access(self):
        p = self.write("x.quar", b"data")
        quarantine._harden(p)
        quarantine._unharden(p)
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)

    def test_harden_reports_but_does_not_raise_on_failure(self):
        p = self.write("x.quar", b"data")
        # This asserts the shape of the POSIX branch's failure note, so pin the
        # branch: on Windows _harden also runs icacls and reports separately.
        with mock.patch.object(config, "IS_WINDOWS", False), \
                mock.patch.object(os, "chmod", side_effect=OSError("read-only fs")):
            notes = quarantine._harden(p)
        self.assertEqual(len(notes), 1)
        self.assertIn("could not harden permissions", notes[0])
        self.assertIn("read-only fs", notes[0])

    def test_unharden_swallows_failures(self):
        p = self.write("x.quar", b"data")
        with mock.patch.object(os, "chmod", side_effect=OSError("nope")):
            quarantine._unharden(p)      # must not raise


class TestHardeningWindowsReal(TempEnvMixin, unittest.TestCase):
    """The icacls branch against the real NTFS ACL machinery.

    Runs only on Windows. This is the observation the simulated test below
    cannot make: that the resulting DACL really blocks execution and really
    keeps DELETE, and that _unharden puts everything back.
    """

    def _icacls(self, p) -> str:
        r = subprocess.run(["icacls", str(p)], capture_output=True, text=True,
                           errors="replace")
        return r.stdout + r.stderr

    @unittest.skipUnless(config.IS_WINDOWS, "needs real NTFS ACLs")
    def test_hardened_file_denies_execute_but_keeps_delete(self):
        p = self.write("x.quar", Path(r"C:\Windows\System32\notepad.exe").read_bytes())
        notes = quarantine._harden(p)
        self.assertIn("execute denied for Everyone (deny ACE)", notes)
        self.assertIn("read-only attribute set", notes)
        acl = self._icacls(p)
        self.assertIn("(DENY)(X)", acl, acl)
        self.assertTrue(os.stat(p).st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)
        # Execution is blocked by the deny ACE, whatever the extension says.
        with self.assertRaises(PermissionError):
            subprocess.Popen([str(p)])
        # The owner still holds DELETE: this is the whole point of /inheritance:d
        # over /inheritance:r -- the old sequence made this unlink fail.
        quarantine._unharden(p)
        acl = self._icacls(p)
        self.assertNotIn("DENY", acl, acl)
        self.assertFalse(os.stat(p).st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)
        os.unlink(p)
        self.assertFalse(p.exists())

    @unittest.skipUnless(config.IS_WINDOWS, "needs real NTFS ACLs")
    def test_hardening_is_reported_truthfully(self):
        """icacls exit codes are inspected: a file that vanished mid-way must
        not be reported as hardened."""
        p = self.sandbox / "gone.quar"
        notes = quarantine._harden(p)
        self.assertFalse(any("execute denied" in n for n in notes), notes)
        self.assertTrue(any("could not" in n for n in notes), notes)


class TestHardeningWindows(TempEnvMixin, unittest.TestCase):
    """The Windows icacls branch, exercised on Linux with subprocess stubbed."""

    def setUp(self):
        super().setUp()
        p = mock.patch.object(config, "IS_WINDOWS", True)
        p.start()
        self.addCleanup(p.stop)

    @staticmethod
    def _ok_run(*_a, **_kw):
        return mock.Mock(returncode=0, stdout="", stderr="")

    def test_harden_detaches_inheritance_and_denies_execute_for_everyone(self):
        """Regression test for a fixed bug.

        The old sequence ('/inheritance:r' then '/grant:r USER:(R)') left the
        file with a read-only DACL and therefore no DELETE right, so restore and
        purge both failed with Access Denied. Inheritance is now *detached*
        (/inheritance:d), which keeps the owner's existing access, and a single
        deny-execute ACE for the Everyone SID is what blocks execution. The SID
        literal is used because 'Everyone' is localised and %USERNAME% can be
        wrong for a Microsoft account.
        """
        path = self.write("x.quar", b"data")
        with mock.patch.object(subprocess, "run", side_effect=self._ok_run) as run:
            notes = quarantine._harden(path)
        calls = [c.args[0] for c in run.call_args_list]
        self.assertEqual(calls, [["icacls", str(path), "/inheritance:d"],
                                 ["icacls", str(path), "/deny", "*S-1-1-0:(X)"]])
        self.assertIn("execute denied for Everyone (deny ACE)", notes)
        for call in run.call_args_list:
            self.assertFalse(call.kwargs["check"],
                             "icacls failures must not raise")

    def test_harden_does_not_depend_on_the_username(self):
        """Regression test for a fixed bug: hardening is SID-based now, so it
        works with no USERNAME in the environment (Microsoft accounts, services).
        """
        path = self.write("x.quar", b"data")
        env = dict(os.environ)
        env.pop("USERNAME", None)
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(subprocess, "run", side_effect=self._ok_run) as run:
            notes = quarantine._harden(path)
        calls = [c.args[0] for c in run.call_args_list]
        self.assertEqual(calls, [["icacls", str(path), "/inheritance:d"],
                                 ["icacls", str(path), "/deny", "*S-1-1-0:(X)"]])
        self.assertIn("execute denied for Everyone (deny ACE)", notes)

    def test_harden_reports_an_icacls_failure_instead_of_claiming_success(self):
        path = self.write("x.quar", b"data")
        failing = mock.Mock(returncode=1, stdout="Failed processing 1 files",
                            stderr="")
        with mock.patch.object(subprocess, "run", return_value=failing):
            notes = quarantine._harden(path)
        self.assertTrue(any("could not deny execute" in n for n in notes), notes)

    def test_harden_sets_the_read_only_attribute_on_windows(self):
        """Second barrier: on FAT32/exFAT there are no ACLs at all and icacls
        fails outright, so the read-only attribute is what remains.
        """
        path = self.write("x.quar", b"data")
        with mock.patch.object(subprocess, "run", side_effect=self._ok_run), \
                mock.patch.object(os, "chmod") as chmod:
            notes = quarantine._harden(path)
        chmod.assert_called_once_with(path, stat.S_IREAD)
        self.assertIn("read-only attribute set", notes)

    def test_unharden_clears_read_only_then_removes_the_deny_ace_and_resets(self):
        """Regression test for a fixed bug.

        os.unlink and os.rename both fail on a read-only file on Windows, so the
        attribute has to be cleared before anything moves. '/reset' alone only
        reapplies *inherited* ACEs, which is a no-op while the file is still
        flagged as protected from inheritance, so inheritance is re-enabled
        first. The legacy username-based deny ACE is still removed for files
        hardened by an older build.
        """
        path = self.write("x.quar", b"data")
        with mock.patch.dict(os.environ, {"USERNAME": "tester"}), \
                mock.patch.object(subprocess, "run", side_effect=self._ok_run) as run, \
                mock.patch.object(os, "chmod") as chmod:
            quarantine._unharden(path)
        chmod.assert_called_once_with(path, stat.S_IWRITE | stat.S_IREAD)
        calls = [c.args[0] for c in run.call_args_list]
        self.assertEqual(calls, [
            ["icacls", str(path), "/remove:d", "*S-1-1-0"],
            ["icacls", str(path), "/remove:d", "tester"],
            ["icacls", str(path), "/inheritance:e"],
            ["icacls", str(path), "/reset"]])

    def test_a_missing_icacls_binary_is_tolerated(self):
        path = self.write("x.quar", b"data")
        with mock.patch.object(subprocess, "run",
                               side_effect=FileNotFoundError("icacls")):
            notes = quarantine._harden(path)
            quarantine._unharden(path)
        self.assertIn("could not harden permissions", notes[0])

    def test_restore_clears_the_read_only_attribute_on_windows(self):
        """Regression test for a fixed bug: the hardened file is read-only, and a
        read-only file cannot be renamed or unlinked on Windows, so restore has
        to clear the bit and put the original writability back.
        """
        with mock.patch.object(subprocess, "run", side_effect=self._ok_run):
            store.init_db()
            body = b"MZ windows restore"
            path = self.write("t.exe", body)
            import hashlib
            sha = hashlib.sha256(body).hexdigest()
            store.upsert_finding({"sha256": sha, "path": str(path),
                                  "size": len(body), "mtime": None, "score": 60,
                                  "severity": "medium", "reasons": []},
                                 scan_id=1)
            f = store.get_findings()[0]
            store.set_verdict(sha, "malicious")
            q = quarantine.quarantine_finding(f["id"])
            with mock.patch.object(os, "chmod") as chmod:
                quarantine.restore(q["quarantine_id"])
            self.assertIn(stat.S_IWRITE | stat.S_IREAD,
                          [c.args[1] for c in chmod.call_args_list])
        self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()


class TestProtectedQuarantineGuard(TempEnvMixin, unittest.TestCase):
    """Quarantine must never silently break an installed program."""

    def _seed(self, relpath):
        import hashlib
        from sentry import store as st
        st.init_db()
        f = self.sandbox / relpath
        f.parent.mkdir(parents=True, exist_ok=True)
        body = b"MZ" + b"\x00" * 3000
        f.write_bytes(body)
        sha = hashlib.sha256(body).hexdigest()
        st.upsert_finding({"sha256": sha, "path": str(f), "size": len(body),
                           "mtime": None, "score": 60, "severity": "medium",
                           "reasons": ["packed"]}, 1)
        fid = next(x["id"] for x in st.get_findings(include_safe=True)
                   if x["path"] == str(f))
        st.set_verdict(sha, "malicious", path=str(f))
        return f, fid

    def test_a_file_in_a_game_folder_is_refused(self):
        f, fid = self._seed("steamapps/common/Game/anticheat.exe")
        with self.assertRaises(quarantine.QuarantineError) as cm:
            quarantine.quarantine_finding(fid)
        msg = str(cm.exception)
        self.assertIn("Refusing to quarantine", msg)
        self.assertIn("verify integrity of game files", msg)
        self.assertTrue(f.exists(), "the file must not have moved")

    def test_an_ordinary_file_is_still_quarantined(self):
        f, fid = self._seed("Downloads/thing.exe")
        result = quarantine.quarantine_finding(fid)
        self.assertFalse(f.exists())
        self.assertEqual(result["original_path"], str(f))

    def test_an_explicit_override_is_honoured(self):
        f, fid = self._seed("steamapps/common/Game/anticheat.exe")
        result = quarantine.quarantine_finding(fid, allow_protected=True)
        self.assertFalse(f.exists())
        self.assertEqual(result["original_path"], str(f))

    def test_the_refusal_happens_before_anything_is_touched(self):
        f, fid = self._seed("steamapps/common/Game/anticheat.exe")
        before = f.read_bytes(), f.stat().st_mode
        with self.assertRaises(quarantine.QuarantineError):
            quarantine.quarantine_finding(fid)
        self.assertEqual((f.read_bytes(), f.stat().st_mode), before)
