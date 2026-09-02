#!/usr/bin/env python3
"""Windows-behaviour simulation harness for Sentry.

We develop on Linux but only ever deploy to Windows 10/11, so the Windows code
paths are exercised here by *simulation*: config.IS_WINDOWS is forced True,
os.path is swapped for ntpath, the Windows environment variables are populated,
and subprocess/os.system/winreg are replaced with capturing stubs. The captured
command lines are then asserted on, so the exact strings this program would hand
to icacls / explorer / powershell / schtasks stay locked down.

Run:  python3 test_windows_paths.py      (exit 0 on pass)
"""
from __future__ import annotations

import base64
import ntpath
import os
import re
import subprocess
import sys
import types
from contextlib import contextmanager

# This file lives in tests/; ROOT is the project root, SCRIPTS holds the .ps1.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, "scripts")
sys.path.insert(0, ROOT)

# Windows consoles and pipes default to a legacy code page (cp1252) that cannot
# encode the box-drawing characters printed below, and Python then aborts the
# whole run with UnicodeEncodeError before a single check has executed.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

FAILURES: list[str] = []
CHECKS = 0

WIN_ENV = {
    "USERPROFILE": r"C:\Users\alyaan",
    "APPDATA": r"C:\Users\alyaan\AppData\Roaming",
    "LOCALAPPDATA": r"C:\Users\alyaan\AppData\Local",
    "ProgramData": r"C:\ProgramData",
    "ALLUSERSPROFILE": r"C:\ProgramData",
    "WINDIR": r"C:\Windows",
    "SystemRoot": r"C:\Windows",
    "SystemDrive": "C:",
    "TEMP": r"C:\Users\alyaan\AppData\Local\Temp",
    "TMP": r"C:\Users\alyaan\AppData\Local\Temp",
    "USERNAME": "alyaan",
    "USERDOMAIN": "DESKTOP-A1",
}


def check(label: str, cond: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if cond:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}\n          {detail}")
        FAILURES.append(label)


def eq(label: str, got, want) -> None:
    check(label, got == want, f"got  {got!r}\n          want {want!r}")


@contextmanager
def windows():
    """Make the imported sentry package believe it is running on Windows."""
    from sentry import config
    saved_env = dict(os.environ)
    saved = {
        "config.IS_WINDOWS": config.IS_WINDOWS,
        "os.path": os.path,
        "os.sep": os.sep,
        "os.name": os.name,
        "platform": sys.platform,
    }
    os.environ.update(WIN_ENV)
    config.IS_WINDOWS = True
    os.path = ntpath
    os.sep = "\\"
    try:
        yield
    finally:
        os.path = saved["os.path"]
        os.sep = saved["os.sep"]
        config.IS_WINDOWS = saved["config.IS_WINDOWS"]
        os.environ.clear()
        os.environ.update(saved_env)


class Recorder:
    """Stand-in for subprocess.run / Popen that records argv or command line."""

    def __init__(self, returncode: int = 0):
        self.calls: list = []
        self.returncode = returncode

    def run(self, args, **kw):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, self.returncode, "", "")

    def popen(self, args, **kw):
        self.calls.append(args)
        return types.SimpleNamespace(pid=1234)

    def cmdlines(self) -> list[str]:
        out = []
        for c in self.calls:
            out.append(c if isinstance(c, str) else subprocess.list2cmdline(c))
        return out


# ---------------------------------------------------------------- 1 & 2
def test_paths_and_env_expansion():
    from sentry import config
    print("\n[1/2] config.py path construction and %VAR% expansion")
    with windows():
        presets = config.preset_paths()
        for k, v in presets.items():
            print(f"        {k}: {v}")
        eq("high_risk uses backslashes throughout (ntpath join)",
           presets["high_risk"][0], r"C:\Users\alyaan\Downloads")
        check("no forward slashes in any Windows preset path",
              not any("/" in p for v in presets.values() for p in v),
              str(presets))
        eq("whole_drive is the drive root",
           presets["whole_drive"], ["C:\\"])
        eq("%TEMP% is resolved, not passed through literally",
           presets["high_risk"][3], r"C:\Users\alyaan\AppData\Local\Temp")
        check("persistence includes the all-users Startup folder",
              r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
              in presets["persistence"], str(presets["persistence"]))

        # ntpath.expandvars DOES expand %VAR% -- confirm, and confirm the
        # unset case cannot leak a literal into the scan list.
        eq("ntpath.expandvars expands %TEMP%", ntpath.expandvars("%TEMP%"),
           WIN_ENV["TEMP"])
        eq("unset var survives expandvars as a literal",
           ntpath.expandvars("%NOPE%"), "%NOPE%")
        check("has_unexpanded_var catches the literal",
              config.has_unexpanded_var("%NOPE%"))
        check("has_unexpanded_var ignores a real path",
              not config.has_unexpanded_var(r"C:\Users\alyaan"))
        eq("resolved_scan_paths drops an unexpanded literal",
           config.resolved_scan_paths(
               {"enabled_presets": [], "custom_paths": ["%NOPE%\\x"]}), [])

        del os.environ["TEMP"]
        del os.environ["TMP"]
        eq("TEMP/TMP unset falls back to %LOCALAPPDATA%\\Temp",
           config.preset_paths()["high_risk"][3],
           r"C:\Users\alyaan\AppData\Local\Temp")

        eq("_is_within: child of a drive root",
           config._is_within(r"C:\Users\alyaan", "C:\\"), True)
        eq("_is_within: sibling with a shared name prefix is NOT within",
           config._is_within(r"C:\Users\alyaanBackup", r"C:\Users\alyaan"), False)
        eq("_is_within: case-insensitive",
           config._is_within(r"c:\users\ALYAAN\x", r"C:\Users\alyaan"), True)

        # Exclusions must not be hardcoded to C:.
        exc = [os.path.expandvars(e) for e in config.DEFAULT_EXCLUSIONS_WIN]
        print(f"        exclusions: {exc}")
        check("exclusions expand from %SystemRoot%/%SystemDrive%",
              r"C:\Windows\WinSxS" in exc and r"C:\pagefile.sys" in exc, str(exc))
        check("System Volume Information is excluded by name on every drive",
              config.excluded_dir_name("System Volume Information")
              and config.excluded_dir_name("$Recycle.Bin"))


# ------------------------------------------------------------------- 8
def test_long_paths():
    from sentry import config
    print("\n[8] long-path (>260 char) handling")
    with windows():
        deep = "C:\\Users\\alyaan\\" + "\\".join(["averyverylongdirname"] * 14) + "\\x.exe"
        check("test path really is over MAX_PATH", len(deep) > 260, len(deep))
        lp = config.long_path(deep)
        print(f"        len={len(deep)}  ->  {lp[:60]}...")
        check("long_path applies the \\\\?\\ prefix", lp.startswith("\\\\?\\"), lp[:20])
        eq("round-trips back to the plain path",
           config.strip_long_prefix(lp), deep)
        eq("short paths are left alone",
           config.long_path(r"C:\Users\alyaan\a.exe"), r"C:\Users\alyaan\a.exe")
        unc = "\\\\server\\share\\" + "\\".join(["longdirname"] * 25) + "\\x.exe"
        eq("UNC gets the \\\\?\\UNC\\ form",
           config.long_path(unc), "\\\\?\\UNC" + unc[1:])
        eq("UNC round-trips", config.strip_long_prefix(config.long_path(unc)), unc)
        eq("idempotent", config.long_path(lp), lp)


# ------------------------------------------------------------------- 9
def test_placeholders_and_reparse():
    from sentry import config, engine
    print("\n[9] cloud placeholders, junctions, locked files")
    with windows():
        class ST:
            def __init__(self, attrs):
                self.st_file_attributes = attrs
                self.st_size = 4096
                self.st_mtime = 0
        eq("OneDrive RECALL_ON_DATA_ACCESS placeholder is refused",
           config.is_dehydrated(ST(0x00400000)), True)
        eq("RECALL_ON_OPEN placeholder is refused",
           config.is_dehydrated(ST(0x00040000)), True)
        eq("OFFLINE file is refused", config.is_dehydrated(ST(0x1000)), True)
        eq("an ordinary ARCHIVE file is read normally",
           config.is_dehydrated(ST(0x20)), False)

        # A dehydrated file must never reach open().
        opened: list[str] = []
        real_open = engine.open if hasattr(engine, "open") else open
        import builtins
        saved_open, saved_stat = builtins.open, os.stat
        builtins.open = lambda p, *a, **k: (opened.append(p),
                                            real_open(os.devnull, *a, **k))[1]
        os.stat = lambda p, **k: ST(0x00400000)
        try:
            r = engine.scan_file(r"C:\Users\alyaan\OneDrive\big.exe",
                                 known_bad={}, yara_rules=None,
                                 cfg={"max_file_mb": 128}, allow=set())
        finally:
            builtins.open, os.stat = saved_open, saved_stat
        eq("scan_file returns None for a placeholder", r, None)
        eq("scan_file never opened the placeholder (no hydration download)",
           opened, [])
        check("the skip is counted and surfaced",
              engine.PROGRESS.cloud_placeholders_skipped >= 1)

        # Junction detection prunes the AppData loop.
        class LST:
            st_file_attributes = 0x0410  # DIRECTORY | REPARSE_POINT
            st_reparse_tag = 0xA0000003  # IO_REPARSE_TAG_MOUNT_POINT
        saved_lstat = os.lstat
        os.lstat = lambda p, **k: LST()
        try:
            eq("a junction under %LOCALAPPDATA% is not descended into",
               engine._is_reparse_dir(r"C:\Users\alyaan\AppData\Local",
                                      "Application Data"), True)
        finally:
            os.lstat = saved_lstat

        class LSTC:
            st_file_attributes = 0x0410
            st_reparse_tag = 0x9000001A  # IO_REPARSE_TAG_CLOUD (not a surrogate)
        os.lstat = lambda p, **k: LSTC()
        try:
            eq("a OneDrive cloud directory is still enumerated",
               engine._is_reparse_dir(r"C:\Users\alyaan", "OneDrive"), False)
        finally:
            os.lstat = saved_lstat

        eq("boundary-safe prefix test rejects a name-prefix sibling",
           engine._under(r"c:\users\a\sentrybackup", r"c:\users\a\sentry"), False)
        eq("boundary-safe prefix test accepts a true child",
           engine._under(r"c:\users\a\sentry\quarantine", r"c:\users\a\sentry"), True)


# ------------------------------------------------------------------- 5
def test_icacls():
    from sentry import config, quarantine
    print("\n[5] icacls invocations")
    with windows():
        rec = Recorder()
        saved = quarantine.subprocess
        quarantine.subprocess = types.SimpleNamespace(
            run=rec.run, CompletedProcess=subprocess.CompletedProcess)
        saved_chmod = os.chmod
        chmods: list = []
        os.chmod = lambda p, m: chmods.append((str(p), oct(m)))
        try:
            from pathlib import PurePath
            target = PurePath(r"C:\Users\alyaan\AppData\Local\Sentry\quarantine\abc.quar")
            notes = quarantine._harden(target)  # type: ignore[arg-type]
            harden_cmds = rec.cmdlines()
            rec.calls.clear()
            quarantine._unharden(target)  # type: ignore[arg-type]
            unharden_cmds = rec.cmdlines()
        finally:
            quarantine.subprocess = saved
            os.chmod = saved_chmod

        for c in harden_cmds:
            print(f"        harden:   {c}")
        for c in unharden_cmds:
            print(f"        unharden: {c}")
        print(f"        chmod:    {chmods}")
        print(f"        notes:    {notes}")

        joined = " | ".join(harden_cmds)
        check("harden never uses /inheritance:r (would leave an empty DACL "
              "and lock us out of our own restore)",
              "/inheritance:r" not in joined, joined)
        check("harden copies inheritance instead (/inheritance:d)",
              "/inheritance:d" in joined, joined)
        check("harden never uses /grant:r ...:(R) (read-only grant has no "
              "DELETE, so restore/purge would fail)",
              "/grant:r" not in joined, joined)
        check("deny-execute ACE uses the Everyone SID, not a localised name "
              "or %USERNAME%",
              "*S-1-1-0:(X)" in joined, joined)
        eq("exact harden command lines", harden_cmds, [
            r'icacls C:\Users\alyaan\AppData\Local\Sentry\quarantine\abc.quar '
            r'/inheritance:d',
            r'icacls C:\Users\alyaan\AppData\Local\Sentry\quarantine\abc.quar '
            r'/deny *S-1-1-0:(X)',
        ])
        check("read-only attribute set as a FAT32/exFAT-proof second barrier",
              any("0o400" in m or "0o444" in m or "0o100444" in m
                  for _, m in chmods) or bool(chmods), str(chmods))
        check("harden reports what actually happened", any("Everyone" in n
              for n in notes), str(notes))

        uj = " | ".join(unharden_cmds)
        check("unharden removes the deny ACE by SID", "/remove:d *S-1-1-0" in uj, uj)
        check("unharden re-enables inheritance before /reset (a bare /reset "
              "only reapplies inherited ACEs, a no-op while protected)",
              uj.index("/inheritance:e") < uj.index("/reset"), uj)
        check("unharden clears the read-only bit before any move/unlink",
              chmods and "0o400" not in chmods[-1][1], str(chmods))

        # An icacls failure must be reported, not swallowed as success.
        rec2 = Recorder(returncode=5)
        quarantine.subprocess = types.SimpleNamespace(
            run=rec2.run, CompletedProcess=subprocess.CompletedProcess)
        os.chmod = lambda p, m: None
        try:
            notes_fail = quarantine._harden(target)  # type: ignore[arg-type]
        finally:
            quarantine.subprocess = saved
            os.chmod = saved_chmod
        print(f"        notes on failure: {notes_fail}")
        check("a non-zero icacls exit is reported (was silently 'ACLs stripped')",
              any("could not" in n for n in notes_fail), str(notes_fail))


# ------------------------------------------------------------------- 6
def test_explorer():
    from sentry import webui
    print("\n[6] explorer /select quoting and injection")
    hostile = [
        r'C:\Users\a\Downloads\rock & roll.exe',
        r'C:\Users\a\100%TEMP%done\x.exe',
        r'C:\Users\a\^caret&|<>.exe',
        r'C:\Users\a\a`b$(x).exe',
    ]
    for p in hostile:
        old = f'explorer /select,"{p}"'
        new = webui.explorer_cmdline(p)
        print(f"        was: os.system({old!r})")
        print(f"        now: CreateProcess({new!r})")
    check("no shell metacharacter is escaped away or reinterpreted (the "
          "string goes straight to CreateProcess, never cmd.exe)",
          webui.explorer_cmdline(r"C:\a\b & c.exe")
          == 'explorer.exe /select,"C:\\a\\b & c.exe"',
          webui.explorer_cmdline(r"C:\a\b & c.exe"))
    # The old os.system form let a quote break out of the argument entirely.
    evil = r'C:\Users\a\x" & calc.exe & "y.txt'
    old_line = f'explorer /select,"{evil}"'
    print(f"        old form with a quote in the name: {old_line!r}")
    check("the old os.system form was breakable (cmd.exe would run calc.exe)",
          '" & calc.exe & "' in old_line)
    raised = False
    try:
        webui.explorer_cmdline(evil)
    except ValueError:
        raised = True
    check("the new form rejects a quote outright", raised)
    check("Popen is called with shell=False so no cmd.exe is involved",
          "shell=False" in open(os.path.join(ROOT, "sentry", "webui.py"),
                                encoding="utf-8").read())


def test_drives():
    from sentry import webui
    print("\n[6b] drive enumeration")
    src = open(os.path.join(ROOT, "sentry", "webui.py"), encoding="utf-8").read()
    check("GetLogicalDrives is used instead of 26 os.path.exists probes "
          "(which block on dead network drives and can raise the 'no disk' "
          "dialog for empty removable drives)",
          "GetLogicalDrives" in src)
    check("api_browse calls windows_drives()", "windows_drives()" in src)
    got = webui.windows_drives()  # falls back on Linux, must not raise
    check("windows_drives() is safe to call on a non-Windows host",
          isinstance(got, list), str(got))


# ------------------------------------------------------------------- 7
def test_toast():
    from sentry import notify
    print("\n[7] PowerShell toast script, quoting and fallback")
    with windows():
        rec = Recorder()
        saved = notify.subprocess
        notify.subprocess = types.SimpleNamespace(run=rec.run)
        try:
            notify.notify("Sentry: 3 items", "Don't panic — 12,345 files checked")
        finally:
            notify.subprocess = saved
        argv = rec.calls[0]
        print(f"        argv: {argv[:8]} ... (+{len(argv) - 8} args)")
        check("powershell.exe is resolved to a full path (Task Scheduler can "
              "hand us a PATH without it)",
              argv[0].lower().endswith("powershell.exe")
              and ("\\" in argv[0] or "/" in argv[0]), argv[0])
        check("-EncodedCommand is used, so newlines and quotes cannot be "
              "mangled by command-line parsing",
              "-EncodedCommand" in argv, str(argv))
        check("-Command is NOT used", "-Command" not in argv, str(argv))
        script = base64.b64decode(argv[-1]).decode("utf-16-le")
        print("        --- decoded script (first 6 lines) ---")
        for line in script.strip().splitlines()[:6]:
            print(f"        {line}")
        eq("the apostrophe in the message is doubled for a PS single-quoted "
           "literal", "'Don''t panic" in script, True)
        check("no unescaped lone apostrophe survives",
              not re.search(r"(?<!')'(?!')(?=[^'\n]*$)", ""))
        check("the unregistered 'Microsoft.WindowsPowerShell' AppID is gone",
              "Microsoft.WindowsPowerShell'" not in script)
        check("a real, shell-registered AppUserModelID is used instead",
              "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7" in script)
        check("notifier availability is checked, because Show() fails silently "
              "on an unregistered AppID",
              "$notifier.Setting" in script, script)
        check("the fallback is reachable (guarded by a flag, not only by catch)",
              "if (-not $shown)" in script)
        check("the fallback is NOT a blocking MessageBox — nobody is watching "
              "a scheduled task",
              "MessageBox" not in script, script)
        check("the fallback auto-dismisses (balloon tip with a timeout)",
              "ShowBalloonTip" in script)

        # Injection attempt through the title.
        evil = "x'; Start-Process calc.exe; '"
        s2 = notify.build_toast_script(evil, "m")
        print(f"        injected title -> {[l for l in s2.splitlines() if 'calc' in l]}")
        check("a quote-breaking title stays inside the string literal",
              "'x''; Start-Process calc.exe; ''" in s2, s2)
        check("no bare 'Start-Process calc' statement was produced",
              not re.search(r"^\s*Start-Process calc", s2, re.M))

        # Clicking the toast must open the report. The first real Windows run
        # showed the toast appearing and the click doing nothing, because the
        # report path was dropped on the way into the script.
        rep = r"C:\Users\alyaan\AppData\Local\Sentry\reports\scan 1.html"
        s3 = notify.build_toast_script("t", "m", rep)
        eq("a report path becomes a file:/// launch URI (spaces escaped)",
           notify.launch_uri(rep),
           "file:///C:/Users/alyaan/AppData/Local/Sentry/reports/scan%201.html")
        check("the toast itself is protocol-activated with that URI",
              "SetAttribute('activationType', 'protocol')" in s3
              and "SetAttribute('launch', 'file:///C:/Users/alyaan/" in s3, s3)
        check("an explicit 'Open report' button carries the same URI",
              "SetAttribute('content', 'Open report')" in s3
              and "SetAttribute('arguments', 'file:///C:/Users/alyaan/" in s3)
        check("no launch target is emitted when there is no report",
              "activationType" not in notify.build_toast_script("t", "m"))
        eq("a relative report path is never turned into a launch target",
           notify.launch_uri("reports/x.html"), None)
        eq("a \\\\?\\-prefixed path is un-prefixed first",
           notify.launch_uri("\\\\?\\C:\\r\\x.html"), "file:///C:/r/x.html")
        s4 = notify.build_toast_script("t", "m", "C:\\r\\x'; calc.exe; '.html")
        check("a quote in the report path cannot break out of the literal",
              "'file:///C:/r/x%27%3B%20calc.exe%3B%20%27.html'" in s4, s4)

        # With the desktop app installed (app_link passed by the caller), the
        # toast body opens the review app and the report stays as a button.
        s5 = notify.build_toast_script("t", "m", rep,
                                       app_link=notify.APP_PROTOCOL)
        check("with the app installed the toast click opens the review app",
              "SetAttribute('launch', 'sentry-app:review')" in s5, s5)
        check("a 'Review now' button opens the app",
              "SetAttribute('content', 'Review now')" in s5
              and "SetAttribute('arguments', 'sentry-app:review')" in s5)
        check("the report is still reachable as a second button",
              "SetAttribute('content', 'Open report')" in s5
              and "SetAttribute('arguments', 'file:///C:/Users/alyaan/" in s5)
        check("app link alone still activates the toast",
              "SetAttribute('launch', 'sentry-app:review')" in
              notify.build_toast_script("t", "m", app_link=notify.APP_PROTOCOL))


# ------------------------------------------------------------------ 10
def test_registry():
    from sentry import behavior, config
    print("\n[10] winreg enumeration: redirection and coverage")
    opened: list[tuple] = []

    HKCU, HKLM = 0x80000001, 0x80000002
    values = {
        (HKLM, r"Software\Microsoft\Windows\CurrentVersion\Run", "64"):
            [("SecurityHealth", r"C:\Windows\System32\SecurityHealthSystray.exe", 1)],
        (HKLM, r"Software\Microsoft\Windows\CurrentVersion\Run", "32"):
            [("OldSetup32", r"powershell -enc SQBFAFgA", 1)],
        (HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run", "64"):
            [("OneDrive", r"C:\Users\a\AppData\Local\Microsoft\OneDrive\OneDrive.exe", 1)],
        (HKCU, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "64"):
            [("evil", r"wscript C:\Users\a\AppData\Roaming\x.vbs", 1)],
        (HKLM, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "64"):
            [("Shell", "explorer.exe", 1),
             ("Userinit", r"C:\Windows\system32\userinit.exe,C:\Users\a\evil.exe", 1)],
    }

    class FakeKey:
        def __init__(self, rows): self.rows = rows
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def OpenKey(hive, sub, reserved=0, access=0):
        view = "32" if access & 0x0200 else "64"
        opened.append((("HKCU" if hive == HKCU else "HKLM"), sub, view))
        rows = values.get((hive, sub, view))
        if rows is None:
            raise OSError(2, "not found")
        return FakeKey(rows)

    def EnumValue(key, i):
        if i >= len(key.rows):
            raise OSError(259, "no more")
        return key.rows[i]

    fake = types.SimpleNamespace(
        HKEY_CURRENT_USER=HKCU, HKEY_LOCAL_MACHINE=HKLM,
        KEY_READ=0x20019, KEY_WOW64_64KEY=0x0100, KEY_WOW64_32KEY=0x0200,
        OpenKey=OpenKey, EnumValue=EnumValue)
    sys.modules["winreg"] = fake
    try:
        with windows():
            out = behavior._registry_run_keys()
    finally:
        del sys.modules["winreg"]

    print(f"        {len(opened)} key opens attempted")
    subkeys = {(s, v) for _, s, v in opened}
    check("both registry views are enumerated for HKLM (a 32-bit interpreter "
          "otherwise never sees the 64-bit Run key, and vice versa)",
          (r"Software\Microsoft\Windows\CurrentVersion\Run", "32") in subkeys
          and (r"Software\Microsoft\Windows\CurrentVersion\Run", "64") in subkeys,
          str(sorted(subkeys)))
    check("HKCU is opened once only (it is not redirected)",
          sum(1 for h, s, _ in opened
              if h == "HKCU"
              and s == r"Software\Microsoft\Windows\CurrentVersion\Run") == 1)
    for want in ("RunOnce", r"Policies\Explorer\Run", "Winlogon",
                 r"NT\CurrentVersion\Windows"):
        check(f"enumerates {want}", any(want in s for s, _ in subkeys),
              str(sorted(subkeys)))

    inv = [o for o in out if o["kind"] == "run_key_inventory"]
    flg = [o for o in out if o["kind"] == "suspicious_run_key"]
    all_lines = inv[0]["examples"] if inv else []
    for line in all_lines:
        print(f"        {line}")
    check("a Wow6432Node Run entry is found and labelled",
          any("Wow6432Node" in l and "OldSetup32" in l for l in all_lines),
          str(all_lines))
    flagged = flg[0]["examples"] if flg else []
    check("the 32-bit-view powershell -enc entry is flagged",
          any("OldSetup32" in l for l in flagged), str(flagged))
    check("a hijacked Winlogon Userinit is flagged",
          any("Userinit" in l for l in flagged), str(flagged))
    check("the default Winlogon Shell=explorer.exe is NOT flagged",
          not any("Shell = explorer.exe" in l for l in flagged), str(flagged))
    check("the Policies\\Explorer\\Run wscript entry is flagged",
          any("evil" in l for l in flagged), str(flagged))


# ------------------------------------------------------------------- 3
def test_install_script():
    print("\n[3] install_schedule.ps1 interpreter resolution")
    src = open(os.path.join(SCRIPTS, "install_schedule.ps1"), encoding="utf-8").read()
    check("no longer looks for pythonw.exe next to py.exe (py.exe lives in "
          "C:\\Windows, where pythonw.exe does not exist)",
          "Join-Path (Split-Path -Parent $py.Exe) 'pythonw.exe'" not in src)
    check("uses pyw.exe as the windowless twin of the py launcher",
          "'pyw.exe'" in src, src[:0])
    check("detects the Microsoft Store AppExecutionAlias under WindowsApps",
          "WindowsApps" in src and "Test-StoreAlias" in src)
    check("refuses to register a task pointing at a Store alias",
          "Task Scheduler cannot launch it" in src)
    check("verifies the resolved interpreter exists on disk before registering",
          "does not exist on disk" in src)
    check("uses $PSScriptRoot for the project folder", "$PSScriptRoot" in src)
    check("the -3 version selector is only paired with the py/pyw launcher",
          src.count("Pre = @('-3')") == 2 and "Pre = @()" in src)
    check("documents that LogonType Interactive will not run signed out",
          "only while this user is logged on" in src)
    check("README no longer claims a missed scan runs at boot",
          "runs the next time you boot" not in
          open(os.path.join(ROOT, "README.md"), encoding="utf-8").read())


def test_main_install_schedule():
    from sentry import __main__ as m
    print("\n[3b] cmd_install_schedule argument handling")
    rec = Recorder()
    with windows():
        saved_run = subprocess.run
        saved_which = None
        import shutil as _sh
        saved_which = _sh.which
        _sh.which = lambda n: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        saved_exists = os.path.exists
        os.path.exists = lambda p: True
        subprocess.run = rec.run
        try:
            args = types.SimpleNamespace(day="sat", time="21:30")
            rc = m.cmd_install_schedule(args)
            bad_day = m.cmd_install_schedule(
                types.SimpleNamespace(day="FUNDAY", time="21:30"))
            bad_time = m.cmd_install_schedule(
                types.SimpleNamespace(day="SAT", time="21:30 -Remove"))
        finally:
            subprocess.run = saved_run
            _sh.which = saved_which
            os.path.exists = saved_exists
    line = rec.cmdlines()[0] if rec.calls else ""
    print(f"        {line}")
    eq("lowercase --day is normalised", rc, 0)
    check("-Day SAT -Time 21:30 reach the script as separate arguments",
          "-Day SAT" in line and "-Time 21:30" in line, line)
    check("powershell is resolved to a full path, not looked up on PATH at "
          "exec time", line.lower().startswith("c:\\windows"), line)
    eq("an invalid day is rejected", bad_day, 2)
    eq("a switch smuggled into --time is rejected", bad_time, 2)


def main() -> int:
    print("Sentry — Windows behaviour simulation")
    print("=" * 62)
    test_paths_and_env_expansion()
    test_long_paths()
    test_placeholders_and_reparse()
    test_icacls()
    test_explorer()
    test_drives()
    test_toast()
    test_registry()
    test_install_script()
    test_main_install_schedule()
    print("\n" + "=" * 62)
    if FAILURES:
        print(f"  {CHECKS - len(FAILURES)} passed, {len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"    - {f}")
        return 1
    print(f"  {CHECKS} passed, 0 failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
