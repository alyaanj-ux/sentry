# Sentry-Lab — agent review findings

Four agents reviewed this build, working from isolated copies so their edits
couldn't collide. A fifth merged the results. Every fix described here is in the
code you have.

Run the suites from the project root: `python tests\run_tests.py`.

Every bug below was reproduced with a runnable script before being fixed. Anything
an agent suspected but couldn't reproduce is listed at the bottom, unfixed, so it
isn't lost.

## Test suites

| Command | Result |
|---|---|
| `python tests\selftest.py` | 30 passed |
| `python tests\test_correctness.py` | 33 passed |
| `python tests\test_windows_paths.py` | 90 passed |
| `python tests\test_detection_quality.py` | detection quality at/above baseline |
| `python tests\run_tests.py` | 515 tests, 513 passed, 2 skipped (running as root), 0 failures |

Total: **675 assertions**, up from 30. All five re-verified independently after the merge.

### Fixed after the first Windows run

The first run on Windows popped two modal *"Location is not available"* dialogs
pointing at a temp folder. Cause: on Windows the `/api/open-folder` directory branch
is `os.startfile`, not `subprocess.Popen`, and three tests stubbed only `Popen` — so
the real Explorer launched against the test sandbox, which `tearDown` then deleted.
Those tests were also *asserting* an `xdg-open` call that can never happen on Windows,
so they would have failed there regardless.

Fixed both layers: `tests/support.py` gained a `stub_launchers()` helper that blocks
`subprocess.Popen` *and* `os.startfile` (with `create=True`, since it doesn't exist on
POSIX), and every open-folder test now pins `config.IS_WINDOWS` explicitly instead of
inheriting the host OS, so the same assertions hold on either platform. Verified by
re-running the module with both real launchers replaced by a trip-wire that raises:
97 tests, zero escapes.

The handler was too lax as well — its guard was
`if not p.exists() and not p.parent.exists()`, which passes whenever the *parent*
survives. So a file moved or deleted since the last scan still got handed to Explorer,
which is exactly how a user gets that dialog. Now the target itself must exist and the
directory to be revealed must be a directory, with an error message that says the file
may have been moved, deleted, or quarantined.

---

## The one that mattered most

**Quarantine restore and delete would have failed on every file, on Windows.**
`quarantine.py` hardened files with:

```
icacls <file> /inheritance:r
icacls <file> /grant:r USER:(R)
icacls <file> /deny USER:(X)
```

`/inheritance:r` *removes* inherited ACEs. A file freshly moved into
`%LOCALAPPDATA%` has no explicit ACEs, so this leaves the DACL empty. `(R)` grants
read but **not DELETE** — and both restore (rename) and purge (unlink) need DELETE.
So every quarantined file would have been stuck: Access Denied, permanently.
`_unharden`'s `icacls /reset` only re-applies *inherited* ACEs, which is a no-op
while the file is still flagged protected-from-inheritance, so it didn't rescue it.

Worse, every icacls call ran with `check=False` and the code appended
`"ACLs stripped; execute denied"` unconditionally — so the UI reported hardening
that had failed. On a Microsoft-account or domain machine `%USERNAME%` may not even
resolve, and you'd never know.

Now: `/inheritance:d` (copies inherited ACEs, owner keeps full control), deny-execute
against the locale-independent Everyone SID `*S-1-1-0`, the read-only attribute as a
second barrier for FAT32/exFAT where there are no ACLs at all, exit codes actually
inspected and surfaced, and read-only cleared before any move or unlink.

This never showed up in testing because the whole thing was developed on Linux,
where the `os.chmod` branch runs instead.

---

## Data-loss and silent-failure bugs

**1. Quarantine never re-verified the file before moving it.** Score a file, mark it
malicious, let something replace the file at that path, then quarantine — the
*replacement* got moved out, the manifest recorded the old hash, and "delete
permanently" destroyed a file you never reviewed. Now the file is re-hashed at
quarantine time and refused if it doesn't match what you reviewed.

**2. Quarantining a symlink hardened and deleted the wrong file.** Only the link
moved; `_harden` followed it and chmod'd the unrelated target; purge unlinked just
the link. The actual payload survived while the UI said it was destroyed. Now
refused, with the real target named.

**3. One file with a non-UTF-8 name aborted the entire scan.** A name like
`evil\xff.txt` made sqlite raise out of `run_scan`, so `finish_scan` never ran and
every finding from every remaining file was discarded. In the dashboard the
background thread just died silently. Now counted as an error and the scan continues.

**4. Long paths (>260 chars) were silently skipped.** Without a `\\?\` prefix,
`os.stat` and `open` fail with ENOENT unless `LongPathsEnabled=1` (off by default)
*and* a long-path manifest is present. `scan_file` returned None with no error
counted, and `os.walk`'s `onerror` swallowed whole subtrees. A full-drive scan
omitted every deep tree — node_modules, nested backups, synced project folders —
and reported a clean run. Now prefixed at every syscall, stripped back before
anything user-visible.

**5. Scanning could trigger gigabytes of silent OneDrive downloads.** Nothing
checked file attributes, so `open()` on a dehydrated placeholder hydrated it. A
whole-drive scan could pull down your entire cloud storage and fill the disk. Now
`OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS` files are skipped before the
`open()`, counted, and reported in the scan notes so the coverage gap is honest.

**6. `max_file_mb` accepted 0 or negative and silently blinded every future scan.**
Not validated, written straight to `config.json`. `_should_inspect` then gated out
every file as "over size limit" — forever, with no error anywhere. Now clamped.

**7. Directory prefix matching had no path boundary, in three places.**
`nc.startswith(data_root)` meant `C:\...\SentryBackup` counted as being inside
`C:\...\Sentry`. In `behavior.py` this was worse: with the shipped exclusion
`C:\Windows\Installer`, a folder named `C:\Windows\InstallerCache` was pruned
entirely — so ransomware evidence there would be invisible. Fixed with a
boundary-respecting helper used everywhere.

---

## Detection quality — the false positive measurement

An agent scanned **59,289 real files (4.82 GB)** from this container: system ELF
binaries, four CPython stdlibs, all of site-packages, node_modules, fonts, docs,
`/etc` scripts. It also pulled **426 genuine Windows PE files** (`.pyd`/`.dll`) out
of 54 real `win_amd64` wheels from PyPI, since the tool targets Windows and a Linux
corpus wouldn't exercise the PE heuristics at all.

| | before | after |
|---|---|---|
| False positives at threshold 25 | 119 | **0** |
| FP rate on real Windows PE files | **27.7%** (118/426) | **0%** |
| Highest score reached by a clean file | 74 (*high* severity) | 18 |
| True-positive detection | 24/25 | **25/25** |

It was flagging **28% of ordinary MSVC-built DLLs**, two at *high* severity
(`psutil/_psutil_windows.pyd`, `pywin32/win32api.pyd` — both scored 74). The
noisiest rules and why they were wrong:

- **"No Authenticode signature"** (+6) — 425 of 426 legitimate Windows binaries are
  unsigned. Discriminates nothing. Now 0, kept as reviewer context only.
- **"Zeroed compile timestamp"** (+6) — 26% of clean binaries. Reproducible builds
  (MSVC `/Brepro`, clang, Rust, Go) zero it or store a content hash. Now 0.
- **"Non-standard section name"** (+8) — every hit was `.CRT` or `.bss`, emitted by
  every MSVC and mingw link. Section list expanded, delta lowered to 5.
- **"Zero raw size, large virtual size"** (+12, "unpacking stub") — all 49 hits were
  literally `.bss`. That *is* what BSS means. Now requires an executable non-BSS section.
- **"High-entropy section"** (+16) — every hit was `.rdata`. Compressed data in
  read-only data is normal; packed *code* is the signal. Now executable sections only.
- **`(anti_debug, dynamic_resolution)` combo** (+12) — deleted entirely. This was the
  suspicion that the data confirmed hardest: `LoadLibrary`/`GetProcAddress` is in
  almost every program, so the rule degenerated to "imports `IsDebuggerPresent`",
  true of 66% of clean binaries. Also removed `QueryPerformanceCounter` (74% of clean
  files!) and `OutputDebugString` from the anti-debug group.
- **`OpenProcess`/`SetThreadContext`** removed from process-injection — `libscipy_openblas`
  imports them. The genuine primitives (`VirtualAllocEx` + `WriteProcessMemory` +
  `CreateRemoteThread`) appear in **1 of 426** clean files, so the tightened group is
  a strong signal and kept at full score.
- **PowerShell patterns ran on `.py` files** — `.py` is in `SCRIPT_EXT`, so every
  Python file got scanned with PowerShell rules. `FromBase64String` matched a Pygments
  keyword table; bare `iex` matched the Elixir REPL name in six lexer files;
  `sdelete` matched `_isdeleted` in matplotlib; `-nop` matched inside the word
  `eat-crnl-nop` in a pandas test. Patterns are now scope-tagged.
- **Base64 blob rule** — all 31 hits were JS source maps (`sourceMappingURL=data:...;base64,`)
  or crypto test vectors. Now requires a decoder in the same file.

**No true positives were lost** — detection went *up*, because widening the dead
`net user /add` pattern (see below) recovered one.

---

## Dead detections — rules that could never fire

**`net user /add`** required `/add` immediately after `user`, but the real syntax
always has a username in between (`net user backdoor Pa55w0rd /add`). The 25-point
"creates or elevates a local account" rule had never once fired. Found independently
by three of the four agents.

**Registry autostart enumeration missed half the registry.** `winreg.OpenKey` uses
the interpreter's own bitness view: 64-bit Python saw only the 64-bit
`HKLM\...\Run` and missed everything written by 32-bit installers under
`Wow6432Node` — and **32-bit Python was worse**, transparently redirected *into*
`Wow6432Node`, never seeing the 64-bit Run key, which is the one most malware uses.
Now enumerates both views explicitly and adds `RunOnceEx`, `RunServices`,
`Policies\Explorer\Run`, and `Winlogon` `Shell`/`Userinit` hijacks.

**Autostart reporting was guaranteed noise.** The autostart directory set was built
from the whole `persistence` preset — which includes `%TEMP%`, `%LOCALAPPDATA%\Temp`
and `%WINDIR%\Temp`. So *every stray .exe in a temp folder* was reported as "executable
in an autostart location", every week. Now uses the real Startup folders only, and
the all-users Startup folder (`C:\ProgramData\...\StartUp`) was missing entirely —
a whole class of machine-wide autostart was invisible.

**TLS callbacks** fired on the mere presence of a TLS *directory*, including 21 files
with no callback array at all. Now requires a real callback array.

---

## Security holes in the local dashboard

**Command injection in `/api/open-folder`.** `os.system(f'explorer /select,"{p}"')`
goes through `cmd.exe`. A file named `x" & calc.exe & "y.txt` closes the quote early
and **cmd.exe runs `calc.exe`**. Ordinary filenames with `&` (`rock & roll.exe`) broke
it too, and `%TEMP%` in a folder name got expanded by cmd. Now a `shell=False`
`Popen` with no shell anywhere in the chain.

**Empty path opened the server's working directory** — `os.path.abspath("")` is the
cwd, which always exists, so the guard passed and the handler launched a file
manager on the project folder. This actually spawned a real `xdg-open` during testing.

**`finding_id: true` quarantined finding #1.** `isinstance(True, int)` is `True` in
Python, so a request that named no finding moved a file off disk.

**Eight routes returned 500 with a stack trace** on a valid-but-non-object JSON body
(`[1,2,3]`, `"str"`, `42`). `silent=True` only covers *unparseable* bodies. Same
class of bug: `.strip()` on a non-string sha256, unguarded `int()` on
`report_threshold`, `int(None)` on restore/purge (only `ValueError` was caught, not
`TypeError`).

---

## Concurrency

`engine.PROGRESS` is a module global that `run_scan` reassigns, and the reassignment
happened *after* the start-up work. Two consequences, both reproduced with a 0.6s
artificial delay: two concurrent scan requests both reported success while only one
scan ran, and a cancel issued right after start-up was written to the *previous*
scan's progress object — so the full scan ran to completion, ignoring the cancel.
Now a single `_begin_scan()` acquires the lock and publishes fresh progress
atomically, and the lock is the only gate.

---

## Documentation was overclaiming

The README said a missed weekly scan "runs the next time you boot". Wrong on two
counts. An `Interactive`-logon task runs **only while that user is signed in** — a
locked screen counts, a signed-out machine does not. So `-WakeToRun` only helps if
the machine slept with you still signed in; otherwise Windows may wake the box, find
no eligible session, and go back to sleep without scanning. `StartWhenAvailable`
then runs the missed occurrence after the next **sign-in**, with Windows' own delay
of up to ten minutes — not at boot. Also `RunLevel Limited` means admin/SYSTEM-only
files are silently unreadable, which matters for a security scanner. README corrected.

`install_schedule.ps1` also had a real defect: with only the `py` launcher installed
it computed `pythonw.exe` from `py.exe`'s directory (`C:\Windows`), where
`pythonw.exe` doesn't exist — so it silently fell back to flashing a console window
every week. The windowless twin of `py.exe` is `pyw.exe`. And with **Microsoft Store
Python**, `Test-Path` *succeeds* on the zero-length AppExecutionAlias, so the script
happily registered a task that Task Scheduler can never launch — failing with 0x2
forever, with nothing telling you. Now detects and refuses with instructions.

---

## Not fixed — carried forward

- **`follow_symlinks: true` + a directory symlink loop** produced 41 findings for 1
  physical file. Real, but opt-in and off by default; a partial guard was added.
- **`store.connect()` never closes connections**, relying on refcounting. No FD
  exhaustion observed over a 250-finding scan, but it makes tempdir cleanup on
  Windows unreliable.
- **`/reports/<name>` symlink escape** — `send_from_directory` resolves symlinks, so a
  symlink planted *inside* the reports folder is served. Needs local write access to
  exploit. Nine `..`/URL-encoding traversal variants are asserted safe.
- **`feeds.py` hardcodes `parts[8]`** for the malware family label. MalwareBazaar's
  column count differs between export versions; worth checking against a live export.
- **`_looks_random()`** (the replacement for the naive `[a-z0-9]{16,}` filename rule)
  is the merge agent's own design, not measured against the 59k corpus.
- **The non-printable-bytes rule is close to dead** — its UTF-16 validity check
  accepts almost any even-length byte string.
- **Archive contents still aren't inspected.** A `.zip` is hashed, not unpacked.

## What none of this covers

Every Windows-specific fix was reasoned and mock-tested on Linux — **not executed on
Windows.** The icacls sequence, `\\?\` prefixing, `GetLogicalDrives`, OneDrive
attribute checks, toast delivery and the Explorer launch are all correct-by-argument,
not correct-by-observation. The benign corpus was 99.3% Linux; only 426 files were
real PEs, and all of them one genre (Python C-extension modules). No
Microsoft-signed OS binaries, no .NET assemblies, no legitimately-packed commercial
installers — so the packer and entropy rules were never measured against real signed
installers, which is where I'd expect the next false positives. And no real malware
was used anywhere: detection is measured against 25 harmless structural decoys, which
proves the rules fire on the shapes they target and says nothing about real-world
samples.

See `CLAUDE_CODE_PROMPT.md` for the Windows verification pass.
