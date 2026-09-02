# Claude Code prompt

Open Claude Code in `D:\ClaudeCode\Sentry` and paste **Prompt 1**. It runs
everything, fixes what it can, and writes `docs\WINDOWS_REPORT.md` for you to
read. You should not need to answer anything while it works.

Everything Windows-specific in this build was reasoned about and mock-tested on
Linux, never executed. The quarantine ACL sequence especially — it decides
whether you can get a quarantined file back, and it has never actually run.

---

## Prompt 1 — full Windows verification, unattended

```
You are verifying a Python project at D:\ClaudeCode\Sentry on Windows. Read
docs\FINDINGS.md first — it explains what the tool does, what was fixed, and
which parts have never been executed on Windows.

Sentry is a local heuristic file scanner. It flags suspicious files; the user
marks each one Malicious / Unknown / Safe; only then can it be quarantined
(moved to %LOCALAPPDATA%\Sentry\quarantine with the original path recorded so it
can be restored exactly).

WORK UNATTENDED. Do not ask me questions — I am not watching. Where a choice
comes up, make the reasonable one, note it in the report, and continue. Work
only inside D:\ClaudeCode\Sentry. Never download or create real malware. Never
quarantine or delete a real game or program file. Use only decoys you create.

Do all of the following, then write the report.

STEP 1 — Environment
Record: Python version and full path, which interpreter layout this is
(python.org install / py launcher only / Microsoft Store), whether pip
dependencies install cleanly, whether LongPathsEnabled is 0 or 1
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem), and
whether OneDrive is in use. Install requirements.txt if needed. If Flask has no
wheel for this Python version, say so — only the dashboard needs it, the scanner
and reports do not.

STEP 2 — Test suites
Run all five and record exact counts:
  python tests\selftest.py
  python tests\test_correctness.py
  python tests\test_windows_paths.py
  python tests\test_detection_quality.py
  python tests\run_tests.py
Two tests skip on Linux with "running as root; permissions are not enforced".
On Windows they should ACTUALLY RUN. If they still skip, that is a real bug in
the skip condition — find it and fix it.
Fix any failure, re-run, and record what you changed. Do not weaken or delete a
test to make it pass.

STEP 3 — Quarantine ACL round-trip  ← the highest-risk item, do it carefully
The old code used `icacls /inheritance:r` + `/grant:r USER:(R)`, which leaves a
file with no DELETE right, so restore and purge would fail Access Denied on
every quarantined file. The replacement uses `/inheritance:d`, a deny-execute ACE
for the Everyone SID *S-1-1-0, and the read-only attribute. That reasoning has
never been tested on Windows.

Build a harmless decoy: copy C:\Windows\System32\notepad.exe to
%USERPROFILE%\Downloads\invoice.pdf.exe (the double extension makes it flag).
Then, via `python -m sentry serve` and its HTTP API or directly through the
Python modules: scan it, mark it malicious, quarantine it, and:
  - run `icacls` on the quarantined file and PASTE THE ACTUAL OUTPUT
  - confirm the file cannot be executed
  - restore it, confirm it returns to the exact original path with its original
    attributes
  - quarantine again, then purge, and confirm it is gone
Repeat for: a decoy on a different volume from %LOCALAPPDATA% (cross-volume
move), and a decoy on a FAT32/exFAT USB stick if one is attached (skip if not).
If any step fails, fix the code in sentry\quarantine.py, re-run, and show the
before/after icacls output. Delete every decoy when done.

STEP 4 — Scheduled task
  powershell -ExecutionPolicy Bypass -File .\scripts\install_schedule.ps1
Then:
  Get-ScheduledTask -TaskName 'Sentry Weekly Scan' | Get-ScheduledTaskInfo
  Start-ScheduledTask -TaskName 'Sentry Weekly Scan'
LastTaskResult must be 0. Confirm no console window flashes and that a report
appears in %LOCALAPPDATA%\Sentry\reports. If this machine has Microsoft Store
Python, the script is supposed to REFUSE with instructions rather than register
a task that can never run — verify it actually does.

STEP 5 — Long paths and OneDrive
Create a path over 300 characters containing a decoy the scanner should flag,
and confirm it IS found. Before the \\?\ fix, deep trees were silently skipped
and the scan reported clean, so this matters most if LongPathsEnabled is 0.
If OneDrive is set up: set a test folder to "Free up space", scan it, and
confirm the network counter stays flat and a skipped-placeholder count appears
in the scan notes. If OneDrive is not set up, say so and skip.

STEP 6 — Notifications and the dashboard
Run `python -m sentry weekly` and confirm a toast actually appears (the old
AppUserModelID was not registered on stock Windows and Show() does not throw for
an unusable one, so it silently did nothing). Test with Focus Assist on too.
Then `python -m sentry serve` and check: the folder picker across every drive,
"Open folder" on files named `rock & roll.exe` and `report^1.exe` (this used to
be a command injection through cmd.exe), and a mark → quarantine → restore cycle
in the UI.

STEP 7 — The real test: a full scan of D:
  python -m sentry scope --only D:\
  python -m sentry weekly
Record how long it took, how many files, and EVERY finding. For each one, judge
honestly whether it is a false positive. This is the number that matters most.

D: has games on it. Anti-cheat and DRM are packed and obfuscated by design, so
the build damps structure-only scores inside game and application folders
(steamapps, Epic Games, Riot Games, Program Files, node_modules, and ~60 more)
and blocks quarantine there entirely. Verify that worked: confirm nothing from a
game install appears at medium or high severity, and confirm the protected rows
are marked as such in the dashboard. If game files ARE surfacing, work out which
specific heuristic fired and whether config.PROTECTED_SEGMENTS is missing a
folder name used on this machine — add it, note it, re-run.
Do NOT quarantine anything real. Findings only.

STEP 8 — Write the report
Create docs\WINDOWS_REPORT.md, written for someone who will read it and nothing
else. Plain language, no jargon dumps. Include:
  - A verdict in the first three lines: is this build trustworthy on Windows,
    yes or no, and the single most important reason.
  - A table: each of steps 1-7, PASS / FAIL / SKIPPED, one line of evidence.
  - Everything you fixed, with file:line and why it was broken.
  - Everything still broken or unverified, and what the practical consequence is
    for someone relying on this tool.
  - The full-scan results: duration, file count, every finding, and your honest
    false-positive judgement on each.
  - Anything in docs\FINDINGS.md that turned out to be WRONG about Windows. I
    would rather know.
  - A short "what I would do next" list, ranked.
Commit nothing to git. Just leave the report and the fixed code in place.
```

---

## Prompt 2 — if you want the next feature built

Pick one and paste it. Ranked by how much it improves real detection.

```
Add archive inspection to Sentry (D:\ClaudeCode\Sentry). A .zip is currently
hashed but never opened, which is how most malware actually arrives. Unpack
zip/7z/rar/iso/cab in memory, bounded — refuse anything with a compression ratio
over ~100:1 or more than N entries so a zip bomb cannot kill a scan — run the
existing per-file scoring on each entry, and attribute findings as
"archive.zip -> inner\path.exe" so the dashboard shows both. Nested archives to a
depth limit. Read docs\FINDINGS.md first for how scoring and the false-positive
tuning work. Add tests to tests\ and keep all five suites passing.
```

```
Add Authenticode signature validation to Sentry (D:\ClaudeCode\Sentry).
heuristics.py currently only checks whether a signature is PRESENT, and
docs\FINDINGS.md explains why presence alone is worthless (425 of 426 legitimate
Windows binaries in the test corpus were unsigned). The useful version is the
inverse: verify the certificate chain with WinVerifyTrust via ctypes, treat a
validly-signed binary from a trusted publisher as a strong NEGATIVE signal that
suppresses the weak structural heuristics, and treat a BROKEN or expired
signature as a positive signal since that is real tampering evidence. This would
also cut game false positives further, since most shipped game binaries are
signed. Cache by hash. Add tests; keep all five suites passing.
```

```
Add process-creation monitoring to Sentry (D:\ClaudeCode\Sentry). It has no
real-time component — the weekly scan only sees aftermath. Add a usermode ETW
consumer (Microsoft-Windows-Kernel-Process) that watches process starts and
flags: unsigned binaries launching from %TEMP% or %APPDATA%, script hosts spawned
by Office processes, and any process whose image path matches an existing
quarantine entry. Log to the existing sqlite store as a new indicator type so it
appears in the weekly report. Usermode only — no kernel driver, no signed-driver
requirement. Add tests with a fake event source; keep all five suites passing.
```
