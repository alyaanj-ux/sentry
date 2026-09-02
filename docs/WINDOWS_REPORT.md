# Sentry on Windows — verification report

Machine: Windows 11 Pro 10.0.26200, python.org Python 3.14.7, run unattended on 2 September 2026.
Everything below was executed on this machine, not simulated. All decoys were copies of `notepad.exe`.

## Verdict

**Yes, this build is trustworthy on Windows — after the fixes in this pass.** The single most
important reason: the quarantine round-trip (deny-execute ACL, restore to the exact path, purge) works
exactly as designed on real NTFS, so the tool can never strand a file. As found, however, the build had
one silent coverage hole (any folder deeper than 260 characters was skipped and reported clean) and a
first full scan of D: was almost entirely false positives (19 of 20). Both are fixed and re-verified;
the same scan now returns 5 findings, none from a game install above "low".

## Step results

| Step | Result | Evidence |
|---|---|---|
| 1 Environment | PASS | python.org 3.14.7 at `C:\Python314`, py launcher present, Store aliases exist but lose to PATH; all requirements install (Flask 3.1.3, pefile, yara-python 4.5.4); LongPathsEnabled = 0; OneDrive in use; not elevated. |
| 2 Test suites | PASS (after fixes) | Before: 3 of 5 suites crashed on cp1252 encoding, unittest had 27 failures + 2 errors + 9 skips. After: 29/29, 29/29 (1 honest skip), 97/97, detection gate 25/25, unittest 544 run / 537 passed / 0 failed / 7 skipped. The two "running as root" tests now really run on Windows. |
| 3 Quarantine ACL round-trip | PASS | Both volumes: quarantined file shows `Everyone:(DENY)(X)` + read-only, `CreateProcess` refused with Access Denied, restore lands on the exact path with attributes intact and the file runs again, purge removes file, sidecar and manifest. FAT32/exFAT: SKIPPED, no removable volume attached. |
| 4 Scheduled task | PASS | Registered as `C:\Python314\pythonw.exe -m sentry weekly`; run manually: pythonw with window handle 0, no console python.exe, LastTaskResult 0, report `scan_2026-09-02_1614_id29.html` written. Store-Python refusal verified by hiding the real interpreter from PATH: script throws the install instructions, exit 1, task untouched. |
| 5 Long paths and OneDrive | FAIL → fixed → PASS | 316-character decoy: scanned as "0 files, clean" before the fix, found at its plain path after. OneDrive: 851 of 854 files are placeholders, all skipped, 0 hydrated, 11 KB of network traffic during the scan (background noise), note in scan output. |
| 6 Notifications and dashboard | PASS (Focus Assist unverified) | Toasts recorded in the Windows notification database for the scheduled run and for my test; click did nothing (fixed, see below). Dashboard via HTTP API: 33/33 checks, including drive picker on C: and D:, `rock & roll.exe` and `report^1.exe` opening Explorer with nothing else spawned, full mark → quarantine → restore cycle, protected-folder refusal and override. |
| 7 Full scan of D: | PASS (after fixes) | First run: 4 min 10 s, 83,231 files, 20 findings (19 false positives, one arguable). Final run with fixes: 1 min 42 s (warm cache), 83,178 files, 5 findings, 0 game-install files at medium or high, protected rows marked and damped. |

## What I fixed

### Product code

1. **Deep folders were silently skipped** — `sentry/config.py:305` (`long_path(..., always=)`),
   `sentry/engine.py:137`, `sentry/behavior.py:86`.
   The `\\?\` prefix was only applied when the *root* of the walk was already 240+ characters. A real
   scan root is short (`D:\`), so `os.walk` ran unprefixed and the first directory beyond 260 characters
   failed inside `scandir`, was swallowed by `onerror`, and the whole subtree vanished. Reproduced with a
   316-character decoy on this machine (LongPathsEnabled = 0): "0 files, clean". Now the walk root is
   always prefixed and user-visible paths are stripped back. Regression tests:
   `tests/test_engine.py:237`, `tests/test_behavior.py:406` (Windows-only, they build the real tree).

2. **Weekly report and scan row could record another scan's numbers** — `sentry/store.py:132`
   (`get_scan`), `sentry/__main__.py:85`.
   `cmd_weekly` looked up "the last finished scan" after its own scan ended. With the dashboard open, a
   4-file manual scan started and finished during the 83,000-file weekly run, became "last", and the
   weekly HTML report and database row said "4 files checked". Now the command uses its own scan id and
   the engine's summary. Test: `tests/test_engine.py:410`.

3. **Sentry's own files were reported as high-severity malware** — `sentry/engine.py:124`,
   `sentry/config.py:355` and `:378` (`scan_self` setting).
   The install folder is excluded by default, but the exclusion lived only in the default list. The
   saved `config.json` on this machine (written by an earlier build) carries its own list without it,
   so the D: scan flagged `tests/test_heuristics.py`, `tests/test_detection_quality.py` and five more of
   Sentry's own files, four of them at *high*. The scanner now prunes its own folder regardless of the
   exclusions list unless `scan_self: true` is set. Test: `tests/test_config.py:462`.

4. **`System.Xml.dll` counted as a "double extension disguising an executable"** —
   `sentry/heuristics.py:142`.
   `.dll` was in the list of launchable extensions. A DLL cannot be launched by double-click, so a
   document-like middle part disguises nothing, and .NET names assemblies after namespaces
   (`System.Xml.dll`, `Newtonsoft.Json.dll`). This rule is a "strong signal", so it bypassed the
   protected-folder damping and produced five medium findings inside Hollow Knight and Elden Ring. `.dll`
   removed from the trailing group. Tests: `tests/test_heuristics.py:85` (expectation corrected, with the
   reason in a comment) and `:213`.

5. **.NET assemblies scored for "tiny import table" and "future timestamp"** —
   `sentry/heuristics.py:377`, `:484`, `:539`.
   A managed assembly imports one native stub and stores a build hash in the timestamp field. The
   benign corpus in FINDINGS.md contained no .NET files, so this was never measured. The PE analyser
   now detects the CLR header and skips both rules, reporting ".NET assembly" as context at score 0.
   Test: `tests/test_heuristics.py:997` (needs the new `PEBuilder.mark_dotnet()` in `tests/support.py:355`).

6. **Toast notifications did nothing when clicked** — `sentry/notify.py:38` (`launch_uri`), `:52`, `:30`.
   You reported this during the run and the notification database confirms it: the scheduled run's toast
   had no `launch` target, because `notify()` received the report path and dropped it. The toast is now
   protocol-activated with a `file:///` URI to the HTML report and carries an explicit "Open report"
   button. The database shows the new toasts with the launch attribute; I could not click one unattended,
   so please try the "Sentry verification toast 2" in the notification centre. Tests in
   `tests/test_windows_paths.py` (toast section), including path-quoting safety.

7. **`Games` added to `config.PROTECTED_SEGMENTS`** — `sentry/config.py:193`.
   `D:\Games\...\Spider-Man.exe` scored 100 (high) and its `steam_api.dll` files 47 (medium) from
   structure alone, because a plain "Games" folder was not a protected location. Trade-off stated in the
   comment there: a cracked `steam_api.dll` (packed, writable-and-executable sections, which is what those
   two DLLs are) is now damped below the report threshold as well. Only a strong signal (bad hash, YARA,
   content/extension mismatch) surfaces a trojaned repack in that folder. Test: `tests/test_config.py:479`.
   One existing web-UI test used a folder named `Games` as a neutral location; its fixture was renamed to
   `Downloads` (`tests/test_webui.py:1054`), assertions unchanged.

### Test harness (these were why the suites could not even run on Windows)

- `tests/selftest.py:26`, `tests/test_correctness.py:28`, `tests/test_windows_paths.py:35`: stdout is
  reconfigured to UTF-8. Under a redirect or a batch file, Python uses cp1252 and the box-drawing
  characters aborted the run before the first check.
- `tests/test_windows_paths.py:378`, `:384`, `:562`, `:581`: source files are opened with
  `encoding="utf-8"`; `webui.py` contains a byte cp1252 cannot decode.
- `tests/support.py:135` (`deny_directory_listing`), `:162` (`is_listable`), `:122`: the two
  "running as root; permissions are not enforced" tests used `os.chmod(dir, 0o000)` and `os.access`.
  On Windows chmod only toggles the read-only attribute and `os.access` reports readable for anything
  that exists, so they skipped on every Windows machine with a misleading reason. They now deny the
  list-directory right for Everyone with icacls and probe with a real listing. Both tests now run and
  pass here (`tests/test_engine.py:295`, `tests/test_webui.py:416`).
- `tests/test_behavior.py:188`: sweep tests stub the registry reader; on Windows the real HKCU/HKLM Run
  keys added an inventory indicator to every result and 13 tests failed.
- `tests/test_config.py:192`, `:302`, `:317`: `ntpath.expanduser` reads `USERPROFILE`, never `HOME`.
- `tests/test_engine.py:174`: the exclusion test passed literal `%SystemRoot%\WinSxS` as a path, which
  Windows expands on one side only.
- `tests/test_quarantine.py:189`, `:286`: two tests unlinked a hardened (read-only) file; they now
  unharden first. The POSIX-branch failure-shape test pins `IS_WINDOWS = False`.
- `tests/test_correctness.py:113`: the "unstorable filename" test built a name from a raw 0xFF byte, which
  Windows cannot represent; on Windows it now uses an unpaired surrogate, the real NTFS equivalent.
- `tests/test_correctness.py:183`: the symlink-refusal test reports SKIP when Windows refuses to create a
  symlink (privilege not held) instead of failing.
- New Windows-only ACL tests: `tests/test_quarantine.py` `TestHardeningWindowsReal` (deny-execute really
  blocks `CreateProcess`, DELETE really survives, unharden really restores).

## Still broken, unverified, or worth knowing

- **Focus Assist / Do Not Disturb not tested.** There is no supported way to toggle it unattended. Expected
  behaviour: the toast is delivered to the notification centre silently and the tray-balloon fallback is
  not used, because the notifier's `Setting` still reads Enabled under DND. Practical consequence: you may
  miss the weekly result until you open the notification centre.
- **FAT32/exFAT quarantine not tested** (no removable drive). On those volumes icacls fails and only the
  read-only attribute protects the file; that branch is reasoned, not observed.
- **Symlink handling not exercised on Windows.** This session cannot create symlinks (not elevated, no
  Developer Mode), so the symlink-refusal tests skip. The code path is unchanged from the Linux-verified
  version.
- **Findings are never retired.** A file flagged by an earlier scan stays "open" in the dashboard even if
  the next scan no longer flags it. Right now the dashboard still lists the seven Sentry-own files from
  the first D: scan at their old high/medium scores; they will not reappear in new reports, but you have
  to dismiss them by hand. The database has 212 open findings accumulated since August.
- **Detection-quality false-positive half cannot run here.** It looks for Linux corpus roots. On this
  Windows machine only the true-positive half runs. A Windows corpus (`C:\Windows\System32`,
  `Program Files`, a Unity game's `Managed` folder) is the obvious next addition.
- **`files_scanned` counts placeholders it did not read.** The OneDrive scan reported 854 files checked
  while 851 were skipped placeholders. Cosmetic, but it overstates coverage.
- **Restore re-inherits the ACL from the destination folder.** Restored files get the folder's inherited
  permissions; any custom explicit ACEs the original had are not preserved. For ordinary user files this
  is invisible.
- **The quarantine of a file beyond 260 characters** was not separately exercised (scanning was). The code
  prefixes source paths above 240 characters, so it should work, but "should" is the honest word.
- **Signature presence only.** `node.exe` is Authenticode-signed by the Node.js Foundation and still lands
  at medium. Nothing validates signatures, so a signed binary from a known publisher gets no credit.

## Full scan of D: — results and judgement

First run (before the Step 7 fixes): 4 min 10 s, 83,231 files, 0 read errors, 20 findings.
Final run (all fixes applied, nothing else running): 1 min 42 s, 83,178 files, 0 read errors, 5 findings.
The scheduled-task run in Step 4 (before the fixes) took 5 min 24 s for 83,205 files; the drop to 1:42 is a
warm file cache, not a code change. The Sentry folder is now pruned, which accounts for the 53 fewer files.

Every finding from the first run, and my judgement:

| # | File | Score | Judgement |
|---|---|---|---|
| 1 | `D:\ClaudeCode\Sentry\tests\test_detection_quality.py` | 100 high | False positive. Sentry's own test fixtures. Cause: config exclusion missing (fix 3). Gone. |
| 2 | `D:\ClaudeCode\Sentry\tests\test_heuristics.py` | 100 high | False positive, same cause. Gone. |
| 3 | `D:\Games\Marvels-Spider-Man-Remastered-AnkerGames\...\Spider-Man.exe` | 100 high | Almost certainly a false positive as *malware*: every reason is an import combination that a AAA engine legitimately has (raw input, sockets, registry, BCrypt, APC). But this is a repack from a piracy site, which is exactly where trojans travel, and a structural scanner cannot tell. Now 32 low, damped by the new `games` segment. I would check its hash on VirusTotal once. |
| 4 | `D:\ClaudeCode\Sentry\tests\test_behavior.py` | 84 high | False positive, fixture strings. Gone. |
| 5 | `D:\ClaudeCode\Sentry\sentry\heuristics.py` | 69 medium | False positive: the rule definitions themselves. Gone. |
| 6 | `D:\ClaudeCode\Sentry\sentry\config.py` | 68 medium | False positive: the docstring mentions the strings. Gone. |
| 7 | `D:\Software Development\NODE\node.exe` | 63 medium | False positive. Official Node.js binary (Authenticode-signed); `CreateRemoteThread`/`OpenProcess` are its inspector/debugger. Still reported: mark it safe in the dashboard. |
| 8 | `D:\ClaudeCode\Sentry\tests\selftest.py` | 51 medium | False positive, fixture strings. Gone. |
| 9 | `D:\ClaudeCode\Sentry\tests\test_engine.py` | 51 medium | False positive, fixture strings. Gone. |
| 10 | `D:\Software Development\NODE\install_tools.bat` | 50 medium | False positive with a caveat: this is the "Tools for Node.js" script from the official installer, and it genuinely does `powershell -ExecutionPolicy Bypass` + download-and-`iex`. The rule is right about the shape; the file is known-good. Still reported. |
| 11 | `...AnkerGames\...\steam_api.dll` | 47 medium | Not malware, but not clean either: packed, writable-and-executable `WUS0/WUS1` sections are the signature of a Steam emulator / crack. Now damped below threshold by `games`. This is the trade-off of fix 7. |
| 12 | `...AnkerGames\...\steam_api64.dll` | 47 medium | Same as 11. |
| 13–17 | `System.Xml.dll` ×4 and `Newtonsoft.Json.dll` ×1 under `SteamLibrary\steamapps\common\{Hollow Knight, ELDEN RING ...}` | 46 medium | False positives. Stock .NET assemblies shipped with Unity games; flagged by the `.Xml.dll` double-extension bug (fix 4) plus the .NET import-table and timestamp rules (fix 5). Gone. These were the game files that reached medium *despite* living in a protected folder, because the buggy rule counted as a strong signal. |
| 18 | `D:\mods\ModEngine-0.1.16\...\dinput8.dll` | 40 low | True positive for what it says, false positive for malware: Mod Engine is a well-known Souls-series mod loader that proxies `dinput8.dll` and writes into the game process by design. Low is the right severity. Unchanged. |
| 19 | `...AnkerGames\...\crs-handler.exe` | 25 low | False positive: the game's crash-report handler (window focus + WinHTTP). Now damped under `games`. |
| 20 | `SteamLibrary\steamapps\common\ELDEN RING\Game\eossdk-win64-shipping.dll` | 25 low (damped from 84) | False positive handled correctly by the existing damping: Epic Online Services SDK. Unchanged. |

Protected-folder check: in the first run, 6 findings were inside protected folders and 5 of them sat at
medium because of the double-extension bug. In the final run, 2 findings are inside protected folders, both
at low, both showing the "Score reduced from … Quarantine is blocked for this location" note, and the
dashboard rows carry the `protected` field (verified over the API, 63 historical rows marked). The
protected segment that was missing on this machine was `games`; `mods` and `AYN THOR games` produced
nothing above low and were left alone. No real file was quarantined at any point.

## Where FINDINGS.md was wrong about Windows

- **"Long paths … now prefixed at every syscall."** Not for the walk itself. The prefix was applied only
  when the root was already long, so the exact failure the fix described (deep trees silently skipped,
  scan reports clean) still happened on this machine until fix 1.
- **"515 tests, 513 passed, 2 skipped … all five re-verified."** That was on Linux. On Windows, as
  delivered, three of the five suites crashed before running a single check and the unittest run had 27
  failures and 2 errors, almost all from tests that assumed POSIX behaviour (HOME, chmod, no registry).
- **"Two tests skip … running as root."** On Windows they skipped for a different reason: the skip
  condition itself was wrong (chmod/`os.access` cannot express "unreadable" on Windows). Not a root issue.
- **"False positives at threshold 25: 0" / "FP rate on real Windows PE files: 0%".** On this real Windows
  drive the first full scan produced 20 findings, 19 of them false positives. The corpus had no .NET
  assemblies, no repacked games, and no dev tools such as `node.exe`, which is where the misses were.
- **The toast fix.** The AppUserModelID change did make toasts appear, as claimed, but the toast was
  inert when clicked because the report path never reached the script. That was not a Windows finding in
  the document at all; you found it.
- **"Remove it from `exclusions` if you would rather see it"** (the install-dir exclusion). It was already
  absent from the config on this machine without anyone removing it, and the document did not consider
  a pre-existing `config.json`.
- **What was right:** the icacls reasoning. `/inheritance:d` + deny-execute for `*S-1-1-0` + read-only
  behaves exactly as argued, on both volumes, and the restore/purge DELETE problem is really gone.

## What I would do next, ranked

1. **Validate Authenticode signatures** (WinVerifyTrust via ctypes) and damp files signed by a trusted
   publisher. This alone would have removed `node.exe` and is the largest remaining false-positive lever on
   Windows.
2. **Retire stale findings**: when a scan covers a path and no longer flags a file, mark the old finding
   resolved instead of leaving it open forever.
3. **Add a Windows benign corpus** to `test_detection_quality.py` (System32, Program Files, a Unity
   `Managed` folder, a `node_modules` tree) so the false-positive gate actually runs on the platform the
   tool targets.
4. **Decide the policy for `Games` deliberately.** Either keep the damping and accept that cracked
   `steam_api.dll`s are hidden, or keep the packer signals at reduced weight there. The current choice is
   documented in the code comment; it should be a conscious product decision.
5. **Test the FAT32 branch and Focus Assist by hand** the next time a USB stick is plugged in and you are
   at the keyboard; both are five-minute checks that cannot be automated safely.
6. **Make `files_scanned` exclude skipped placeholders**, or report both numbers, so coverage is not
   overstated on OneDrive-heavy profiles.
7. **Enable Developer Mode or run one elevated test pass** so the two symlink tests execute on Windows
   at least once.

## Housekeeping

- Nothing was committed to git (the folder is not a repository).
- Decoys created and removed: `%USERPROFILE%\Downloads\invoice.pdf.exe`, `Downloads\SentryUiTest\`,
  `D:\ClaudeCode\Sentry\_decoys\`, `D:\ClaudeCode\Sentry\_longpath\`. All confirmed absent, quarantine
  folder empty, no finding or verdict rows left pointing at them.
- The dashboard robustness check briefly set `max_file_mb` to 1 in the real config; it was restored to 128.
- The real config now has `custom_paths: ["D:\\"]` and no presets, as `scope --only D:\` leaves it.
- Scan rows 25–33 and reports `scan_2026-09-02_1614_id29.html` / `_1624_id31.html` / `_1631_id33.html`
  were produced by this pass. Row 31 still carries "4 files" from the race in fix 2; row 33 is correct.
- The "Sentry Weekly Scan" task was replaced (it already existed from an earlier install) and is scheduled
  for Sundays at 12:00 under `pythonw.exe`.
