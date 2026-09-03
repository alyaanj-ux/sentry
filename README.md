# Sentry

A local heuristic file scanner for Windows. Scans the folders you choose, runs a
weekly check on a schedule, and lets you mark each flagged file **Malicious**,
**Unknown**, or **Safe** — then quarantine or delete it on your terms.

**It never moves or deletes anything on its own.** Quarantine only runs when you
click it, and only on a file you have already marked malicious or unknown. That
rule is enforced in code (`quarantine.py`), not just documented.

This is a detection tool, not endpoint protection. It has no real-time
component and no kernel driver. **Keep Windows Defender (or whatever you use)
enabled and run this alongside it.**

---

## Layout

Everything lives inside this one folder.

```
Sentry\
├── Sentry.bat          <- start here (menu: dashboard, scan, scope, tests)
├── README.md
├── requirements.txt
├── sentry\             the Python package
├── tests\              all test suites and the runner
├── scripts\            individual .bat launchers + install_schedule.ps1
└── docs\               review findings, Windows verification prompt
```

Scan results, quarantined files and reports are NOT stored here — they live in
`%LOCALAPPDATA%\Sentry` so that reinstalling or moving this folder never touches
your quarantine. See "Where things live" below.

## Quick start

Double-click **`Sentry.bat`** and pick an option. Or from a terminal:

```
cd /d <the folder you cloned into>
python -m pip install -r requirements.txt
python tests\run_tests.py          verify the build (556 tests)
python -m sentry serve              dashboard at http://127.0.0.1:8787
python -m sentry weekly             scan + HTML report + notification
```

In cmd.exe, `cd D:\...` from a C: prompt does not change drive — use `cd /d`.
`Sentry.bat` and every script in `scripts\` handle this for you.

The suite is `unittest`, and `run_tests.py` is the runner the counts above refer to:
**556 tests, 549 passing, 7 skipped.** `pytest` also works and reports a larger number —
**574 collected, 567 passing, 7 skipped, plus 1158 subtests** — because it counts the
module-level checks in `test_windows_paths.py` individually where the unittest runner
groups them. Both are green; they are two ways of counting the same suite.

## Install

You need Python 3.10 or newer. Check with `python --version`.

```
cd <the folder you cloned into>
pip install -r requirements.txt
```

If `yara-python` fails to build, ignore it — everything else still works and the
dashboard will tell you pattern rules are disabled.

## Run the dashboard

```
python -m sentry serve
```

Opens `http://127.0.0.1:8787` in your browser. Or double-click
`run_dashboard.bat`.

The server binds to loopback only and rejects requests that don't carry a local
header, so a random web page you visit can't drive it.

## Set up the weekly scan

```
powershell -ExecutionPolicy Bypass -File .\scripts\install_schedule.ps1
```

Defaults to Sunday at 12:00. Change it:

```
powershell -ExecutionPolicy Bypass -File .\scripts\install_schedule.ps1 -Day SAT -Time 21:30
```

The task is registered to run as you, with `LogonType Interactive`, which means
it **only runs while you are signed in** — a locked screen is fine, a signed-out
or logged-off machine is not. `StartWhenAvailable` is on, so a scan missed
because the PC was off or signed out runs shortly after your next **sign-in**
(Windows adds its own delay, typically up to 10 minutes) rather than silently
skipping the week. It does not run at boot before you sign in, and `-WakeToRun`
only wakes the machine usefully if you were still signed in when it slept.

The task also runs unelevated (`RunLevel Limited`), so files readable only by
Administrators or SYSTEM are skipped without an error.

Each run writes a timestamped HTML report to `%LOCALAPPDATA%\Sentry\reports` and
shows a Windows notification.

Remove it with `scripts\install_schedule.ps1 -Remove`.

---

## The three verdicts

| Verdict | What it does |
|---|---|
| **Malicious** | Unlocks the Quarantine button. Nothing moves until you press it. |
| **Unknown** | Same — for files you're suspicious of but not sure about. |
| **Safe** | Adds the file's SHA-256 to your allowlist. Future scans skip it silently, so it stops nagging you every week. |

Verdicts are keyed by SHA-256, not path. Marking a file safe covers that exact
file wherever it moves; if its contents change, it gets re-flagged.

## Quarantine

Quarantining a file:

1. Records its **original absolute path** in the database and a `.quar.txt`
   sidecar next to the quarantined copy.
2. Moves it to `%LOCALAPPDATA%\Sentry\quarantine\<sha256>.quar` — the extension
   is stripped so it can't be launched by double-click.
3. Strips inherited ACLs and denies execute for your user.

**Restore** puts it back at the exact original path with its original
permissions and clears the verdict so it gets re-reviewed. **Delete
permanently** requires two confirmations and is the only operation that removes
data.

If a quarantine attempt fails with "file is locked", something is running it.
Close that program and retry.

---

## What it actually detects

Findings are scored 0–100 and additive. Nothing here is authoritative — the
point is to rank files so you review the right ten instead of all 400,000.

**Known-bad hashes.** SHA-256 lookup against the MalwareBazaar feed, cached
locally and refreshed automatically when older than 7 days. Exact match only —
one changed byte and it misses, which is why the other layers exist. Add your
own hashes to `%LOCALAPPDATA%\Sentry\feeds\custom_bad_hashes.txt`, one per line.

**YARA rules.** Drop `.yar` files into `%LOCALAPPDATA%\Sentry\rules`. A good
starting set is the [signature-base](https://github.com/Neo23x0/signature-base)
repo. Requires `yara-python`.

**PE structure.** Packer section names (UPX, Themida, VMProtect, …), section
entropy above 7.2, writable+executable sections, entry point outside or in the
last section, missing/tiny import tables, embedded PE files in resources,
missing Authenticode signature, zeroed or future compile timestamps, TLS
callbacks.

**API import combinations.** Individually normal Win32 calls that are
suspicious together — `VirtualAllocEx` + `WriteProcessMemory` +
`CreateRemoteThread` alongside runtime `GetProcAddress` resolution is process
injection; `GetAsyncKeyState` plus network APIs is a keylogger shape; bulk
crypto plus filesystem enumeration is ransomware shape.

**Filename tricks.** Double extensions (`invoice.pdf.exe`), right-to-left
override characters that visually reverse the extension, long whitespace runs
before `.exe`, executables sitting in media folders.

**Content/extension mismatch.** A `.txt` or `.jpg` whose bytes start with `MZ`
or `\x7fELF`. High-confidence signal, rarely a false positive.

**Script obfuscation.** PowerShell `-EncodedCommand` with long base64,
`FromBase64String`, `IEX`, reflective assembly loading, execution-policy bypass,
`vssadmin delete shadows`, Defender exclusion additions, LOLBin abuse
(`certutil -urlcache`, `mshta`, `rundll32 javascript:`), nested eval/decode.

**Office macros.** VBA project presence, auto-execution entry points
(`AutoOpen`, `Workbook_Open`), `Shell()` calls, PowerShell/URLMON references.

**System indicators** (weekly run only, directory-level rather than per-file):
clusters of files with known ransomware extensions, ransom-note filenames,
executables in autostart folders, and a full inventory of `Run`/`RunOnce`
registry keys with suspicious ones called out.

### Changing what gets scanned

From the dashboard: the **Scan scope** tab. From the command line:

```
python -m sentry scope                     show current scope
python -m sentry scope --only D:\          scan ONLY D:, presets off
python -m sentry scope --add D:\Downloads  add a folder
python -m sentry scope --remove D:\Games   remove a folder
python -m sentry scope --presets none       disable all presets
python -m sentry scope --reset              back to defaults
```

Or double-click `scripts\scope_show.bat` / `scripts\scope_d_only.bat`.

`--only` is the one for a single-drive setup: it disables every preset (they all
point at C:) and replaces the custom folder list in one step. It refuses a path
that is not a directory, and warns with a nonzero exit if you end up with an
empty scope, so a mistyped path cannot silently give you a scanner that checks
nothing.

**Restricting to D: drops the autostart-folder checks**, because Windows Startup
folders live on C:. The registry autostart sweep still runs regardless of scan
scope, since it reads the registry rather than walking a directory.

**Sentry excludes its own install folder by default.** Its test suite deliberately
contains the exact strings the script heuristics hunt for — `vssadmin delete
shadows`, `certutil -urlcache`, `Add-MpPreference` — as test fixtures. Without this
exclusion, scanning the drive Sentry lives on flags Sentry itself. Remove the entry
from `exclusions` in `config.json` if you would rather see it.

### Games and installed programs

Anti-cheat and DRM are, structurally, indistinguishable from malware.
EasyAntiCheat, BattlEye, Vanguard, Denuvo and VMProtect are all *deliberately*
packed, high-entropy, obfuscated, and full of the process-injection and
anti-debug API calls the heuristics look for — because resisting tampering is
their entire job. A structural scanner flags them every single time.

Sentry handles this in two ways, which do different jobs:

**Scores are damped inside application folders.** A finding in `steamapps`,
`Epic Games`, `Riot Games`, `Program Files`, `node_modules` and similar keeps
only 30% of a *structure-only* score, and the report shows the original number
and why it was reduced. Matching is on path segments, so any drive and any
install location works — `D:\SteamLibrary\steamapps\...` counts just as much as
the default under Program Files.

**Strong evidence is never damped.** A known-bad hash match, a YARA malware
rule, an executable wearing a `.txt` extension, a script deleting shadow copies
or adding Defender exclusions — those keep full score wherever they are. This
damps "it looks hardened", never "it is behaving maliciously". A trojaned game
file still surfaces at full severity.

**Quarantine refuses these locations outright.** Moving a file out of a game
install does not neutralise something you were unsure about — it breaks the
game, usually much later and in a way nobody connects back to this tool. If a
game file really is bad, the launcher's **verify integrity of game files**
replaces it correctly and quarantine does not. The dashboard marks these rows
and offers an *Override & quarantine* button behind two confirmations, for when
you are certain.

Note the deliberate asymmetry: a *launcher filename* is not protective on its
own. Protecting `EasyAntiCheat.exe` by name would let malware immunise itself by
picking the name. Real ones live under a recognised install folder; one of those
names sitting in Downloads scores as a masquerade instead.

### Recovering a quarantined file

The **original absolute path is recorded in two places before the file moves**: the
manifest row in `sentry.db`, and a `.quar.txt` sidecar written next to the
quarantined copy — so the quarantine folder is self-describing even if the database
is lost. The original permission bits are stored too.

Each held file in the Quarantine tab has two buttons:

- **Restore to original path** — puts it back exactly where it was, byte- and
  permission-identical, and clears the verdict so it gets reviewed again next scan.
- **Mark safe & restore** — same move, and also adds the file's SHA-256 to your
  allowlist so it stops being flagged every week. This is the one for a false
  positive.

If the move fails — something else now occupies the original path — nothing is
allowlisted and the file stays held, so a failed restore can never leave you with
a "safe" verdict on a file that never came back.

From the command line, `python -m sentry quarantine` lists every entry with its
original path and current location.

### Tuning

Settings → **Reporting threshold** (default 25). Lower is noisier. If your
weekly report has too much junk, raise it to 35–40. If you want to see
everything, drop it to 15.

---

## Testing it safely

```
python tests\selftest.py
```

Builds a sandbox of harmless decoy files that reproduce structural traits
(a PE header behind a `.txt` name, a double extension, obfuscation-shaped
script text), runs the full pipeline, and asserts 29 behaviours including
that quarantine is refused without a verdict and that restore is byte- and
permission-exact.

**Do not test with real malware samples on your main machine.** If you want to
go that route, use a VM with host-only networking, no shared folders, and a
clean snapshot to roll back to.

---

## Command line

```
python -m sentry serve                  dashboard (default)
python -m sentry scan [PATH ...]        one-off scan, prints results
python -m sentry weekly                 headless scan + report + notification
python -m sentry status                 current state as JSON
python -m sentry update-feed [--full]   refresh the hash cache
python -m sentry quarantine             list quarantine entries
python -m sentry install-schedule       register the weekly task
```

## Where things live

```
%LOCALAPPDATA%\Sentry\
  sentry.db          findings, verdicts, quarantine manifest, scan history
  config.json        your settings
  quarantine\        moved files + .quar.txt sidecars
  reports\           weekly HTML reports
  rules\             your YARA rules
  feeds\             cached known-bad hashes
```

Everything is local. Nothing is uploaded anywhere. The only outbound network
request is downloading the public hash feed, which you can turn off in Settings.

---

## Known limitations

Worth being clear about, since they define what this tool can and can't do:

- **No real-time protection.** It scans when you tell it to or when the weekly
  task fires. Something can execute between scans.
- **No kernel visibility.** A real AV uses a minifilter driver to see file
  operations as they happen. That needs a signed driver — not practical to build
  solo. Behavioural detection here is static aftermath only.
- **Hash matching is exact.** Polymorphic malware defeats it trivially.
- **Locked files are skipped.** Anything a running process holds open can't be
  read or moved.
- **Heuristics produce false positives.** Packed installers, game
  anti-cheat, and legitimate admin scripts trip several of these checks. That's
  the reason nothing is automatic — a scanner that quarantined on score alone
  would eventually eat something you needed.
- **Archive contents aren't inspected.** A `.zip` is hashed, not unpacked.

## Where to take it next

If you want to keep building: unpack archives in memory and scan the contents,
add an ETW usermode consumer for actual process-creation events, train a
classifier on the [EMBER](https://github.com/elastic/ember) dataset and add its
score as another signal, or add Authenticode chain validation (signature
*presence* is checked, validity isn't).
