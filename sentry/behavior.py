"""Post-scan sweep for ransomware and persistence indicators.

This is static (it looks at what is on disk now), not a real-time monitor.
A true behavioural monitor needs a kernel filter driver on Windows; this
catches the aftermath cheaply and reliably, which is what a weekly cadence
can actually act on.
"""
from __future__ import annotations

import os
import re
from collections import defaultdict

from . import config

NOTE_EXT = {".txt", ".html", ".htm", ".hta", ".rtf"}

# An action word plus an object word, rather than a single keyword. A bare
# "readme.txt" must never match — that would fire on almost every machine.
_ACTION_PREFIXES = ("decrypt", "recover", "restore", "unlock", "encrypt")
_OBJECT_WORDS = {"file", "files", "filesystem", "data", "instruction",
                 "instructions", "instruct", "help", "howto", "how",
                 "readme", "info", "key", "keys", "guide", "important"}
_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def is_ransom_note_name(filename: str) -> bool:
    """True when a filename looks like a dropped ransom note."""
    stem, ext = os.path.splitext(filename.lower())
    if ext not in NOTE_EXT:
        return False
    tokens = {t for t in _TOKEN_SPLIT.split(stem) if t}
    if not tokens:
        return False
    if "ransom" in tokens:
        return True
    has_action = any(t.startswith(_ACTION_PREFIXES) for t in tokens)
    has_object = bool(tokens & _OBJECT_WORDS)
    if has_action and has_object:
        return True
    # Aggressive attention-grabbing prefixes combined with an action word.
    if has_action and (filename.startswith("!") or filename.startswith("#")
                       or stem.startswith("000") or "_-_" in stem):
        return True
    return False

KNOWN_RANSOM_EXT = {
    ".locked", ".crypted", ".crypt", ".encrypted", ".enc", ".cerber", ".locky",
    ".zepto", ".odin", ".thor", ".wncry", ".wcry", ".wnry", ".djvu", ".stop",
    ".cryptolocker", ".ryk", ".ryuk", ".conti", ".lockbit", ".makop", ".phobos",
    ".mkp", ".basta", ".avos", ".hive", ".pandora", ".vvv", ".ccc", ".micro",
    ".ecc", ".exx", ".ezz", ".r5a", ".xtbl", ".onion", ".aes256",
}

SUSPICIOUS_AUTOSTART_EXT = {".exe", ".bat", ".cmd", ".vbs", ".js", ".ps1",
                            ".scr", ".com", ".hta", ".jar", ".pif"}


def _under(child_nc: str, parent_nc: str) -> bool:
    """Boundary-respecting prefix test (see engine._under)."""
    return (child_nc == parent_nc
            or child_nc.startswith(parent_nc.rstrip(os.sep) + os.sep))


def sweep(paths: list[str], cfg: dict) -> list[dict]:
    """Return a list of indicator dicts (not file findings — directory-level signals)."""
    indicators: list[dict] = []
    ransom_ext_hits: dict[str, list[str]] = defaultdict(list)
    note_hits: list[str] = []
    autostart_hits: list[str] = []
    exclusions = cfg.get("exclusions", [])

    # Only the real Start Menu Startup folders count as autostart. The
    # 'persistence' preset also contains %TEMP% and %WINDIR%\Temp, and using
    # the whole preset meant every stray .exe in a temp folder was reported as
    # an "autostart entry".
    autostart_dirs = {os.path.normcase(os.path.normpath(p))
                      for p in config.startup_dirs()}

    for root_path in paths:
        if not os.path.isdir(config.long_path(root_path)):
            continue
        # Prefixed walk for the same reason as engine.iter_candidate_files:
        # a bare root means every directory beyond MAX_PATH is unreadable and
        # silently dropped -- exactly where a ransomware note would be missed.
        walk_root = config.long_path(os.path.abspath(root_path), always=True)
        for dirpath, dirnames, filenames in os.walk(
                walk_root, topdown=True, onerror=lambda e: None):
            dirpath = config.strip_long_prefix(dirpath)   # user-visible paths stay plain
            nc = os.path.normcase(os.path.normpath(dirpath))
            if _under(nc, os.path.normcase(os.path.normpath(str(config.DATA_ROOT)))):
                dirnames[:] = []
                continue
            if any(_under(nc, os.path.normcase(
                    os.path.normpath(os.path.expandvars(e))))
                   for e in exclusions):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames
                           if not config.excluded_dir_name(d)]

            for fn in filenames:
                low = fn.lower()
                ext = os.path.splitext(low)[1]
                if ext in KNOWN_RANSOM_EXT:
                    ransom_ext_hits[ext].append(os.path.join(dirpath, fn))
                if is_ransom_note_name(fn):
                    note_hits.append(os.path.join(dirpath, fn))
                if nc in autostart_dirs and ext in SUSPICIOUS_AUTOSTART_EXT:
                    autostart_hits.append(os.path.join(dirpath, fn))

    for ext, files in ransom_ext_hits.items():
        if len(files) >= 3:
            indicators.append({
                "kind": "ransomware_extension",
                "severity": "high",
                "title": f"{len(files)} files carry the ransomware-associated "
                         f"extension '{ext}'",
                "detail": "Files renamed en masse with a known ransomware extension. "
                          "If you did not encrypt these yourself, disconnect from the "
                          "network and do not pay anything before checking "
                          "nomoreransom.org for a free decryptor.",
                "examples": files[:8],
                "count": len(files),
            })

    if note_hits:
        # A single note with no matching encrypted files is more likely to be a
        # legitimate "recovery instructions" file from backup software.
        corroborated = bool(ransom_ext_hits) or len(note_hits) >= 3
        indicators.append({
            "kind": "ransom_note",
            "severity": "high" if corroborated else "medium",
            "title": f"{len(note_hits)} file(s) matching known ransom-note filenames",
            "detail": ("Ransomware drops these into every directory it encrypts."
                       if corroborated else
                       "Filename resembles a ransom note, but no encrypted files "
                       "were found alongside it — this may be a legitimate "
                       "recovery-instructions file. Open it and check."),
            "examples": note_hits[:8],
            "count": len(note_hits),
        })

    if autostart_hits:
        indicators.append({
            "kind": "autostart_entry",
            "severity": "medium",
            "title": f"{len(autostart_hits)} executable/script in an autostart location",
            "detail": "Anything here runs automatically at logon. Confirm you "
                      "recognise each one.",
            "examples": autostart_hits[:10],
            "count": len(autostart_hits),
        })

    indicators.extend(_registry_run_keys())
    return indicators


def _registry_run_keys() -> list[dict]:
    """Enumerate Windows autostart registry values. No-op elsewhere."""
    if not config.IS_WINDOWS:
        return []
    try:
        import winreg  # type: ignore
    except ImportError:
        return []

    RUN_SUBKEYS = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
        r"Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"Software\Microsoft\Windows NT\CurrentVersion\Windows",  # Load / Run
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",  # Shell/Userinit
    ]
    targets = [(hive, sk) for hive in (winreg.HKEY_CURRENT_USER,
                                       winreg.HKEY_LOCAL_MACHINE)
               for sk in RUN_SUBKEYS]

    # Registry redirection: a 32-bit Python on 64-bit Windows silently gets the
    # Wow6432Node copy of HKLM\Software\... and never sees the 64-bit Run key;
    # a 64-bit Python sees only the 64-bit copy and misses autostart entries
    # written by 32-bit installers. Enumerate BOTH views explicitly and dedupe.
    views = [("64", getattr(winreg, "KEY_WOW64_64KEY", 0)),
             ("32", getattr(winreg, "KEY_WOW64_32KEY", 0))]

    # Winlogon values that are load points but not free-form Run entries. Their
    # normal contents are benign and must not be flagged.
    WINLOGON_DEFAULTS = {
        "shell": {"explorer.exe"},
        "userinit": {r"c:\windows\system32\userinit.exe,",
                     r"c:\windows\system32\userinit.exe"},
        "load": set(),
        "run": set(),
    }
    WINLOGON_KEYS = {"shell", "userinit", "load", "run"}

    def is_winlogon_style(sk: str) -> bool:
        return sk.endswith(("Winlogon", r"NT\CurrentVersion\Windows"))

    entries: list[str] = []
    flagged: list[str] = []
    seen: set[str] = set()
    for hive, subkey in targets:
        label = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
        for view_name, view_flag in views:
            # HKCU is not redirected, so only enumerate it once.
            if hive == winreg.HKEY_CURRENT_USER and view_name == "32":
                continue
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view_flag)
            except OSError:
                continue
            with key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    if not isinstance(value, str) or not value.strip():
                        continue
                    lname = str(name).strip().lower()
                    if is_winlogon_style(subkey):
                        # Only the handful of load-point values matter here.
                        if lname not in WINLOGON_KEYS:
                            continue
                        if value.strip().lower() in WINLOGON_DEFAULTS.get(lname, set()):
                            continue
                    shown = subkey if view_name == "64" else f"{subkey} [Wow6432Node]"
                    line = f"{label}\\{shown} :: {name} = {value}"
                    dedupe = f"{label}|{subkey}|{name}|{value}".lower()
                    if dedupe in seen:
                        continue
                    seen.add(dedupe)
                    entries.append(line)
                    v = str(value).lower()
                    if is_winlogon_style(subkey) or any(t in v for t in (
                            "powershell", "-enc", "frombase64string", "mshta",
                            "rundll32 javascript", "certutil", "wscript",
                            r"\appdata\local\temp", r"\appdata\roaming\temp")):
                        flagged.append(line)

    out: list[dict] = []
    if flagged:
        out.append({
            "kind": "suspicious_run_key",
            "severity": "high",
            "title": f"{len(flagged)} autostart registry entr(y/ies) look suspicious",
            "detail": "Autostart entries that invoke a script host, decode base64, "
                      "or launch from a temp folder are a common persistence trick.",
            "examples": flagged[:8],
            "count": len(flagged),
        })
    if entries:
        out.append({
            "kind": "run_key_inventory",
            "severity": "info",
            "title": f"{len(entries)} total autostart registry entries",
            "detail": "Full inventory for your review — most of these are legitimate.",
            "examples": entries[:25],
            "count": len(entries),
        })
    return out
