"""Configuration and platform paths for Sentry."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

IS_WINDOWS = sys.platform.startswith("win")


def _data_root() -> Path:
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return Path(base) / "Sentry"
    return Path(os.path.expanduser("~")) / ".sentry"


DATA_ROOT = _data_root()
DB_PATH = DATA_ROOT / "sentry.db"
QUARANTINE_DIR = DATA_ROOT / "quarantine"
REPORTS_DIR = DATA_ROOT / "reports"
RULES_DIR = DATA_ROOT / "rules"
FEED_DIR = DATA_ROOT / "feeds"
CONFIG_PATH = DATA_ROOT / "config.json"
LOG_PATH = DATA_ROOT / "sentry.log"

# Executable / script types we inspect closely.
BINARY_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".efi", ".msi"}
SCRIPT_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
              ".wsf", ".wsh", ".hta", ".sh", ".py", ".lnk", ".reg", ".jar"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xls", ".doc", ".ppt"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".gz", ".tar"}

# Extensions that are almost never worth hashing during a broad sweep.
SKIP_EXT = {".mp4", ".mkv", ".avi", ".mov", ".mp3", ".flac", ".wav", ".psd",
            ".raw", ".cr2", ".nef", ".vmdk", ".vhd", ".vhdx", ".wim", ".esd"}


_UNEXPANDED_VAR = re.compile(r"%[A-Za-z_][A-Za-z0-9_()#$'+,.\-]*%")


def _expand(p: str) -> str:
    return os.path.expandvars(os.path.expanduser(p))


def has_unexpanded_var(p: str) -> bool:
    """True when `%FOO%` survived expansion, i.e. the variable is not set.

    os.path.expandvars() leaves the literal text in place for unset variables,
    and a literal '%TEMP%' must never reach the scanner as a path.
    """
    return bool(IS_WINDOWS and _UNEXPANDED_VAR.search(p))


def _win_temp(localapp: str) -> str:
    """Resolve the user temp dir without ever returning a literal '%TEMP%'."""
    for var in ("TEMP", "TMP"):
        v = os.environ.get(var)
        if v:
            return v
    return os.path.join(localapp, "Temp") if localapp else ""


def _all_users_startup() -> str:
    pd = os.environ.get("ProgramData") or os.environ.get("ALLUSERSPROFILE") or ""
    if not pd:
        return ""
    return os.path.join(pd, r"Microsoft\Windows\Start Menu\Programs\StartUp")


def startup_dirs() -> list[str]:
    """Directories whose contents run automatically at logon."""
    if not IS_WINDOWS:
        return [os.path.join(os.path.expanduser("~"), ".config", "autostart")]
    appdata = os.environ.get("APPDATA", "")
    out = []
    if appdata:
        out.append(os.path.join(
            appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"))
    au = _all_users_startup()
    if au:
        out.append(au)
    return out


def preset_paths() -> dict[str, list[str]]:
    """Named scan-scope presets, resolved for the current platform."""
    if IS_WINDOWS:
        up = os.environ.get("USERPROFILE", os.path.expanduser("~"))
        localapp = os.environ.get("LOCALAPPDATA", "")
        windir = os.environ.get("WINDIR") or os.environ.get("SystemRoot") or r"C:\Windows"
        presets = {
            "high_risk": [
                os.path.join(up, "Downloads"),
                os.path.join(up, "Desktop"),
                os.path.join(up, "Documents"),
                _win_temp(localapp),
            ],
            "persistence": startup_dirs() + [
                os.path.join(localapp, "Temp") if localapp else "",
                os.path.join(windir, "Temp"),
                os.path.join(windir, "Tasks"),
            ],
            "user_profile": [up],
            "whole_drive": [os.environ.get("SystemDrive", "C:") + "\\"],
        }
    else:
        home = os.path.expanduser("~")
        presets = {
            "high_risk": [f"{home}/Downloads", f"{home}/Desktop",
                          f"{home}/Documents", "/tmp"],
            "persistence": [f"{home}/.config/autostart", "/etc/cron.d",
                            f"{home}/.local/share/systemd/user", "/var/tmp"],
            "user_profile": [home],
            "whole_drive": ["/"],
        }
    return {k: [p for p in v if p and not has_unexpanded_var(p)]
            for k, v in presets.items()}


PRESET_LABELS = {
    "high_risk": "Downloads, Desktop, Documents, Temp",
    "persistence": "Startup & persistence locations",
    "user_profile": "Entire user profile",
    "whole_drive": "Whole drive (slow)",
}

DEFAULT_EXCLUSIONS_WIN = [
    r"%SystemRoot%\WinSxS",
    r"%SystemRoot%\servicing",
    r"%SystemRoot%\Installer",
    r"%SystemRoot%\SoftwareDistribution",
    r"%SystemDrive%\$Recycle.Bin",
    r"%SystemDrive%\System Volume Information",
    r"%ProgramData%\Microsoft\Windows Defender",
    r"%SystemDrive%\hiberfil.sys",
    r"%SystemDrive%\pagefile.sys",
    r"%SystemDrive%\swapfile.sys",
]

# Directory *names* that are skipped on every drive, not just C:. A whole-drive
# or D:\ scan otherwise walks into D:\System Volume Information (access denied
# on every entry) and D:\$Recycle.Bin.
EXCLUDED_DIR_NAMES_WIN = {
    "$recycle.bin", "system volume information", "$windows.~bt",
    "$windows.~ws", "$sysreset", "recovery", "config.msi",
}

# --------------------------------------------------------------------------
# protected application locations
# --------------------------------------------------------------------------
#
# Games and their protection layers are, structurally, indistinguishable from
# malware. Anti-cheat drivers (EasyAntiCheat, BattlEye, Vanguard) and DRM
# (Denuvo, VMProtect, Themida) are *deliberately* packed, high-entropy,
# obfuscated, and use exactly the process-injection and anti-debug APIs the
# heuristics look for -- because their job is to resist tampering. A structural
# scanner will light up on them every single time.
#
# Two protections, both needed and doing different jobs:
#
#   1. Findings inside these folders have their STRUCTURE-ONLY score damped
#      (see engine.damp_protected). Strong signals -- a known-bad hash, a YARA
#      malware match, an executable wearing a .txt extension -- are NOT damped,
#      because a genuinely trojaned game file must still surface.
#
#   2. Quarantine REFUSES these paths outright. Moving a file out of a game
#      install does not neutralise a threat you were unsure about; it breaks
#      the game, often in a way that is hard to connect back to this tool. The
#      correct repair for a bad file in a game is the launcher's own "verify
#      integrity of game files", which re-downloads it.
#
# Matching is on path segments, so it works for any install location and any
# drive letter -- D:\SteamLibrary\steamapps\... matches just as well as the
# default under Program Files.

PROTECTED_SEGMENTS = {
    # storefronts and launchers
    "steamapps", "steamlibrary", "steam", "epic games", "epicgameslauncher",
    "gog galaxy", "gog games", "gogcom", "origin games", "ea games",
    "ea desktop", "electronic arts", "ubisoft", "ubisoft game launcher",
    "battle.net", "blizzard entertainment", "riot games", "rockstar games",
    "bethesda.net launcher", "xboxgames", "windowsapps", "amazon games",
    "itch", "minecraft", "curseforge", "overwolf", "modrinth",
    # A plain "Games" folder (D:\Games\<title>\...) is where installers and
    # repacks that are not tied to a storefront land. Added after a real D:
    # scan put a game executable and its steam_api DLLs at high/medium from
    # structure alone. Trade-off, stated plainly: a cracked steam_api.dll's
    # packer signals are damped here too, so a strong signal (bad hash, YARA,
    # extension mismatch) is what must surface a genuinely trojaned repack.
    "games",
    # anti-cheat and DRM, the loudest false positives of all
    "easyanticheat", "easyanticheat_eos", "battleye", "vanguard",
    "punkbuster", "denuvo", "nprotect", "xigncode3", "faceit",
    "anticheatexpert", "ricochet",
    # engines and runtimes shipped inside games
    "unrealengine", "ue4prereqisitesetup", "unitycrashhandler",
    "monobleedingedge", "_commonredist", "directx", "vc_redist",
    "steamworks shared", "dotnet", "oalinst",
    # general application installs
    "program files", "program files (x86)", "programdata",
    "windowsapps", "packagecache", "nvidia corporation", "amd", "intel",
    # developer trees full of scripts that legitimately look scary
    "node_modules", "site-packages", "dist-packages", ".venv", "venv",
    ".git", ".cargo", ".rustup", ".nuget", ".gradle", ".m2",
}

# Launcher and anti-cheat binaries. These names are deliberately NOT treated as
# protected on their own: protecting by filename alone would mean malware that
# names itself EasyAntiCheat.exe and drops into Downloads could never be
# quarantined. Every real install of these lives under a directory that
# PROTECTED_SEGMENTS already covers, so the name adds no coverage there.
#
# The list earns its place the other way round -- one of these names OUTSIDE any
# protected directory is a masquerade, which `heuristics.check_filename` scores.
LAUNCHER_FILENAMES = {
    "easyanticheat.sys", "easyanticheat.exe", "easyanticheat_eos.sys",
    "beservice.exe", "bedaisy.sys", "battleye.exe", "vgk.sys", "vgc.exe",
    "steam.exe", "steamservice.exe", "steamwebhelper.exe", "gameoverlayui.exe",
    "epicgameslauncher.exe", "eosoverlayrenderhelper.exe",
    "galaxyclient.exe", "riotclientservices.exe", "vgtray.exe",
}


def path_segments(path: str) -> list[str]:
    """Lowercased path components, splitting on BOTH separators.

    os.path is host-dependent: on POSIX it does not treat "\\" as a separator,
    so a Windows path collapses to a single component and every per-segment or
    filename check silently stops working. This tool targets Windows but is
    developed and tested on Linux, so path logic has to be host-independent.
    """
    return [s.strip().lower()
            for s in re.split(r"[\\/]+", strip_long_prefix(str(path or "")))
            if s.strip()]


def basename_any(path: str) -> str:
    """The final component of a path, whichever separator style it uses."""
    segs = path_segments(path)
    return segs[-1] if segs else ""


def protected_reason(path: str) -> str | None:
    """Return the marker that makes `path` a protected application location.

    None means the path is ordinary and gets no special treatment.
    """
    if not path:
        return None
    segments = path_segments(path)
    if not segments:
        return None

    # The filename itself is not a directory segment.
    for seg in (segments[:-1] if len(segments) > 1 else segments):
        if seg in PROTECTED_SEGMENTS:
            return f"inside a protected application folder ({seg})"
    return None


def is_protected(path: str) -> bool:
    return protected_reason(path) is not None

# NTFS reparse tags that must never be walked into: name surrogates that point
# back into the tree (the legacy AppData junctions loop), and cloud-provider
# tags whose content is not local.
REPARSE_TAG_MOUNT_POINT = 0xA0000003  # junction
REPARSE_TAG_SYMLINK = 0xA000000C
NAME_SURROGATE_TAGS = {REPARSE_TAG_MOUNT_POINT, REPARSE_TAG_SYMLINK}

# FILE_ATTRIBUTE_* bits that mean "reading this will pull bytes over the network".
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
DEHYDRATED_MASK = (FILE_ATTRIBUTE_OFFLINE
                   | FILE_ATTRIBUTE_RECALL_ON_OPEN
                   | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)


def is_dehydrated(st) -> bool:
    """True for an OneDrive/cloud placeholder whose bytes are not on disk.

    Opening one of these triggers a silent hydration download, which on a
    whole-drive scan can mean gigabytes of traffic and a full disk. We refuse
    to read them at all.
    """
    if not IS_WINDOWS:
        return False
    attrs = getattr(st, "st_file_attributes", 0) or 0
    return bool(attrs & DEHYDRATED_MASK)


def excluded_dir_name(name: str) -> bool:
    return IS_WINDOWS and name.lower() in EXCLUDED_DIR_NAMES_WIN


LONG_PATH_PREFIX = "\\\\?\\"
_LONG_PATH_THRESHOLD = 240


def long_path(p: str, *, always: bool = False) -> str:
    """Return `p` in a form the Win32 API accepts for paths beyond MAX_PATH.

    Without the \\\\?\\ prefix, os.stat/open/shutil.move on a path longer than
    260 characters fail with ENOENT unless the machine has LongPathsEnabled set
    AND the interpreter is manifest-declared long-path aware. Applying the
    prefix at the syscall boundary works regardless of both.

    `always=True` prefixes even a short absolute path. os.walk() builds every
    child path from the root it was given, so a *directory walk* has to start
    prefixed no matter how short the root is -- otherwise the first directory
    past 260 characters fails inside scandir(), onerror swallows it, and the
    whole subtree silently disappears from the scan. (Observed on Windows with
    LongPathsEnabled=0: a 316-character decoy scanned as "0 files, clean".)
    """
    if not IS_WINDOWS or not p:
        return p
    if not always and len(p) < _LONG_PATH_THRESHOLD:
        return p
    if p.startswith(LONG_PATH_PREFIX) or p.startswith("\\\\.\\"):
        return p
    if p.startswith("\\\\"):  # UNC  ->  \\?\UNC\server\share
        return LONG_PATH_PREFIX + "UNC" + p[1:]
    if not os.path.isabs(p):
        return p
    # The prefix disables all normalisation, so normalise first.
    return LONG_PATH_PREFIX + os.path.normpath(p)


def strip_long_prefix(p: str) -> str:
    if p.startswith(LONG_PATH_PREFIX + "UNC\\"):
        return "\\\\" + p[len(LONG_PATH_PREFIX) + 4:]
    if p.startswith(LONG_PATH_PREFIX):
        return p[len(LONG_PATH_PREFIX):]
    return p

DEFAULT_EXCLUSIONS_NIX = ["/proc", "/sys", "/dev", "/run", "/snap",
                          "/var/lib/docker", "/usr/lib/modules"]


def install_dir() -> str:
    """The directory Sentry itself is installed in (the parent of the package).

    This is excluded by default. Sentry's own test suite deliberately contains
    the exact strings the script heuristics look for -- `vssadmin delete
    shadows`, `certutil -urlcache`, `Add-MpPreference`, base64 blobs -- as test
    fixtures. Scanning the drive Sentry lives on therefore flags Sentry's own
    source, which is noise that teaches you to ignore real findings.

    It is listed in the default exclusions for visibility, but the scanner
    also prunes it on its own (engine.iter_candidate_files) unless the config
    sets `scan_self: true`. Relying on the exclusions list alone was not
    enough: a config.json saved by an earlier build, or by the dashboard's
    exclusions editor, carries its own list and silently drops this entry --
    which is exactly what put seven of Sentry's own files, four at *high*
    severity, into a real weekly report.
    """
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


DEFAULTS: dict = {
    # Which presets are enabled for the scheduled weekly run.
    "enabled_presets": ["high_risk", "persistence"],
    # Extra folders the user picked in the UI.
    "custom_paths": [],
    "exclusions": (DEFAULT_EXCLUSIONS_WIN if IS_WINDOWS
                   else DEFAULT_EXCLUSIONS_NIX) + [install_dir()],
    # Minimum score to surface a finding. Lower = noisier.
    "report_threshold": 25,
    "max_file_mb": 128,
    "follow_symlinks": False,
    # Scan Sentry's own install folder (its test fixtures are full of the
    # strings the script rules look for). Off unless you really want that.
    "scan_self": False,
    "use_yara": True,
    "use_hash_feed": True,
    "feed_max_age_days": 7,
    # Never auto-acts. Present so the setting is explicit and auditable.
    "auto_quarantine": False,
    "notify_on_scheduled_scan": True,
    "web_port": 8787,
}


def ensure_dirs() -> None:
    for d in (DATA_ROOT, QUARANTINE_DIR, REPORTS_DIR, RULES_DIR, FEED_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    ensure_dirs()
    cfg = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            pass
    return cfg


def save_config(cfg: dict) -> None:
    ensure_dirs()
    merged = load_config()
    merged.update(cfg)
    CONFIG_PATH.write_text(json.dumps(merged, indent=2), encoding="utf-8")


def resolved_scan_paths(cfg: dict | None = None) -> list[str]:
    """Expand enabled presets + custom paths into a deduplicated path list."""
    # Only None means "use the saved config". An explicitly-passed empty dict is
    # a caller asking for an empty scope and must be honoured.
    cfg = load_config() if cfg is None else cfg
    presets = preset_paths()
    out: list[str] = []
    for name in cfg.get("enabled_presets", []):
        out.extend(presets.get(name, []))
    out.extend(_expand(p) for p in cfg.get("custom_paths", []))

    seen, uniq = set(), []
    for p in out:
        # An unset %VAR% survives expandvars as literal text; abspath() would
        # then silently turn it into a cwd-relative path. Drop it outright.
        if not p or has_unexpanded_var(p):
            continue
        norm = os.path.normpath(os.path.abspath(p))
        key = norm.lower() if IS_WINDOWS else norm
        if key not in seen and os.path.exists(long_path(norm)):
            seen.add(key)
            uniq.append(norm)
    # Drop paths already covered by a broader parent.
    uniq.sort(key=len)
    pruned: list[str] = []
    for p in uniq:
        if not any(_is_within(p, parent) for parent in pruned):
            pruned.append(p)
    return pruned


def _is_within(child: str, parent: str) -> bool:
    c = os.path.normcase(os.path.normpath(child))
    p = os.path.normcase(os.path.normpath(parent))
    return c == p or c.startswith(p.rstrip(os.sep) + os.sep)
