"""Shared test helpers: hermetic environment redirection and a PE32+ writer.

Nothing in here touches the real ~/.sentry (or %LOCALAPPDATA%\\Sentry) tree and
nothing performs network I/O.
"""
from __future__ import annotations

import ntpath
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

from sentry import config, feeds

# --------------------------------------------------------------------------
# OS file-manager launch stub
# --------------------------------------------------------------------------


@contextmanager
def stub_launchers(*, popen_side_effect=None, startfile_side_effect=None):
    """Block every path by which /api/open-folder can reach a real launcher.

    The handler picks its launcher three ways: `subprocess.Popen` with an
    explorer.exe command line (Windows, file), `os.startfile` (Windows,
    directory), and `subprocess.Popen(["xdg-open", ...])` (POSIX). A test that
    stubs only `subprocess.Popen` therefore still calls `os.startfile` for
    real when the suite runs on Windows -- which opened an Explorer window on
    a temp directory that `tearDown` then deleted, producing a "Location is
    not available" dialog and failing the assertion as well.

    `os.startfile` does not exist on POSIX, hence `create=True`.
    """
    with mock.patch("subprocess.Popen", side_effect=popen_side_effect) as popen, \
            mock.patch("os.startfile", create=True,
                       side_effect=startfile_side_effect) as startfile:
        yield SimpleNamespace(popen=popen, startfile=startfile)


# --------------------------------------------------------------------------
# hermetic environment
# --------------------------------------------------------------------------

# Every module-level name in `config` that points somewhere on disk. If a new
# one is added to config.py and not listed here, `test_config.py` fails loudly.
CONFIG_PATH_ATTRS = (
    "DATA_ROOT", "DB_PATH", "QUARANTINE_DIR", "REPORTS_DIR", "RULES_DIR",
    "FEED_DIR", "CONFIG_PATH", "LOG_PATH",
)


class TempEnvMixin:
    """Redirects all Sentry on-disk state into a throwaway directory.

    `feeds.HASH_DB` / `feeds.USER_HASH_DB` are bound at *import* time from
    `config.FEED_DIR`, so rebinding `config.FEED_DIR` alone is not enough --
    they have to be patched separately (see the design notes in the report).
    """

    def setUp(self) -> None:  # noqa: N802
        super().setUp()
        self.data_root = Path(tempfile.mkdtemp(prefix="sentry_ut_data_"))
        self.sandbox = Path(tempfile.mkdtemp(prefix="sentry_ut_box_"))
        self.addCleanup(shutil.rmtree, self.data_root, ignore_errors=True)
        self.addCleanup(shutil.rmtree, self.sandbox, ignore_errors=True)

        self._saved_config = {a: getattr(config, a) for a in CONFIG_PATH_ATTRS}
        self._saved_feeds = (feeds.HASH_DB, feeds.USER_HASH_DB)

        config.DATA_ROOT = self.data_root
        config.DB_PATH = self.data_root / "sentry.db"
        config.QUARANTINE_DIR = self.data_root / "quarantine"
        config.REPORTS_DIR = self.data_root / "reports"
        config.RULES_DIR = self.data_root / "rules"
        config.FEED_DIR = self.data_root / "feeds"
        config.CONFIG_PATH = self.data_root / "config.json"
        config.LOG_PATH = self.data_root / "sentry.log"
        feeds.HASH_DB = config.FEED_DIR / "known_bad.csv"
        feeds.USER_HASH_DB = config.FEED_DIR / "custom_bad_hashes.txt"

        config.ensure_dirs()

    def tearDown(self) -> None:  # noqa: N802
        for attr, value in self._saved_config.items():
            setattr(config, attr, value)
        feeds.HASH_DB, feeds.USER_HASH_DB = self._saved_feeds
        super().tearDown()

    # -- convenience ------------------------------------------------------

    def offline_cfg(self, **overrides) -> dict:
        """A config dict that never reaches the network and never uses YARA."""
        cfg = dict(config.DEFAULTS)
        cfg.update({"use_hash_feed": False, "use_yara": False,
                    "exclusions": [], "enabled_presets": [],
                    "custom_paths": [], "report_threshold": 25})
        cfg.update(overrides)
        return cfg

    def write(self, relpath: str, data: bytes | str) -> Path:
        p = self.sandbox / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            p.write_text(data, encoding="utf-8")
        else:
            p.write_bytes(data)
        return p


import subprocess as _subprocess

_REAL_POPEN = _subprocess.Popen


def _run_unstubbed(args: list[str]):
    """subprocess.run with the *real* Popen, even inside stub_launchers().

    Several web-UI test classes stub subprocess.Popen for their whole lifetime
    (so /api/open-folder can never launch Explorer). subprocess.run() looks
    Popen up on the module at call time, so an icacls call made for test
    set-up would otherwise hit the stub and die inside communicate().
    """
    with mock.patch.object(_subprocess, "Popen", _REAL_POPEN):
        return _subprocess.run(args, capture_output=True, check=False,
                               timeout=30)


def deny_directory_listing(path):
    """Make `path` unlistable for the current user; returns an undo callable.

    POSIX: chmod 000. Windows: os.chmod only toggles the read-only attribute,
    which has no effect on reading, so tests that used it (and then probed with
    os.access, which on Windows only ever reflects that attribute) skipped
    themselves as "running as root" on every Windows machine. Here a deny ACE
    for the Everyone SID on the list-directory right (RD) is applied with
    icacls instead. Deny ACEs are evaluated before allows, so it beats the
    owner's own inherited grant. Only RD is denied, not generic read: os.stat
    still needs FILE_READ_ATTRIBUTES so that os.path.isdir() keeps working and
    the failure lands in scandir(), which is the code path under test.
    """
    p = str(path)
    if config.IS_WINDOWS:
        _run_unstubbed(["icacls", p, "/deny", "*S-1-1-0:(RD)"])

        def undo():
            _run_unstubbed(["icacls", p, "/remove:d", "*S-1-1-0"])
    else:
        os.chmod(p, 0o000)

        def undo():
            os.chmod(p, 0o755)
    return undo


def is_listable(path) -> bool:
    """True if the current process can enumerate `path` right now.

    os.access(path, os.R_OK) is not usable for this on Windows: it returns
    True for anything that exists. An actual listing attempt is the only
    honest probe, on both platforms.
    """
    try:
        os.listdir(path)
        return True
    except PermissionError:
        return False


class FakeNtOs:
    """Stand-in for the `os` module that behaves like Windows' os.path.

    `config._is_within` and `engine._is_excluded` read `os.path.*` and `os.sep`
    off the module global, so patching this object over `<module>.os` is enough
    to exercise the Windows path semantics from Linux.
    """

    path = ntpath
    sep = "\\"
    altsep = "/"

    def __getattr__(self, name):  # everything else falls through to real os
        return getattr(os, name)


# --------------------------------------------------------------------------
# score / reason helpers
# --------------------------------------------------------------------------

def total(hits) -> int:
    return sum(d for d, _ in hits)


def reasons(hits) -> list[str]:
    return [r for _, r in hits]


def has_reason(hits, needle: str) -> bool:
    return any(needle.lower() in r.lower() for _, r in hits)


def delta_for(hits, needle: str) -> int | None:
    """Score delta of the first reason containing `needle`, or None."""
    for d, r in hits:
        if needle.lower() in r.lower():
            return d
    return None


# --------------------------------------------------------------------------
# minimal PE32+ writer
# --------------------------------------------------------------------------

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
HEADER_SIZE = 0x400

# IMAGE_SCN_* section characteristics
SCN_CODE = 0x00000020
SCN_INITIALIZED_DATA = 0x00000040
SCN_UNINITIALIZED_DATA = 0x00000080
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

TEXT_CHARS = SCN_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ
DATA_CHARS = SCN_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE
RDATA_CHARS = SCN_INITIALIZED_DATA | SCN_MEM_READ
WX_CHARS = SCN_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ | SCN_MEM_WRITE

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE = 0, 1, 2
DIR_SECURITY, DIR_TLS = 4, 9

# Machine types
MACHINE_AMD64 = 0x8664
MACHINE_I386 = 0x14C

DOS_STUB = (
    b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd!\xb8\x01L\xcd!"
    b"This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00"
)


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _import_blob(imports: dict[str, list[str]], base_rva: int) -> bytes:
    """Build a complete IMAGE_IMPORT_DESCRIPTOR block for PE32+."""
    dlls = list(imports.items())
    off = 20 * (len(dlls) + 1)          # descriptor array + null terminator
    layout = []
    for _dll, funcs in dlls:
        oft = off
        off += 8 * (len(funcs) + 1)
        ft = off
        off += 8 * (len(funcs) + 1)
        layout.append({"oft": oft, "ft": ft})

    strings = bytearray()
    strings_off = off                    # 4-byte aligned by construction
    for i, (dll, funcs) in enumerate(dlls):
        layout[i]["name"] = strings_off + len(strings)
        strings += dll.encode() + b"\x00"
        if len(strings) % 2:
            strings += b"\x00"
        hints = []
        for fn in funcs:
            hints.append(strings_off + len(strings))
            strings += struct.pack("<H", 0) + fn.encode() + b"\x00"
            if len(strings) % 2:
                strings += b"\x00"
        layout[i]["hints"] = hints

    buf = bytearray(strings_off + len(strings))
    for i, (_dll, _funcs) in enumerate(dlls):
        lay = layout[i]
        struct.pack_into("<IIIII", buf, 20 * i,
                         base_rva + lay["oft"], 0, 0,
                         base_rva + lay["name"], base_rva + lay["ft"])
        for j, hint in enumerate(lay["hints"]):
            struct.pack_into("<Q", buf, lay["oft"] + 8 * j, base_rva + hint)
            struct.pack_into("<Q", buf, lay["ft"] + 8 * j, base_rva + hint)
    buf[strings_off:strings_off + len(strings)] = strings
    return bytes(buf)


class PEBuilder:
    """Hand-rolled, structurally valid PE32+ (or PE32) image builder.

    Only the parts `heuristics.analyse_pe` inspects are modelled, but those are
    modelled *correctly*, so pefile parses the result without warnings that
    would short-circuit analysis.
    """

    def __init__(self, *, machine: int = MACHINE_AMD64,
                 timestamp: int = 0x5F5E1000, dll: bool = False,
                 subsystem: int = 3, plus: bool = True):
        self.machine = machine
        self.timestamp = timestamp
        self.dll = dll
        self.subsystem = subsystem
        self.plus = plus
        self.sections: list[dict] = []
        self.imports: dict[str, list[str]] | None = None
        self.entry_point: int | None = None
        self.entry_section: int | None = None
        self.signed = False
        self.tls = False
        self.tls_callbacks = True
        self.resource_pe: bytes | None = None
        self.dotnet = False

    # -- fluent builders --------------------------------------------------

    def add_section(self, name: str, data: bytes = b"",
                    characteristics: int = RDATA_CHARS, *,
                    virtual_size: int | None = None,
                    raw_size: int | None = None) -> "PEBuilder":
        self.sections.append({
            "name": name,
            "data": data,
            "chars": characteristics,
            "vsize": len(data) if virtual_size is None else virtual_size,
            "raw_override": raw_size,
        })
        return self

    def add_text(self, size: int = 0x400) -> "PEBuilder":
        return self.add_section(".text", b"\x90" * size, TEXT_CHARS)

    def add_imports(self, imports: dict[str, list[str]]) -> "PEBuilder":
        self.imports = imports
        return self

    def set_entry_point(self, rva: int) -> "PEBuilder":
        self.entry_point = rva
        return self

    def set_entry_in_section(self, index: int) -> "PEBuilder":
        """Place the entry point 16 bytes into section `index`."""
        self.entry_section = index
        return self

    def sign(self, signed: bool = True) -> "PEBuilder":
        self.signed = signed
        return self

    def mark_dotnet(self) -> "PEBuilder":
        """Give the image a CLR runtime header (a managed .NET assembly)."""
        self.dotnet = True
        return self

    def add_tls(self, present: bool = True, callbacks: bool = True) -> "PEBuilder":
        """Add a TLS directory.

        `callbacks=False` gives the bare directory a plain C++ binary using
        thread_local gets (AddressOfCallBacks == 0); the default registers one
        real callback, which is what the detection rule looks for.
        """
        self.tls = present
        self.tls_callbacks = callbacks
        return self

    # -- output -----------------------------------------------------------

    def build(self) -> bytes:
        secs = [dict(s) for s in self.sections]
        if not secs:
            secs.append({"name": ".text", "data": b"\x90" * 0x200,
                         "chars": TEXT_CHARS, "vsize": 0x200,
                         "raw_override": None})

        # Virtual addresses first: the import blob needs to know its own RVA.
        va = SECT_ALIGN
        for s in secs:
            s["va"] = va
            va = _align(va + max(s["vsize"], 1), SECT_ALIGN)

        import_dir = (0, 0)
        if self.imports is not None:
            blob = _import_blob(self.imports, va)
            secs.append({"name": ".idata", "data": blob, "chars": RDATA_CHARS,
                         "vsize": len(blob), "raw_override": None, "va": va})
            import_dir = (va, len(blob))
            va = _align(va + len(blob), SECT_ALIGN)

        tls_dir = (0, 0)
        if self.tls:
            image_base = 0x140000000 if self.plus else 0x400000
            if getattr(self, "tls_callbacks", True):
                # A real callback array immediately after the directory: one
                # non-null entry, then the null terminator.
                if self.plus:
                    tls_blob = struct.pack("<QQQQII", 0, 0, 0,
                                           image_base + va + 40, 0, 0)
                    tls_blob += struct.pack("<QQ", image_base + secs[0]["va"], 0)
                else:
                    tls_blob = struct.pack("<IIIIII", 0, 0, 0,
                                           image_base + va + 24, 0, 0)
                    tls_blob += struct.pack("<II", image_base + secs[0]["va"], 0)
            elif self.plus:
                tls_blob = struct.pack("<QQQQII", 0, 0, 0, 0, 0, 0)
            else:
                tls_blob = struct.pack("<IIIIII", 0, 0, 0, 0, 0, 0)
            secs.append({"name": ".tls", "data": tls_blob, "chars": RDATA_CHARS,
                         "vsize": len(tls_blob), "raw_override": None, "va": va})
            tls_dir = (va, len(tls_blob))
            va = _align(va + len(tls_blob), SECT_ALIGN)

        size_of_image = va

        # Raw file offsets.
        ptr = HEADER_SIZE
        for s in secs:
            if s["raw_override"] is not None:
                s["raw"] = s["raw_override"]
                s["ptr"] = ptr if s["raw"] else 0
            else:
                s["raw"] = _align(len(s["data"]), FILE_ALIGN)
                s["ptr"] = ptr if s["raw"] else 0
            ptr += s["raw"]
        end_of_sections = ptr

        # Entry point.
        if self.entry_point is not None:
            ep = self.entry_point
        elif self.entry_section is not None:
            ep = secs[self.entry_section]["va"] + 16
        else:
            ep = next((s["va"] for s in secs if s["chars"] & SCN_MEM_EXECUTE),
                      secs[0]["va"])

        cert_dir = (0, 0)
        if self.signed:
            cert_dir = (end_of_sections, 0x100)   # security dir is a raw offset

        opt_size = 240 if self.plus else 224
        nsec = len(secs)

        # ---- DOS header
        out = bytearray()
        out += b"MZ" + struct.pack("<13H", 0x90, 0, 3, 0, 4, 0, 0xFFFF, 0,
                                   0xB8, 0, 0, 0, 0x40)
        out += b"\x00" * (0x3C - len(out))
        out += struct.pack("<I", 0x80)
        out += DOS_STUB
        out += b"\x00" * (0x80 - len(out))
        assert len(out) == 0x80

        # ---- PE signature + file header
        chars = 0x0022 | (0x2000 if self.dll else 0)   # EXECUTABLE_IMAGE|LARGE_ADDR
        out += b"PE\x00\x00"
        out += struct.pack("<HHIIIHH", self.machine, nsec, self.timestamp,
                           0, 0, opt_size, chars)

        # ---- optional header
        code_size = sum(s["raw"] for s in secs if s["chars"] & SCN_CODE)
        init_size = sum(s["raw"] for s in secs
                        if s["chars"] & SCN_INITIALIZED_DATA)
        base_of_code = next((s["va"] for s in secs if s["chars"] & SCN_CODE),
                            SECT_ALIGN)
        opt = bytearray()
        opt += struct.pack("<HBB", 0x20B if self.plus else 0x10B, 14, 0)
        opt += struct.pack("<III", code_size, init_size, 0)
        opt += struct.pack("<II", ep, base_of_code)
        if self.plus:
            opt += struct.pack("<Q", 0x140000000)
        else:
            opt += struct.pack("<II", base_of_code, 0x400000)
        opt += struct.pack("<II", SECT_ALIGN, FILE_ALIGN)
        opt += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)
        opt += struct.pack("<III", 0, size_of_image, HEADER_SIZE)
        opt += struct.pack("<I", 0)                       # CheckSum
        opt += struct.pack("<HH", self.subsystem, 0x120)
        if self.plus:
            opt += struct.pack("<QQQQ", 0x100000, 0x1000, 0x100000, 0x1000)
        else:
            opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
        opt += struct.pack("<II", 0, 16)                  # LoaderFlags, NumRva

        dirs = [(0, 0)] * 16
        dirs[DIR_IMPORT] = import_dir
        dirs[DIR_SECURITY] = cert_dir
        dirs[DIR_TLS] = tls_dir
        if self.dotnet:
            dirs[14] = (secs[0]["va"], 72)   # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
        for rva, size in dirs:
            opt += struct.pack("<II", rva, size)
        assert len(opt) == opt_size, (len(opt), opt_size)
        out += opt

        # ---- section table
        for s in secs:
            nm = s["name"].encode()[:8]
            out += nm + b"\x00" * (8 - len(nm))
            out += struct.pack("<IIII", s["vsize"], s["va"], s["raw"], s["ptr"])
            out += struct.pack("<IIHH", 0, 0, 0, 0)
            out += struct.pack("<I", s["chars"])

        assert len(out) <= HEADER_SIZE, f"too many sections for {HEADER_SIZE:#x}"
        out += b"\x00" * (HEADER_SIZE - len(out))

        # ---- section bodies
        for s in secs:
            if not s["raw"]:
                continue
            body = s["data"][:s["raw"]]
            out += body + b"\x00" * (s["raw"] - len(body))

        if self.signed:
            out += b"\x00" * 0x100
        return bytes(out)

    def write(self, path: str | os.PathLike) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(self.build())
        return p


def benign_pe(**kwargs) -> PEBuilder:
    """A boring, signed, well-imported PE that should trigger almost nothing."""
    return (PEBuilder(**kwargs)
            .add_text(0x600)
            .add_section(".rdata", b"config data\x00" * 40, RDATA_CHARS)
            .add_section(".data", b"\x00" * 0x200, DATA_CHARS)
            .add_imports({"kernel32.dll": ["CreateFileW", "ReadFile",
                                           "WriteFile", "CloseHandle",
                                           "GetLastError", "ExitProcess"],
                          "user32.dll": ["MessageBoxW", "LoadStringW"]})
            .set_entry_in_section(0)
            .sign())


ASCII_TEXT = (b"The quick brown fox jumps over the lazy dog. "
              b"Sentry is a local heuristic file scanner.\n") * 60

UNIFORM_BYTES = bytes(range(256)) * 40
