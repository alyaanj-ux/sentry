"""Static heuristics: entropy, PE structure analysis, filename tricks, script obfuscation.

Each check returns (score_delta, reason) pairs. Scores are additive and capped.
Nothing here is authoritative — the point is to rank files for human review,
which is why the tool never acts on a score by itself.
"""
from __future__ import annotations

import math
import os
import re
from collections import Counter
from pathlib import Path

from . import config

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:  # pragma: no cover
    HAVE_PEFILE = False


# Import-name groups that are individually normal but suspicious in combination.
#
# Membership is deliberately conservative: an API only belongs to a group if it
# is rare in legitimate software.  Measured over 426 genuine Windows PE files
# (MSVC/mingw-built .pyd/.dll from PyPI win_amd64 wheels), the APIs removed
# below were present in 3%-74% of clean binaries, which made every group they
# belonged to fire constantly:
#   queryperformancecounter 316/426, isdebuggerpresent 281/426,
#   outputdebugstringa 49/426, openprocess 46/426, setthreadcontext 44/426,
#   getsysteminfo 13/426, while genuine injection primitives
#   (virtualallocex/writeprocessmemory/createremotethread) appeared in 1/426.
API_GROUPS: dict[str, set[str]] = {
    "process_injection": {
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntunmapviewofsection", "queueuserapc",
        "ntwritevirtualmemory", "rtlcreateuserthread", "ntcreatethreadex",
        "virtualprotectex",
    },
    "dynamic_resolution": {
        "loadlibrarya", "loadlibraryw", "getprocaddress", "ldrloaddll",
        "ldrgetprocedureaddress",
    },
    "anti_debug": {
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "ntsetinformationthread",
    },
    "keylogging": {
        "getasynckeystate", "getkeyboardstate", "setwindowshookexa",
        "setwindowshookexw", "getrawinputdata", "getforegroundwindow",
    },
    "crypto": {
        "cryptencrypt", "cryptgenkey", "cryptacquirecontexta", "bcryptencrypt",
        "cryptderivekey", "cryptimportkey",
    },
    "network": {
        "internetopenurla", "internetopenurlw", "urldownloadtofilea",
        "urldownloadtofilew", "winhttpopenrequest", "wsastartup",
        "internetreadfile", "httpsendrequesta", "connect", "send", "recv",
    },
    "persistence": {
        "regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "createservicea",
        "createservicew", "openscmanagera", "schrpcregistertask",
    },
    "privilege": {
        "adjusttokenprivileges", "lookupprivilegevaluea", "openprocesstoken",
        "impersonateloggedonuser", "duplicatetokenex",
    },
    "discovery": {
        "createtoolhelp32snapshot", "process32first", "process32next",
        "enumprocesses", "getcomputernamea", "openprocess",
    },
}

# Pairs that meaningfully raise suspicion when seen together.
#
# The (anti_debug, dynamic_resolution) pair was removed: dynamic_resolution
# (LoadLibrary/GetProcAddress) is present in almost every real program, so the
# pair degenerated into "imports IsDebuggerPresent", which is true of 281/426
# clean Windows binaries.  It was the single noisiest import rule (42 clean
# files hit it, 9 of them pushed over the reporting threshold by it).
COMBO_RULES: list[tuple[tuple[str, ...], int, str]] = [
    (("process_injection", "dynamic_resolution"), 22,
     "Process-injection APIs combined with runtime API resolution"),
    (("process_injection", "discovery"), 18,
     "Process enumeration plus remote-memory write APIs"),
    (("keylogging", "network"), 20,
     "Keyboard capture APIs plus network transmission APIs"),
    (("crypto", "discovery"), 14,
     "Bulk crypto APIs plus filesystem/process enumeration (ransomware shape)"),
    (("persistence", "network"), 12,
     "Autostart-persistence APIs plus network download APIs"),
    (("privilege", "process_injection"), 16,
     "Privilege escalation APIs plus injection APIs"),
]

STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata", ".xdata",
    ".rsrc", ".reloc", ".tls", ".debug", ".didat", ".sxdata", ".gfids",
    ".00cfg", ".textbss", ".detourc", ".detourd", "code", "data", "const",
    # Ordinary MSVC / mingw / clang / Rust / Go linker output.  Every one of
    # these was observed in the clean-binary corpus; ".crt" and ".bss" alone
    # accounted for all 116 "non-standard section name" hits on clean files.
    ".crt", ".tbss", ".data1", ".rodata", ".eh_fram", ".eh_frame", ".drectve",
    ".buildid", ".msvcjmc", ".voltbl", ".retplne", ".giats", ".sdata",
    ".srdata", ".imrsiv", ".orpc", ".comment", ".stab", ".stabstr", ".symtab",
    ".strtab", ".charmap", ".wpp_sf", ".extjmp", ".idlsym", ".textcoa",
    ".itext", ".init", ".fini", ".ctors", ".dtors", ".jcr", ".note",
    ".rsrc1", ".rsrc2", ".text1", ".idata1", "_rdata", "_text", ".fptable",
    ".symtab$", ".gopclnt", ".noptrda", ".noptrbs", ".typelin", ".itablin",
}

# Prefixes of legitimate toolchain sections whose names get truncated to the
# 8-byte PE section-name field (".debug_info" -> ".debug_i", "/19" -> long-name
# reference emitted by binutils, etc).
STANDARD_SECTION_PREFIXES = (".debug", ".zdebug", ".gnu", "/", "$")

# Uninitialised-data sections: zero raw size is their normal state.
BSS_SECTIONS = {".bss", ".tbss", ".textbss", "bss", ".noptrbs", ".sbss"}

# Section names strongly associated with known packers.
PACKER_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".upx": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack", ".themida": "Themida",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma", ".petite": "Petite",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS", "pebundle": "PEBundle",
    ".nsp0": "NsPack", ".mew": "MEW", ".packed": "generic packer",
    "kkrunchy": "kkrunchy", ".boom": "BoomProtect", ".ccg": "CCG",
}

# A double extension is a *disguise*: the user sees "invoice.pdf" and launches
# an executable. That only works for types Explorer will launch on a
# double-click, so .dll is deliberately absent from the trailing group -- a
# library cannot be launched that way, and .NET names its assemblies after
# namespaces (System.Xml.dll, Newtonsoft.Json.dll, System.Text.Json.dll).
# On a real Windows drive those alone produced five medium-severity findings
# inside game installs, bypassing the protected-folder damping because this
# rule counts as a strong signal.
DANGEROUS_DOUBLE_EXT = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|ppt|pptx|txt|jpg|jpeg|png|gif|mp4|mp3|zip|rar|"
    r"csv|rtf|htm|html|log|json|xml)\s*\.(?:exe|scr|com|bat|cmd|pif|vbs|vbe|js|"
    r"jse|wsf|hta|lnk|ps1|jar|msi|cpl)$", re.IGNORECASE)

# Right-to-left override and friends — used to visually reverse an extension.
BIDI_CHARS = {"‪", "‫", "‬", "‭", "‮",
              "⁦", "⁧", "⁨", "⁩", "‏", "‎"}

# Extensions where PowerShell / Windows-Script *idioms* are meaningful.  The
# generic patterns below run on every script type; the "ps"-scoped ones only run
# here.  Rationale: .py / .js / .sh library code is full of tokens that look
# like PowerShell idioms out of context ("iex" is the Elixir shell and appears
# in Pygments lexers, ".downloadFile(" is an ordinary JS method in tuf-js and
# playwright, "FromBase64String" appears in a Pygments keyword table).  Those
# produced 30 of the clean-corpus script hits.
PS_IDIOM_EXT = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".wsf", ".wsh",
                ".jse", ".hta", ".lnk", ".reg", ".txt", ".log"}

# (pattern, delta, reason, scope) - scope "any" runs everywhere, "ps" only on
# PS_IDIOM_EXT files.
SCRIPT_PATTERNS: list[tuple[re.Pattern, int, str, str]] = [
    (re.compile(rb"frombase64string", re.I), 18,
     "PowerShell base64 payload decoding (FromBase64String)", "ps"),
    (re.compile(rb"-e(?:nc|ncoded|ncodedcommand)?\s+[A-Za-z0-9+/=]{60,}", re.I), 30,
     "PowerShell encoded-command with long base64 blob", "any"),
    # Narrowed: bare word "iex" is far too common (Elixir REPL references,
    # lexer token tables).  Require it to be used as a call/pipe target.
    (re.compile(rb"(?:^|[|;{(&]|\bcmd\s)\s*iex\s*[\(\$'\"@]|\binvoke-expression\b",
                re.I | re.M), 16,
     "Dynamic code execution (Invoke-Expression / IEX)", "any"),
    # "downloadfile" dropped: it is an ordinary method name in JS/Python HTTP
    # clients (12 clean hits).  DownloadString / WebClient / BITS remain
    # PowerShell-specific enough to keep.
    (re.compile(rb"downloadstring|invoke-webrequest|start-bitstransfer"
                rb"|net\.webclient|urldownloadtofile", re.I), 18,
     "Remote payload download in script", "any"),
    # "-nop"/"-noprofile" dropped: "-nop" matched inside ordinary hyphenated
    # words ("eat-crnl-nop") and -NoProfile is how node-gyp and playwright
    # legitimately invoke PowerShell.  Hidden-window and execution-policy
    # bypass are the parts that actually indicate evasion.
    (re.compile(rb"-w(?:indowstyle)?\s+hidden|-executionpolicy\s+bypass", re.I), 16,
     "Execution-policy bypass / hidden window flags", "any"),
    (re.compile(rb"\[reflection\.assembly\]::load|\[system\.reflection", re.I), 20,
     "In-memory .NET assembly loading", "ps"),
    (re.compile(rb"add-mppreference\s+-exclusionpath|set-mppreference", re.I), 35,
     "Attempts to add Windows Defender exclusions", "any"),
    (re.compile(rb"vssadmin\s+delete\s+shadows|wbadmin\s+delete|bcdedit\s+/set", re.I), 40,
     "Deletes shadow copies / tampers with recovery (ransomware behaviour)", "any"),
    # Anchored: unanchored "sdelete" matched "_isdeleted",
    # "bundleDependenciesDeleteFalse" and an all-caps keyword table.
    (re.compile(rb"\bcipher\s+/w|(?<![\w.$-])sdelete(?:64)?(?:\.exe)?\s+[-/]", re.I),
     12, "Secure-wipe utility invocation", "any"),
    (re.compile(rb"schtasks\s+/create|reg\s+add.{0,80}\\run\b", re.I), 18,
     "Creates autostart persistence", "any"),
    (re.compile(rb"net\s+user\s+(?:[^\n]{0,60}\s)?/add"
                rb"|net\s+localgroup\s+administrators\s+.{1,40}/add", re.I), 25,
     "Creates or elevates a local account", "any"),
    (re.compile(rb"chr\(\d{1,3}\)\s*&\s*chr\(\d{1,3}\)\s*&\s*chr\(", re.I), 20,
     "Character-code string obfuscation", "any"),
    (re.compile(rb"(?:eval|atob)\s*\(\s*(?:atob|unescape|decodeuricomponent)", re.I), 22,
     "Nested eval/decode obfuscation", "any"),
    (re.compile(rb"wscript\.shell.{0,60}\.run", re.I | re.S), 14,
     "WScript.Shell command execution", "any"),
    (re.compile(rb"certutil\s+.{0,40}-(?:urlcache|decode)", re.I), 28,
     "certutil abused for download/decode (LOLBin)", "any"),
    (re.compile(rb"mshta\s+(?:http|javascript:)", re.I), 26,
     "mshta remote execution", "any"),
    (re.compile(rb"rundll32\s+.{0,40}javascript:", re.I), 30,
     "rundll32 script execution", "any"),
    (re.compile(rb"curl\s+.{0,80}\|\s*(?:ba)?sh|wget\s+.{0,80}\|\s*(?:ba)?sh", re.I), 26,
     "Pipes remote content directly into a shell", "any"),
]

# A long base64 run is only interesting when something in the file can decode
# or execute it.  On its own it matched JS source maps, cryptographic test
# vectors and embedded data tables (31 clean hits).
B64_DECODER = re.compile(
    rb"frombase64string|atob\s*\(|b64decode|base64\s*\.\s*decode"
    rb"|-e(?:nc|ncodedcommand)?\s|::fromb|decodebase64|certutil\s+.{0,40}-decode",
    re.I)
# Data URIs and source maps are self-describing embedded data, not obfuscation.
B64_BENIGN_CONTEXT = re.compile(rb"sourcemappingurl|;base64,|data:[\w/+.-]{1,40};",
                                re.I)

MZ = b"MZ"
ELF = b"\x7fELF"
SCRIPT_SNIFF_BYTES = 512 * 1024


def shannon_entropy(data: bytes) -> float:
    """Bits of entropy per byte. >7.2 on a whole section suggests packed/encrypted."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ------------------------------------------------------------ filename

_VOWELS = set("aeiouy")


def _looks_random(stem: str) -> bool:
    """Crude but effective randomness signal for an all-lowercase name stem.

    A bare `[a-z0-9]{16,}` length test flags legitimate one-word system
    libraries — presentationframework.dll, windowsformsintegration.dll,
    reachframework.dll — which is a guaranteed false positive on any Windows
    install. Real English/product words keep a pronounceable letter structure:
    they mix vowels and consonants, never run five consonants together, and do
    not carry hex-style digit runs. Anything that violates that is what dropped
    payloads (`a8f3c91b2d47e05f.exe`, `bbbbbbbbbbbbbbbb.dll`) look like.
    """
    letters = [c for c in stem if c.isalpha()]
    if not letters:
        return True
    # Digits mixed into an otherwise word-like name: hex/base32 droppings.
    if any(c.isdigit() for c in stem):
        return True
    vowels = sum(1 for c in letters if c in _VOWELS)
    ratio = vowels / len(letters)
    if ratio < 0.20 or ratio > 0.65:
        return True
    run = best_c = best_v = 0
    prev_is_vowel = None
    for c in letters:
        is_v = c in _VOWELS
        run = run + 1 if is_v is prev_is_vowel else 1
        prev_is_vowel = is_v
        if is_v:
            best_v = max(best_v, run)
        else:
            best_c = max(best_c, run)
    return best_c >= 5 or best_v >= 4


def check_filename(path: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    name = os.path.basename(path)
    lower = name.lower()

    if DANGEROUS_DOUBLE_EXT.search(name):
        out.append((32, f"Double extension disguising an executable: {name!r}"))
    if any(ch in name for ch in BIDI_CHARS):
        out.append((40, "Filename contains a bidirectional-override character "
                        "(visually fakes the real extension)"))
    if re.search(r"\s{4,}\.(?:exe|scr|bat|cmd|vbs|js|com|pif)$", lower):
        out.append((28, "Long whitespace run before executable extension"))
    if len(name) > 160:
        out.append((8, "Abnormally long filename"))
    # Executables masquerading in a folder that should not contain them.
    parent = os.path.basename(os.path.dirname(path)).lower()
    ext = os.path.splitext(lower)[1]
    if ext in config.BINARY_EXT and parent in {"pictures", "music", "videos", "documents"}:
        out.append((10, f"Executable located in a media/document folder ({parent})"))
    if re.fullmatch(r"[a-z0-9]{16,}\.(?:exe|dll|scr)", lower) and _looks_random(
            os.path.splitext(lower)[0]):
        out.append((12, "Random-looking filename typical of dropped payloads"))
    # A launcher or anti-cheat binary outside every known install location is a
    # masquerade: the real ones live under Steam / Epic / Riot / Program Files,
    # which config.protected_reason() recognises. This is the inverse of the
    # protected-location rule, and the reason that name list is not itself
    # protective -- otherwise malware could immunise itself by picking the name.
    if (config.basename_any(path) in config.LAUNCHER_FILENAMES
            and not config.is_protected(path)):
        out.append((30, f"Named after a game launcher or anti-cheat service "
                        f"({name}) but located outside any known install "
                        f"folder - a common masquerade"))
    return out


def check_content_type_mismatch(path: str, header: bytes) -> list[tuple[int, str]]:
    ext = os.path.splitext(path)[1].lower()
    out: list[tuple[int, str]] = []
    looks_pe = header.startswith(MZ)
    looks_elf = header.startswith(ELF)
    doc_like = {".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".doc", ".docx",
                ".xls", ".xlsx", ".csv", ".rtf", ".log", ".json", ".xml", ".mp3",
                ".mp4", ".html", ".htm"}
    if (looks_pe or looks_elf) and ext in doc_like:
        kind = "Windows PE" if looks_pe else "ELF"
        out.append((45, f"File extension is {ext} but content is a {kind} executable"))
    if looks_pe and ext == "":
        out.append((15, "Extensionless file containing a PE executable"))
    return out


# ------------------------------------------------------------------ PE

def _has_tls_callbacks(pe) -> bool:
    """True only when the TLS directory names at least one real callback."""
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if not tls or not getattr(tls, "struct", None):
        return False
    aoc = getattr(tls.struct, "AddressOfCallBacks", 0)
    if not aoc:
        return False
    try:
        rva = aoc - pe.OPTIONAL_HEADER.ImageBase
        if rva < 0:
            return False
        plus = pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
        first = pe.get_qword_at_rva(rva) if plus else pe.get_dword_at_rva(rva)
        return bool(first)
    except Exception:  # noqa: BLE001
        return False


def analyse_pe(path: str) -> tuple[list[tuple[int, str]], dict]:
    """Structural analysis of a Windows PE file. Returns (findings, metadata)."""
    out: list[tuple[int, str]] = []
    meta: dict = {}
    if not HAVE_PEFILE:
        return out, meta
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
        ])
    except Exception as exc:  # noqa: BLE001 - pefile raises many types
        return [(10, f"Malformed PE structure ({type(exc).__name__})")], meta

    try:
        meta["is_dll"] = bool(pe.is_dll())
        meta["machine"] = hex(pe.FILE_HEADER.Machine)
        meta["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
        # A managed (.NET) assembly has a CLR runtime header. Its native import
        # table is a single _CorExeMain/_CorDllMain stub and its timestamp is
        # a deterministic-build hash, so two rules below are meaningless for
        # it. (The benign corpus in FINDINGS.md contained no .NET assemblies.)
        dotnet = False
        try:
            com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
            dotnet = bool(com.VirtualAddress and com.Size)
        except Exception:  # noqa: BLE001
            pass
        meta["dotnet"] = dotnet

        # --- sections
        high_entropy: list[str] = []
        wx_sections: list[str] = []
        odd_names: list[str] = []
        packers: set[str] = set()
        raw_zero: list[str] = []

        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("utf-8", "replace")
            lname = name.lower().strip()
            data = sec.get_data() or b""
            ent = shannon_entropy(data[:1024 * 1024])

            chars = sec.Characteristics
            writable = bool(chars & 0x80000000)
            executable = bool(chars & 0x20000000)

            if lname in PACKER_SECTIONS:
                packers.add(PACKER_SECTIONS[lname])
            elif (lname and lname not in STANDARD_SECTIONS
                  and not lname.startswith(STANDARD_SECTION_PREFIXES)):
                odd_names.append(name)

            # Only *executable* high-entropy sections indicate packed code.
            # Compressed/encrypted payloads that legitimately live in read-only
            # data (icons, PNG resources, embedded certificates, lookup tables)
            # produced every high-entropy hit on the clean corpus, all of them
            # in .rdata.
            if ent > 7.2 and len(data) > 4096 and executable:
                high_entropy.append(f"{name} ({ent:.2f})")

            if writable and executable:
                wx_sections.append(name)
            # A zero-raw-size section is only an unpacking stub if it is
            # executable.  Uninitialised-data sections (.bss/.tbss) are
            # zero-raw-size by definition and produced all 49 clean hits.
            if (sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0x1000
                    and executable and lname not in BSS_SECTIONS):
                raw_zero.append(name)

        meta["sections"] = len(pe.sections)
        meta["packers"] = sorted(packers)

        if packers:
            out.append((25, f"Known packer signature: {', '.join(sorted(packers))}"))
        if high_entropy:
            out.append((16, "High-entropy section(s) suggesting packed or "
                            f"encrypted code: {', '.join(high_entropy[:3])}"))
        if wx_sections:
            out.append((14, "Section marked both writable and executable: "
                            f"{', '.join(wx_sections[:3])}"))
        if odd_names:
            out.append((5, f"Non-standard section name(s): {', '.join(odd_names[:3])}"))
        if raw_zero:
            out.append((12, "Section with zero raw size but large virtual size "
                            f"(unpacking stub): {', '.join(raw_zero[:2])}"))

        # --- entry point placement
        try:
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_sec = None
            for i, sec in enumerate(pe.sections):
                if sec.VirtualAddress <= ep < sec.VirtualAddress + max(
                        sec.Misc_VirtualSize, sec.SizeOfRawData):
                    ep_sec = i
                    break
            if ep_sec is None:
                out.append((22, "Entry point does not fall inside any section"))
            elif ep_sec == len(pe.sections) - 1 and len(pe.sections) > 1:
                out.append((14, "Entry point located in the final section "
                                "(common after packing)"))
            elif not (pe.sections[ep_sec].Characteristics & 0x20000000):
                out.append((16, "Entry point in a non-executable section"))
        except Exception:  # noqa: BLE001
            pass

        # --- imports
        groups_hit: dict[str, list[str]] = {}
        total_imports = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports or []:
                    if not imp.name:
                        continue
                    total_imports += 1
                    fn = imp.name.decode("utf-8", "replace").lower()
                    for gname, apis in API_GROUPS.items():
                        if fn in apis:
                            groups_hit.setdefault(gname, []).append(fn)
        meta["imports"] = total_imports
        meta["api_groups"] = sorted(groups_hit)

        for names, delta, reason in COMBO_RULES:
            if all(n in groups_hit for n in names):
                sample = ", ".join(
                    sorted({a for n in names for a in groups_hit[n]})[:4])
                out.append((delta, f"{reason} [{sample}]"))

        if dotnet:
            out.append((0, ".NET assembly (managed code; native import table "
                           "and compile timestamp are not meaningful)"))
        elif total_imports == 0 and not packers:
            out.append((18, "PE has no readable import table (imports likely "
                            "resolved at runtime to evade static analysis)"))
        elif 0 < total_imports <= 5:
            out.append((10, f"Unusually small import table ({total_imports} functions)"))

        # --- signature presence
        sec_dir = getattr(pe, "OPTIONAL_HEADER", None)
        signed = False
        try:
            d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            signed = d.VirtualAddress != 0 and d.Size != 0
        except Exception:  # noqa: BLE001
            pass
        meta["signed"] = signed
        if not signed:
            # Informational only (score 0): 425 of 426 clean Windows binaries in
            # the measured corpus carry no Authenticode signature, so absence
            # of a signature discriminates nothing.  It stays in the reason
            # list because it is useful context for the human reviewer once
            # something else has already raised the score.
            out.append((0, "No embedded Authenticode signature"))

        # --- resource-embedded executable
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            try:
                for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for rid in getattr(rtype, "directory", type("x", (), {"entries": []})).entries:
                        for lang in getattr(rid, "directory", type("x", (), {"entries": []})).entries:
                            data = pe.get_data(lang.data.struct.OffsetToData,
                                               min(2, lang.data.struct.Size))
                            if data.startswith(MZ) and lang.data.struct.Size > 8192:
                                out.append((26, "Embedded PE executable found in "
                                                "resources (dropper pattern)"))
                                raise StopIteration
            except StopIteration:
                pass
            except Exception:  # noqa: BLE001
                pass

        # --- timestamp sanity
        # --- timestamp sanity
        # Reproducible builds (MSVC /Brepro, clang, Rust, Go, Python wheels)
        # either zero the timestamp or replace it with a content hash, which
        # frequently decodes as a far-future date.  Zeroed stamps appeared in
        # 109/426 clean binaries and future stamps in 3/426, so a zeroed stamp
        # is reported without score and a future stamp is scored lightly.
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts == 0:
                out.append((0, "Zeroed PE compile timestamp"))
            elif ts > 2_000_000_000 and not dotnet:
                out.append((4, "PE compile timestamp is in the future"))
        except Exception:  # noqa: BLE001
            pass

        # --- TLS callbacks
        # A TLS *directory* alone only means the binary uses thread_local
        # storage (any C++ binary does).  Require an actual callback array
        # with at least one non-null entry, and score it lightly: 114/426
        # clean binaries genuinely register a TLS callback (the MSVC/mingw CRT
        # installs __dyn_tls_init), so this cannot carry a finding by itself.
        if _has_tls_callbacks(pe):
            out.append((2, "TLS callbacks present (can run code before entry point)"))
    finally:
        try:
            pe.close()
        except Exception:  # noqa: BLE001
            pass

    return out, meta


# -------------------------------------------------------------- scripts

def _is_text_in_some_encoding(sample: bytes) -> bool:
    """True if the bytes decode cleanly as UTF-8 or UTF-16 text."""
    for enc in ("utf-8", "utf-16-le", "utf-16-be"):
        try:
            # Trim to a codepoint boundary-safe length for the multibyte cases.
            sample.decode(enc)
            return True
        except UnicodeDecodeError as exc:
            # A truncated final character is not evidence of binary content.
            if exc.start >= len(sample) - 4:
                return True
    return False


# Container formats that happen to carry a script-ish extension (.jar is a zip).
_CONTAINER_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"BZh",
                    b"\xfd7zXZ", b"7z\xbc\xaf", b"Rar!", MZ, ELF)


def analyse_script(path: str, data: bytes) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    sample = data[:SCRIPT_SNIFF_BYTES]
    ext = os.path.splitext(path)[1].lower()
    ps_scope = ext in PS_IDIOM_EXT

    for pattern, delta, reason, scope in SCRIPT_PATTERNS:
        if scope == "ps" and not ps_scope:
            continue
        if pattern.search(sample):
            out.append((delta, reason))

    # Very long single-token base64 blobs inside a script, but only when the
    # file also contains something able to decode or execute them, and only
    # when the blob is not a self-describing data URI / source map.
    if B64_DECODER.search(sample):
        for m in re.finditer(rb"[A-Za-z0-9+/=]{200,}", sample):
            lead = sample[max(0, m.start() - 60):m.start()]
            if B64_BENIGN_CONTEXT.search(lead):
                continue
            out.append((12, f"Long base64-like blob embedded in script "
                            f"({len(m.group(0))} chars)"))
            break

    # Non-printable-byte check.  Skipped for container formats, and skipped
    # when the content is valid UTF-8/UTF-16 text: non-Latin scripts (Arabic,
    # Hindi, Korean source data) are legitimately "non-printable" bytewise and
    # produced every clean hit on this rule.
    if (sample and len(sample) > 512
            and not sample.startswith(_CONTAINER_MAGIC)
            and not _is_text_in_some_encoding(sample)):
        printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
        if printable / len(sample) < 0.7:
            out.append((12, "Script-type file is mostly non-printable bytes"))
    return out


def analyse_macro_office(path: str, data: bytes) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    low = data[:2 * 1024 * 1024].lower()
    if b"vbaproject.bin" in low or b"\x00a\x00t\x00t\x00r\x00i\x00b\x00u\x00t" in low:
        out.append((12, "Office document contains a VBA macro project"))
    for marker, delta, reason in [
        (b"auto_open", 20, "VBA auto-execution macro (Auto_Open)"),
        (b"autoopen", 20, "VBA auto-execution macro (AutoOpen)"),
        (b"document_open", 18, "VBA auto-execution macro (Document_Open)"),
        (b"workbook_open", 18, "VBA auto-execution macro (Workbook_Open)"),
        (b"shell(", 22, "VBA macro invokes Shell()"),
        (b"createobject", 12, "VBA macro uses CreateObject"),
        (b"powershell", 25, "Office document references PowerShell"),
        (b"urlmon", 22, "Office document references URLMON (download)"),
    ]:
        if marker in low:
            out.append((delta, reason))
    return out


def severity_for(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    if score >= 25:
        return "low"
    return "info"
