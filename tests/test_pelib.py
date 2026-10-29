"""pelib.py: header sniffing, classification, version resources, long paths, the CLI.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import io
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from pefixtures import (CUI, EFI_APP, NATIVE, PE32, PELIB, X64, X86, edge_lfanew_bytes,
                        pe_bytes, run, vblock, version_blob, vstring, write_pe)

import pelib


class SniffTests(unittest.TestCase):
    def test_pe32plus_is_x64(self):
        info = pelib.sniff_bytes(pe_bytes(machine=X64))
        self.assertEqual((info["arch"], info["magic"], info["dll"]), ("x64", "pe32+", True))

    def test_pe32_is_x86(self):
        info = pelib.sniff_bytes(pe_bytes(machine=X86))
        self.assertEqual((info["arch"], info["magic"]), ("x86", "pe32"))

    def test_unknown_machine_is_other(self):
        self.assertEqual(pelib.sniff_bytes(pe_bytes(machine=0x1234))["arch"], "other")

    def test_rejects(self):
        bad_lfanew = bytearray(pe_bytes())
        struct.pack_into("<I", bad_lfanew, 0x3C, 0xFFFFFF00)
        bad_magic = bytearray(pe_bytes())
        struct.pack_into("<H", bad_magic, 0x98, 0x999)
        cases = {
            "empty": b"",
            "mz only": b"MZ" + b"\x00" * 0x200,
            "text": b"not a pe at all" * 100,
            "bad e_lfanew": bytes(bad_lfanew),
            "bad magic": bytes(bad_magic),
        }
        for label, data in cases.items():
            with self.subTest(label):
                self.assertIsNone(pelib.sniff_bytes(data))

    def test_rejects_section_table_past_eof(self):
        data = bytearray(pe_bytes(size=0x400))
        struct.pack_into("<H", data, 0x86, 40)
        struct.pack_into("<I", data, 0x3C, 0x3C0)
        self.assertIsNone(pelib.sniff_bytes(bytes(data), file_size=0x400))

    def test_signature_at_sniff_boundary_does_not_raise(self):
        self.assertIsNone(pelib.sniff_bytes(edge_lfanew_bytes()))

    def test_every_truncation_is_safe(self):
        data = pe_bytes()
        for n in range(0, 0x200, 7):
            pelib.sniff_bytes(data[:n])


class ClassificationTests(unittest.TestCase):
    def kind(self, **kwargs):
        return pelib.sniff_bytes(pe_bytes(**kwargs))["kind"]

    def test_kinds(self):
        cases = [
            ("dll", dict(dll=True)),
            ("exe", dict(dll=False)),
            ("resource", dict(dll=True, entry=0, code_size=0)),
            ("native", dict(dll=False, subsystem=NATIVE)),
            ("native", dict(dll=True, subsystem=NATIVE)),
            ("efi", dict(dll=False, subsystem=EFI_APP)),
            ("exe", dict(dll=False, entry=0, code_size=0)),
        ]
        for expected, kwargs in cases:
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.kind(**kwargs), expected)
        self.assertEqual(set(k for k, _ in cases), set(pelib.KINDS))

    def test_clr_keeps_header_arch(self):
        info = pelib.sniff_bytes(pe_bytes(machine=X86, clr=True))
        self.assertTrue(info["clr"])
        self.assertEqual(info["arch"], "x86")
        self.assertFalse(pelib.sniff_bytes(pe_bytes())["clr"])

    def test_embedded_signature(self):
        self.assertTrue(pelib.sniff_bytes(pe_bytes(cert=True))["embedded_signature"])
        self.assertFalse(pelib.sniff_bytes(pe_bytes())["embedded_signature"])

    def test_pe32_directories(self):
        info = pelib.sniff_bytes(pe_bytes(machine=X86, magic=PE32, clr=True, cert=True))
        self.assertTrue(info["clr"] and info["embedded_signature"])

    def test_subsystem_names(self):
        self.assertEqual(pelib.SUBSYSTEMS[CUI], "cui")
        self.assertEqual(pelib.SUBSYSTEMS[13], "efi-rom")
        self.assertEqual(pelib.SUBSYSTEMS[16], "windows-boot")


class VersionTests(unittest.TestCase):
    def test_fixed_file_version(self):
        parsed = pelib.parse_version_blob(version_blob())
        self.assertEqual(parsed["file_version"], "10.0.19045.3803")
        self.assertEqual(parsed["product_version"], "10.0.19045.3803")
        self.assertTrue(parsed["fixed"])

    def test_strings_are_extracted(self):
        parsed = pelib.parse_version_blob(version_blob(strings={
            "CompanyName": "Microsoft Corporation",
            "FileDescription": "NT Layer DLL",
        }))
        self.assertEqual(parsed["company"], "Microsoft Corporation")
        self.assertEqual(parsed["description"], "NT Layer DLL")

    def test_string_fallback_without_fixed_info(self):
        table = vblock("040904B0", b"", vtype=1, vlen=0,
                       children=vstring("FileVersion", "6.1.7601.17514"))
        blob = vblock("VS_VERSION_INFO", b"", vtype=0, vlen=0,
                      children=vblock("StringFileInfo", b"", vtype=1, vlen=0, children=table))
        parsed = pelib.parse_version_blob(blob)
        self.assertFalse(parsed["fixed"])
        self.assertEqual(parsed["file_version"], "6.1.7601.17514")

    def test_garbage_is_empty(self):
        self.assertEqual(pelib.parse_version_blob(b"\xff" * 64)["file_version"], "")

    def test_version_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pe(Path(tmp) / "v.dll", version=(6, 3, 9600, 17031))
            self.assertEqual(pelib.version_of(str(path))["file_version"], "6.3.9600.17031")

    def test_version_tuple(self):
        self.assertEqual(pelib.version_tuple("10.0.19041.3803"), (10, 0, 19041, 3803))
        self.assertEqual(pelib.version_tuple("1.2"), (1, 2, 0, 0))
        self.assertEqual(pelib.version_tuple(""), (0, 0, 0, 0))
        self.assertEqual(pelib.version_tuple("1.x.3"), (1, 0, 3, 0))

    def test_real_binary_if_present(self):
        ntdll = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "ntdll.dll"
        if not ntdll.exists():
            self.skipTest("no ntdll.dll on this host")
        self.assertRegex(pelib.version_of(str(ntdll))["file_version"], r"^\d+\.\d+\.\d+\.\d+$")


class ProgressTests(unittest.TestCase):
    class Stream(io.StringIO):
        def __init__(self, tty):
            super().__init__()
            self.tty = tty

        def isatty(self):
            return self.tty

    def progress(self, tty, enabled=True):
        stream = self.Stream(tty)
        progress = pelib.Progress(enabled, stream)
        progress.LIVE_SECONDS = progress.LOG_SECONDS = 0
        return progress, stream

    def test_log_lines_into_a_pipe(self):
        progress, stream = self.progress(tty=False)
        progress.tick(lambda: "scan: 1 files")
        progress.tick(lambda: "scan: 2 files")
        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[1].startswith("[i] scan: 2 files, "))
        self.assertNotIn("\r", stream.getvalue())

    def test_one_redrawn_line_on_a_console(self):
        progress, stream = self.progress(tty=True)
        progress.tick(lambda: "place: 1/2 files")
        progress.tick(lambda: "place: 2/2 files")
        progress.clear()
        self.assertEqual(stream.getvalue().count("\r"), 4)
        self.assertNotIn("\n", stream.getvalue())

    def test_render_only_when_printed(self):
        calls = []
        progress, stream = self.progress(tty=False, enabled=False)
        progress.tick(lambda: calls.append(1) or "x")
        quiet = pelib.Progress(True, self.Stream(False))   # default 10 s interval
        quiet.tick(lambda: calls.append(1) or "x")
        self.assertEqual((calls, stream.getvalue()), ([], ""))

    def test_formats(self):
        self.assertEqual([pelib.duration(s) for s in (5.25, 245, 3725)], ["5.2s", "4m05s", "1h02m"])
        self.assertEqual(pelib.eta(10, 25, 100), ", ETA 30.0s")
        self.assertEqual(pelib.eta(10, 0, 100), "")
        self.assertEqual(pelib.byte_string(3 * 1024 ** 3), "3.0 GB")


class ParallelTests(unittest.TestCase):
    def test_ordered_map_keeps_input_order(self):
        items = list(range(200))
        for jobs in (1, 4):
            got = list(pelib.ordered_map(lambda x: x * x, iter(items), jobs, window=7))
            self.assertEqual(got, [(x, x * x) for x in items])

    def test_default_jobs(self):
        self.assertTrue(1 <= pelib.default_jobs() <= pelib.MAX_DEFAULT_JOBS)


class LongPathTests(unittest.TestCase):
    def test_prefix_only_when_needed(self):
        if os.name != "nt":
            self.assertEqual(pelib.long_path("/a/b", True), "/a/b")
            return
        self.assertEqual(pelib.long_path(r"C:\x"), r"C:\x")
        self.assertTrue(pelib.long_path(r"C:\x", True).startswith("\\\\?\\C:\\"))
        self.assertTrue(pelib.long_path(r"\\host\share\x", True).startswith("\\\\?\\UNC\\host"))


class CliTests(unittest.TestCase):
    def test_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_pe(Path(tmp) / "x.dll", version=(1, 2, 3, 4))
            result = run(PELIB, "info", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            info = json.loads(result.stdout)
            self.assertEqual((info["kind"], info["file_version"]), ("dll", "1.2.3.4"))

    def test_not_a_pe(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.txt"
            path.write_text("hello", encoding="ascii")
            result = run(PELIB, "info", path)
            self.assertEqual(result.returncode, 1)
            self.assertIn("[!] pelib: not a PE", result.stderr)

    def test_usage(self):
        self.assertEqual(run(PELIB).returncode, 2)
        self.assertEqual(run(PELIB, "version").stdout.strip(), pelib.VERSION)


if __name__ == "__main__":
    unittest.main()
