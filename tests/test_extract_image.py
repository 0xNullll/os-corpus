"""extract-image.ps1: the -Directory path end to end (no elevation, no media), and the argument
checks that run before anything is mounted. Skipped where Windows PowerShell is not available.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pefixtures import STORED, WRAPPER, build_image

import pelib

POWERSHELL = shutil.which("powershell") if os.name == "nt" else None


def wrapper(*args):
    return subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-File", WRAPPER, *[str(a) for a in args], "-Python", sys.executable],
                          capture_output=True, text=True)


@unittest.skipUnless(POWERSHELL, "Windows PowerShell not available")
class WrapperTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="os-corpus-wrapper-")
        self.root = Path(self._tmp.name)
        self.img = build_image(self.root / "img")
        self.out = self.root / "corpus" / "build"
        self.report = self.root / "corpus" / "manifests" / "build"

    def tearDown(self):
        shutil.rmtree(pelib.long_path(self._tmp.name, True), ignore_errors=True)
        self._tmp.cleanup()

    def test_directory_source(self):
        result = wrapper("-Directory", self.img, "-Out", self.out, "-Label", "build")
        text = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, text)
        self.assertIn("[+] identity    manifest bound to img", text)
        self.assertIn("[+] extract-image: build, 9 files, verified", text)

        raw = (self.report / "source.json").read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "source.json has a BOM")
        self.assertNotIn(b"\r\n", raw)
        source = json.loads(raw)
        self.assertEqual(source["schema"], "os-corpus/source/1")
        self.assertEqual(source["kind"], "directory")
        self.assertIsNone(source["container"])
        self.assertEqual(source["collectedFiles"], len(STORED))
        self.assertEqual(source["manifestSha256"],
                         pelib.sha256_file(str(self.report / "manifest.sha256")))

    def test_delete_source_needs_verification(self):
        result = wrapper("-Iso", self.root / "x.iso", "-Out", self.out, "-DeleteSource", "-NoVerify")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("cannot be combined with -NoVerify", result.stderr)

    def test_delete_source_is_iso_only(self):
        result = wrapper("-Directory", self.img, "-Out", self.out, "-DeleteSource")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("only applies to -Iso", result.stderr)
        self.assertTrue(self.img.exists())


if __name__ == "__main__":
    unittest.main()
