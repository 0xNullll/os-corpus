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


class PortabilityTests(unittest.TestCase):
    # Script functions of Windows PowerShell 5.1's Utility module. They are missing when
    # powershell.exe inherits PowerShell 7's PSModulePath, which is how GitHub Actions starts it,
    # so the wrapper must not call them (Get-FileHash failed CI that way).
    SCRIPT_FUNCTIONS = ("Get-FileHash", "New-TemporaryFile", "New-Guid", "Format-Hex",
                        "Import-PowerShellDataFile", "ConvertFrom-SddlString")

    def test_no_utility_script_functions(self):
        code = "\n".join(line.split("#", 1)[0]
                         for line in Path(WRAPPER).read_text(encoding="utf-8").splitlines())
        for name in self.SCRIPT_FUNCTIONS:
            self.assertNotIn(name.lower(), code.lower(), name)


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

        # The result is the last line, after the time line; the log holds the same lines.
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        self.assertTrue(lines[-1].startswith("[+] extract-image: build, 9 files, verified, in "),
                        lines[-1])
        self.assertTrue(lines[-2].startswith("[i] time        scan "), lines[-2])
        logs = list((self.root / "corpus" / "logs").glob("build-*.log"))
        self.assertEqual(len(logs), 1)
        log = logs[0].read_text(encoding="utf-8")
        self.assertIn("[+] collect: 9 files stored", log)
        self.assertIn("[+] verify: ", log)
        self.assertEqual(log.splitlines()[-1], lines[-1])

    def test_no_log(self):
        result = wrapper("-Directory", self.img, "-Out", self.out, "-Label", "build", "-NoLog")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.root / "corpus" / "logs").exists())

    def test_edition_argument_checks(self):
        cases = [
            (("-Directory", self.img, "-Edition", "Windows 11 Pro"), "needs an image source"),
            (("-Iso", self.root / "x.iso", "-Edition", "Windows 11 Pro", "-Index", "6"),
             "both pick the image"),
        ]
        for args, message in cases:
            with self.subTest(message):
                result = wrapper(*args, "-Out", self.out)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)

    def test_relative_paths_follow_the_powershell_location(self):
        # An elevated window starts in C:\Windows\system32 and the user cd's to the repo: `cd`
        # moves $PWD but not the process directory, which is where the subprocess starts here.
        command = ("Set-Location -LiteralPath '{root}'; "
                   "& '{wrapper}' -Directory .\\img -Out .\\corpus\\build -Label build -Python '{py}'; "
                   "exit $LASTEXITCODE").format(root=self.root, wrapper=WRAPPER, py=sys.executable)
        result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
                                 "Bypass", "-Command", command],
                                capture_output=True, text=True, cwd=str(Path(WRAPPER).parent))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.report / "manifest.sha256").exists())

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
