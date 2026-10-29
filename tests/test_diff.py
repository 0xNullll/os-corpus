"""diff_corpus.py: two corpora collected from fake images that differ in one known way per kind
of change.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from pefixtures import COLLECT, DIFF, build_image, output, read_tsv, run, write_pe

import diff_corpus
import pelib


class DiffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="os-corpus-diff-")
        root = Path(cls._tmp.name)
        cls.root = root

        old = build_image(root / "old-img")
        write_pe(old / "Windows/System32/v.dll", marker=b"V1", version=(1, 0, 0, 0))

        new = build_image(root / "new-img")
        write_pe(new / "Windows/System32/v.dll", marker=b"V2", version=(2, 0, 0, 0))  # updated
        write_pe(new / "Windows/System32/b.dll", marker=b"B9")                        # rebuilt
        write_pe(new / "Windows/System32/new.dll", marker=b"NEW")                     # added
        (new / "Windows/System32/drivers/x.sys").unlink()                             # removed
        tool = new / "Program Files/App/tool.exe"                                     # moved
        (new / "Program Files/App2").mkdir(parents=True)
        tool.rename(new / "Program Files/App2/tool.exe")

        for name, img in (("old", old), ("new", new)):
            result = run(COLLECT, img, root / "corpus" / name, "--link-root", "none")
            assert result.returncode == 0, output(result)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(pelib.long_path(cls._tmp.name, True), ignore_errors=True)
        cls._tmp.cleanup()

    def diff(self, *extra):
        return run(DIFF, self.root / "corpus" / "old", self.root / "corpus" / "new", *extra)

    def test_counts(self):
        result = self.diff()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("[+] diff: old -> new: 1 added, 1 removed, 1 updated, 1 rebuilt, 1 moved, "
                      "5 unchanged", result.stdout)
        self.assertIn("1.0.0.0 -> 2.0.0.0", result.stdout)
        self.assertIn("Program Files/App/tool.exe -> Program Files/App2/tool.exe", result.stdout)

    def test_tsv(self):
        path = self.root / "diff.tsv"
        result = self.diff("--tsv", path)
        self.assertEqual(result.returncode, 0, output(result))
        header, rows = read_tsv(path)
        self.assertEqual(tuple(header), diff_corpus.DIFF_HEADER)
        self.assertEqual([(r["change"], r["name"]) for r in rows], [
            ("added", "new.dll"), ("removed", "x.sys"), ("updated", "v.dll"),
            ("rebuilt", "b.dll"), ("moved", "tool.exe")])
        updated = rows[2]
        self.assertEqual((updated["old_version"], updated["new_version"]), ("1.0.0.0", "2.0.0.0"))

    def test_only_and_report_directories(self):
        manifests = self.root / "corpus" / "manifests"
        result = run(DIFF, manifests / "old", manifests / "new", "--only", "unchanged",
                     "--limit", "0", "--tsv", self.root / "unchanged.tsv")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("[i] unchanged: all 5", result.stdout)
        _, rows = read_tsv(self.root / "unchanged.tsv")
        self.assertEqual(len(rows), 5)

    def test_errors(self):
        self.assertEqual(self.diff("--only", "nonsense").returncode, 2)
        missing = run(DIFF, self.root / "nope", self.root / "corpus" / "new")
        self.assertEqual(missing.returncode, 1)
        self.assertIn("[!] diff: cannot read", missing.stderr)


if __name__ == "__main__":
    unittest.main()
