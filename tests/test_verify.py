"""verify_corpus.py: run against a real collect_pes.py output, then against tampered copies of
it, one failure class at a time.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from pefixtures import COLLECT, VERIFY, build_image, output, pe_bytes, run

import collect_pes
import pelib
import verify_corpus


class ContractTests(unittest.TestCase):
    def test_columns_agree_with_collect(self):
        self.assertEqual(verify_corpus.MODULES_HEADER, collect_pes.MODULES_HEADER)
        self.assertEqual(verify_corpus.DUPLICATES_HEADER, collect_pes.DUPLICATES_HEADER)
        self.assertEqual(verify_corpus.COLLISIONS_HEADER, collect_pes.COLLISIONS_HEADER)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="os-corpus-verify-")
        self.root = Path(self._tmp.name)
        img = build_image(self.root / "img")
        self.out = self.root / "corpus" / "build"
        self.report = self.root / "corpus" / "manifests" / "build"
        result = run(COLLECT, img, self.out, "--link-root", "none")
        self.assertEqual(result.returncode, 0, output(result))

    def tearDown(self):
        shutil.rmtree(pelib.long_path(self._tmp.name, True), ignore_errors=True)
        self._tmp.cleanup()

    def verify(self, *extra):
        return run(VERIFY, self.out, *extra)

    def assertCode(self, result, code, *needles):
        text = output(result)
        self.assertEqual(result.returncode, code, text)
        for needle in needles:
            self.assertIn(needle, text)

    def edit(self, name, change):
        path = self.report / name
        text = change(path.read_text(encoding="utf-8"))
        # Path.write_text has no newline argument before Python 3.10.
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    # -- passing -----------------------------------------------------------

    def test_passes(self):
        self.assertCode(self.verify(), 0, "[+] verify:", "[>] re-hashing 9 files (",
                        "[+] hashes      9 verified in", "[+] modules")

    def test_parallel_hashing(self):
        self.assertCode(self.verify("--jobs", "1"), 0)
        self.assertCode(self.verify("--jobs", "4"), 0)
        victim = self.out / "Windows/System32/b.dll"
        data = bytearray(victim.read_bytes())
        data[-1] ^= 0xFF
        victim.write_bytes(bytes(data))
        self.assertCode(self.verify("--jobs", "4"), 4, "Windows/System32/b.dll")
        self.assertCode(self.verify("--jobs", "0"), 2)

    def test_fast_skips_hashes(self):
        self.assertCode(self.verify("--fast"), 0, "[~] hashes      skipped (--fast)")

    # -- content mismatch: 4 ------------------------------------------------

    def test_same_size_corruption(self):
        victim = self.out / "Windows/System32/b.dll"
        data = bytearray(victim.read_bytes())
        data[-1] ^= 0xFF
        victim.write_bytes(bytes(data))
        self.assertCode(self.verify(), 4, "[!] verify: hashes")
        self.assertCode(self.verify("--fast"), 0)

    def test_size_change_is_caught_by_fast(self):
        victim = self.out / "Windows/System32/b.dll"
        victim.write_bytes(victim.read_bytes() + b"tampered")
        self.assertCode(self.verify("--fast"), 4, "[!] verify: sizes")

    def test_extra_file(self):
        (self.out / "Windows/System32/extra.dll").write_bytes(pe_bytes(marker=b"E"))
        self.assertCode(self.verify(), 4, "1 unexpected")

    def test_missing_file(self):
        (self.out / "Windows/System32/b.dll").unlink()
        self.assertCode(self.verify(), 4, "1 missing")

    def test_identity(self):
        (self.report / "source.json").write_text(json.dumps({
            "schema": "os-corpus/source/1", "kind": "directory",
            "image": {"name": "img", "bytes": 0, "sha256": ""},
            "revision": "", "manifestSha256": "0" * 64,
        }), encoding="utf-8")
        self.assertCode(self.verify(), 4, "[!] verify: identity")

    def test_malformed_manifest(self):
        self.edit("manifest.sha256", lambda t: t + "nothex  Windows/x.dll\n")
        self.assertCode(self.verify(), 4, "malformed")

    # -- report disagrees: 5 -------------------------------------------------

    def test_two_canonical_rows(self):
        def promote_variant(text):
            lines = text.splitlines()
            for i, line in enumerate(lines):
                fields = line.split("\t")
                if fields[-1] == "Windows/WinSxS/amd64_comp/b.dll":
                    self.assertEqual(fields[2], "0")
                    fields[2] = "1"
                    lines[i] = "\t".join(fields)
            return "\n".join(lines) + "\n"
        self.edit("modules.tsv", promote_variant)
        self.assertCode(self.verify(), 5, "exactly one canonical")

    def test_summary_counts(self):
        def change(text):
            summary = json.loads(text)
            summary["counts"]["stored_files"] += 1
            return json.dumps(summary)
        self.edit("summary.json", change)
        self.assertCode(self.verify(), 5, "[!] verify: summary")

    def test_stored_duplicate(self):
        self.edit("duplicates.tsv",
                  lambda t: t + "x.dll\tx64\t%s\tWindows/System32/a.dll\tWindows/System32/b.dll\n"
                  % ("0" * 64))
        self.assertCode(self.verify(), 5, "also stored")

    # -- collisions: 3 ----------------------------------------------------

    def test_collisions(self):
        self.edit("collisions.tsv",
                  lambda t: t + "Windows/a.dll\t%s\tWindows/A.dll\t%s\n" % ("1" * 64, "2" * 64))
        self.assertCode(self.verify(), 3, "[!] verify: collisions")
        self.assertCode(self.verify("--allow-collisions"), 0, "[~] collisions")

    def test_mismatch_outranks_collisions(self):
        self.edit("collisions.tsv",
                  lambda t: t + "Windows/a.dll\t%s\tWindows/A.dll\t%s\n" % ("1" * 64, "2" * 64))
        (self.out / "Windows/System32/b.dll").unlink()
        self.assertCode(self.verify(), 4)

    # -- usage and errors --------------------------------------------------

    def test_requires_report(self):
        self.assertCode(run(VERIFY, self.out, "--report", self.root / "nope"), 2)

    def test_missing_manifest(self):
        (self.report / "manifest.sha256").unlink()
        self.assertCode(self.verify(), 1, "interrupted")


if __name__ == "__main__":
    unittest.main()
