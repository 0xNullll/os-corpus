"""collect_pes.py: selection rules as pure functions, then the real tool end to end on a fake
image tree (tests/pefixtures.py).

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import os
import random
import shutil
import tempfile
import unittest
from pathlib import Path

from pefixtures import (COLLECT, STORED, X64, build_image, output, pe_bytes, read_manifest,
                        read_tsv, run, same_file, write_pe)

import collect_pes
import pelib


def rec(rel, digest, arch="x64", version=None):
    r = collect_pes.make_record(rel, 1, digest * 64, arch)
    if version is not None:
        r.info = {"file_version": version}
    return r


class SelectionTests(unittest.TestCase):
    def test_location_and_rank_order(self):
        ordered = [
            ("Windows/System32/a.dll", "system32"),
            ("Windows/SysWOW64/a.dll", "syswow64"),
            ("Windows/SystemApps/x/a.dll", "systemapps"),
            ("Program Files (x86)/App/a.dll", "programfiles"),
            ("Windows/WinSxS/x/a.dll", "winsxs"),
            ("Windows/System32/DriverStore/FileRepository/f/a.dll", "driverstore"),
            ("Windows/Fonts/a.dll", "windows"),
            ("Users/a.dll", "other"),
        ]
        for rel, expected in ordered:
            self.assertEqual(collect_pes.location(rel), expected, rel)
        ranks = [collect_pes.rank(rel) for rel, _ in ordered]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual([loc for _, loc in ordered], list(collect_pes.LOCATIONS))

    def test_exclusions(self):
        pats = [p.lower() for p in collect_pes.DEFAULT_EXCLUDES]
        self.assertTrue(collect_pes.is_excluded("$recycle.bin/x.dll", False, pats))
        self.assertTrue(collect_pes.is_excluded("windows/softwaredistribution/download/x.dll",
                                                False, pats))
        self.assertTrue(collect_pes.is_excluded("windows/winsxs/temp", True, pats))
        self.assertFalse(collect_pes.is_excluded("windows/system32/kernel32.dll", False, pats))

    def test_identical_bytes_are_stored_once(self):
        stored, dups = collect_pes.select_group(
            [rec("Windows/WinSxS/x/a.dll", "a"), rec("Windows/System32/a.dll", "a")], lambda r: {})
        self.assertEqual([r.rel for r in stored], ["Windows/System32/a.dll"])
        self.assertTrue(stored[0].canonical)
        self.assertEqual(dups, [("a.dll", "x64", "a" * 64, "Windows/System32/a.dll",
                                 "Windows/WinSxS/x/a.dll")])

    def test_every_content_is_stored_and_the_best_is_canonical(self):
        stored, dups = collect_pes.select_group(
            [rec("Windows/WinSxS/x/a.dll", "b"), rec("Windows/System32/a.dll", "a")], lambda r: {})
        self.assertEqual([(r.rel, r.canonical) for r in stored],
                         [("Windows/System32/a.dll", True), ("Windows/WinSxS/x/a.dll", False)])
        self.assertEqual(dups, [])

    def test_version_breaks_a_rank_tie(self):
        versions = {"Windows/System32/aaa/v.dll": "1.0.0.1", "Windows/System32/zzz/v.dll": "2.0.0.0"}
        stored, _ = collect_pes.select_group(
            [rec(p, d) for p, d in zip(sorted(versions), "ab")],
            lambda r: {"file_version": versions[r.rel]})
        self.assertEqual(stored[0].rel, "Windows/System32/zzz/v.dll")

    def test_rank_beats_version(self):
        stored, _ = collect_pes.select_group(
            [rec("Windows/WinSxS/x/v.dll", "a", version="9.0.0.0"),
             rec("Windows/System32/v.dll", "b", version="1.0.0.0")], lambda r: {})
        self.assertEqual(stored[0].rel, "Windows/System32/v.dll")

    def test_result_does_not_depend_on_order(self):
        items = [("Windows/System32/a.dll", "a"), ("Windows/WinSxS/x/a.dll", "a"),
                 ("Windows/WinSxS/y/a.dll", "b"), ("Windows/WinSxS/z/a.dll", "c"),
                 ("Program Files/A/a.dll", "c")]
        expected = None
        for seed in range(6):
            shuffled = [rec(p, d, version="1.0.0.0") for p, d in items]
            random.Random(seed).shuffle(shuffled)
            stored, dups = collect_pes.select_group(shuffled, lambda r: {})
            got = ([(r.rel, r.canonical) for r in stored], sorted(dups))
            expected = expected or got
            self.assertEqual(got, expected)

    def test_collisions(self):
        records = [rec("Windows/System32/Foo.dll", "a"), rec("Windows/System32/foo.dll", "b"),
                   rec("Windows/System32/bar.dll", "c")]
        kept, collisions = collect_pes.find_collisions(records)
        self.assertEqual(sorted(r.rel for r in kept),
                         ["Windows/System32/Foo.dll", "Windows/System32/bar.dll"])
        self.assertEqual(collisions, [("Windows/System32/Foo.dll", "a" * 64,
                                       "Windows/System32/foo.dll", "b" * 64)])

    def test_hash_index_forgets_replaced_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x.dll")
            index = collect_pes.HashIndex()
            index.record("a" * 64, path, prefer=True)
            index.record("b" * 64, path, prefer=True)
            self.assertIsNone(index.get("a" * 64))
            self.assertEqual(index.get("b" * 64), os.path.normpath(path))

    def test_hash_index_skips_paths_outside_a_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = collect_pes.HashIndex()
            index.add_build({"../escape.dll": "a" * 64, "C:/x.dll": "b" * 64,
                             "Windows/ok.dll": "c" * 64}, tmp)
            self.assertEqual(list(index.by_digest), ["c" * 64])


class CollectTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="os-corpus-test-")
        self.root = Path(self._tmp.name)
        self.img = build_image(self.root / "img")
        self.out = self.root / "corpus" / "testbuild"
        self.report = self.root / "corpus" / "manifests" / "testbuild"

    def tearDown(self):
        shutil.rmtree(pelib.long_path(self._tmp.name, True), ignore_errors=True)
        self._tmp.cleanup()

    def collect(self, *extra, out=None, report=None, img=None):
        return run(COLLECT, img or self.img, out or self.out, "--report", report or self.report,
                   "--label", "testbuild", *extra)

    def summary(self, report=None):
        return json.loads(((report or self.report) / "summary.json").read_text(encoding="utf-8"))

    # -- what is stored ----------------------------------------------------

    def test_stores_every_distinct_content(self):
        result = self.collect()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("[+] collect: 9 files stored (8 modules, 1 variants)", result.stdout)
        for phase in ("[>] scanning ", "[>] selecting: 10 PEs in 8 (name, arch) groups",
                      "[>] placing 9 files (", "[>] writing reports to "):
            self.assertIn(phase, result.stdout)
        self.assertEqual(sorted(read_manifest(self.report)), STORED)

        summary = self.summary()
        self.assertEqual(summary["schema"], "os-corpus/summary/1")
        counts = summary["counts"]
        self.assertEqual((counts["pe_files"], counts["stored_files"], counts["distinct_modules"],
                          counts["variants"], counts["duplicate_paths"], counts["collisions"]),
                         (10, 9, 8, 1, 1, 0))
        self.assertEqual(summary["arch"], {"x64": 6, "x86": 2})
        self.assertEqual(summary["kinds"], {"dll": 6, "exe": 1, "native": 1, "resource": 1})
        self.assertEqual(summary["locations"], {"programfiles": 1, "system32": 5, "syswow64": 1,
                                                "windows": 1, "winsxs": 1})
        self.assertEqual(summary["bytes"]["stored_total"],
                         sum((self.out / rel).stat().st_size for rel in STORED))

        for rel in ("$Recycle.Bin", "Windows/SoftwareDistribution", "Windows/System32/notpe.dll",
                    "Windows/System32/edge.bin", "Windows/WinSxS/amd64_comp/a.dll"):
            self.assertFalse((self.out / rel).exists(), rel)
        self.assertEqual((self.out / "Windows/System32/a.dll").read_bytes(), pe_bytes(marker=b"A"))

    def test_reports(self):
        self.collect()
        header, modules = read_tsv(self.report / "modules.tsv")
        self.assertEqual(tuple(header), collect_pes.MODULES_HEADER)
        by_path = {m["path"]: m for m in modules}
        self.assertEqual(sorted(by_path), STORED)
        self.assertEqual(by_path["Windows/System32/b.dll"]["canonical"], "1")
        self.assertEqual(by_path["Windows/WinSxS/amd64_comp/b.dll"]["canonical"], "0")
        self.assertEqual(by_path["Windows/WinSxS/amd64_comp/b.dll"]["location"], "winsxs")
        self.assertEqual(by_path["Windows/System32/en-US/a.dll.mui"]["kind"], "resource")
        self.assertEqual(by_path["Windows/System32/drivers/x.sys"]["kind"], "native")
        self.assertEqual(by_path["Windows/System32/drivers/x.sys"]["subsystem"], "native")
        net = by_path["Windows/Microsoft.NET/Framework/v4.0.30319/System.dll"]
        self.assertEqual((net["clr"], net["arch"], net["machine"]), ("1", "x86", "0x014c"))
        self.assertEqual(by_path["Program Files/App/tool.exe"]["kind"], "exe")

        header, duplicates = read_tsv(self.report / "duplicates.tsv")
        self.assertEqual(tuple(header), collect_pes.DUPLICATES_HEADER)
        self.assertEqual([(d["kept"], d["duplicate"]) for d in duplicates],
                         [("Windows/System32/a.dll", "Windows/WinSxS/amd64_comp/a.dll")])

        header, collisions = read_tsv(self.report / "collisions.tsv")
        self.assertEqual((tuple(header), collisions), (collect_pes.COLLISIONS_HEADER, []))

    def test_version_decides_within_one_location(self):
        img = self.root / "img2"
        write_pe(img / "Windows/System32/aaa/v.dll", marker=b"1", version=(1, 0, 0, 1))
        write_pe(img / "Windows/System32/zzz/v.dll", marker=b"2", version=(2, 0, 0, 0))
        result = self.collect(img=img)
        self.assertEqual(result.returncode, 0, output(result))
        _, modules = read_tsv(self.report / "modules.tsv")
        canonical = [(m["path"], m["file_version"]) for m in modules if m["canonical"] == "1"]
        self.assertEqual(canonical, [("Windows/System32/zzz/v.dll", "2.0.0.0")])

    def test_phases_are_recorded_in_run_order(self):
        result = self.collect()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual([name for name, _ in self.summary()["phases"]],
                         ["scan", "select", "place", "reports"])
        self.assertIn("[i] time              scan ", result.stdout)

    def test_jobs_do_not_change_the_result(self):
        names = ("manifest.sha256", "modules.tsv", "duplicates.tsv", "collisions.tsv")
        reports = {}
        for jobs in ("1", "4"):
            out = self.root / "corpus" / ("jobs" + jobs)
            report = self.root / "corpus" / "manifests" / ("jobs" + jobs)
            result = run(COLLECT, self.img, out, "--report", report, "--link-root", "none",
                         "--jobs", jobs)
            self.assertEqual(result.returncode, 0, output(result))
            self.assertIn("[i] jobs     %s" % jobs, result.stdout)
            reports[jobs] = {n: (report / n).read_bytes() for n in names}
        self.assertEqual(reports["1"], reports["4"])
        self.assertEqual(run(COLLECT, self.img, self.out, "--jobs", "0").returncode, 2)

    def _tamper_cache(self, header=None):
        """Set the cached file version of System32/a.dll to 9.9.9.9 (and optionally the header)."""
        path = self.report / "scan-cache.tsv"
        lines = path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[0], "#\tos-corpus/scan-cache/2\tinfo/%d" % pelib.INFO_VERSION)
        if header:
            lines[0] = header
        for i, line in enumerate(lines):
            fields = line.split("\t")
            if fields[-1] == "Windows/System32/a.dll":
                info = json.loads(fields[4])
                info["file_version"] = "9.9.9.9"
                fields[4] = json.dumps(info, sort_keys=True, separators=(",", ":"))
                lines[i] = "\t".join(fields)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    def a_dll_version(self):
        _, modules = read_tsv(self.report / "modules.tsv")
        return next(m["file_version"] for m in modules if m["path"] == "Windows/System32/a.dll")

    def test_resume_reuses_cached_module_info(self):
        self.collect()
        self._tamper_cache()
        result = self.collect("--resume")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("reading versions of 0 (9 cached)", result.stdout)
        self.assertIn("(0 hashed, 10 reused)", result.stdout)
        self.assertEqual(self.a_dll_version(), "9.9.9.9")

    def test_cache_of_another_info_version_is_not_trusted(self):
        self.collect()
        self._tamper_cache(header="#\tos-corpus/scan-cache/2\tinfo/0")
        result = self.collect("--resume")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("reading versions of 9 (0 cached)", result.stdout)
        self.assertEqual(self.a_dll_version(), "")

    def test_identical_bytes_are_linked(self):
        self.collect()
        self.assertTrue(same_file(self.out / "Windows/System32/a.dll",
                                  self.out / "Windows/System32/dup.dll"))

    def test_arch_filter(self):
        result = self.collect("--arch", "x64")
        self.assertEqual(result.returncode, 0, output(result))
        rows = read_manifest(self.report)
        self.assertNotIn("Windows/SysWOW64/a.dll", rows)
        self.assertEqual(len(rows), 7)

    # -- runs and re-runs --------------------------------------------------

    def test_dry_run_writes_nothing(self):
        out = self.root / "corpus" / "dry"
        report = self.root / "corpus" / "manifests" / "dry"
        result = run(COLLECT, self.img, out, "--report", report, "--link-root", "none", "--dry-run")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("dry run, nothing written", result.stdout)
        self.assertFalse(out.exists())
        self.assertFalse(report.exists())

    def test_refuses_nonempty_output(self):
        self.collect()
        second = self.collect()
        self.assertEqual(second.returncode, 2)
        self.assertIn("[!] collect: output is not empty", second.stderr)

    def test_resume_is_byte_identical(self):
        self.collect()
        names = ("manifest.sha256", "modules.tsv", "duplicates.tsv", "collisions.tsv")
        first = {n: (self.report / n).read_bytes() for n in names}
        result = self.collect("--resume")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual({n: (self.report / n).read_bytes() for n in names}, first)
        self.assertIn("9 already in place", result.stdout)
        self.assertIn("[=] modules.tsv unchanged", result.stdout)

    def test_second_build_reuses_bytes(self):
        self.collect()
        other = self.root / "corpus" / "second"
        result = self.collect(out=other, report=self.root / "corpus" / "manifests" / "second")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue(same_file(other / "Windows/System32/b.dll",
                                  self.out / "Windows/System32/b.dll"))
        self.assertIn("(1 other build(s), 8 contents indexed)", result.stdout)
        self.assertEqual(self.summary(self.root / "corpus" / "manifests" / "second")["corpus"],
                         "second")

    def test_links_survive_moving_the_root(self):
        self.collect()
        moved = self.root / "moved"
        os.rename(self.root / "corpus", moved)
        result = run(COLLECT, self.img, moved / "second")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue(same_file(moved / "second/Windows/System32/b.dll",
                                  moved / "testbuild/Windows/System32/b.dll"))

    def test_report_named_otherwise_is_still_found(self):
        # The wrapper names the report after -Label, which may differ from the corpus folder.
        first = self.root / "corpus" / "b1"
        self.collect(out=first, report=self.root / "corpus" / "manifests" / "custom")
        result = run(COLLECT, self.img, self.root / "corpus" / "b2")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertTrue(same_file(self.root / "corpus/b2/Windows/System32/b.dll",
                                  first / "Windows/System32/b.dll"))

    def test_link_root_none_links_within_the_build_only(self):
        self.collect()
        other = self.root / "corpus" / "second"
        result = run(COLLECT, self.img, other, "--link-root", "none")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("[i] link     none", result.stdout)
        self.assertFalse(same_file(other / "Windows/System32/b.dll",
                                   self.out / "Windows/System32/b.dll"))
        self.assertTrue(same_file(other / "Windows/System32/a.dll",
                                  other / "Windows/System32/dup.dll"))

    def test_obsolete_index_file_is_reported_not_deleted(self):
        old = self.root / "corpus" / ".hash-index.tsv"
        old.parent.mkdir(parents=True)
        old.write_text("", encoding="utf-8")
        result = self.collect()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn(".hash-index.tsv is no longer used", result.stdout)
        self.assertTrue(old.exists())

    def test_rewrite_never_touches_another_build(self):
        self.collect()
        original = (self.out / "Windows/System32/b.dll").read_bytes()
        # A second build whose b.dll is hardlinked to the first build's, then rebuilt from an
        # image whose b.dll changed. The new bytes must replace the link, not write through it.
        other = self.root / "corpus" / "second"
        (other / "Windows/System32").mkdir(parents=True)
        os.link(self.out / "Windows/System32/b.dll", other / "Windows/System32/b.dll")
        write_pe(self.img / "Windows/System32/b.dll", marker=b"B3")
        result = self.collect("--force", out=other, report=self.root / "corpus" / "manifests" / "second")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual((self.out / "Windows/System32/b.dll").read_bytes(), original)
        self.assertEqual((other / "Windows/System32/b.dll").read_bytes(), pe_bytes(marker=b"B3"))

    def test_stale_files_are_reported(self):
        self.collect()
        (self.out / "Windows/System32/old.dll").write_bytes(pe_bytes(marker=b"O"))
        result = self.collect("--resume")
        self.assertEqual(result.returncode, 0, output(result))
        self.assertIn("[~] 1 file(s) in the output are not in the manifest", result.stdout)
        self.assertEqual(self.summary()["counts"]["stale_files"], 1)
        self.assertTrue((self.out / "Windows/System32/old.dll").exists())

    def test_no_pe_is_an_error(self):
        empty = self.root / "empty"
        empty.mkdir()
        result = self.collect(img=empty)
        self.assertEqual(result.returncode, 1)
        self.assertIn("no PE files found", result.stderr)

    def test_skips_symlink_loop(self):
        loop = self.img / "Windows/System32/loop"
        try:
            os.symlink(str(self.img / "Windows"), str(loop), target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available")
        result = self.collect()
        self.assertEqual(result.returncode, 0, output(result))
        self.assertEqual(sorted(read_manifest(self.report)), STORED)

    def test_deep_path_is_collected(self):
        img = self.root / "deep-img"
        deep = img
        for index in range(24):
            deep = deep / ("component_%02d" % index)
        try:
            os.makedirs(pelib.long_path(str(deep), True), exist_ok=True)
        except OSError as exc:
            self.skipTest("cannot create deep paths: %s" % exc)
        target = deep / "deep.dll"
        with open(pelib.long_path(str(target), True), "wb") as handle:
            handle.write(pe_bytes(marker=b"D"))
        self.assertGreater(len(str(target)), 260)

        result = self.collect(img=img)
        self.assertEqual(result.returncode, 0, output(result))
        rows = read_manifest(self.report)
        self.assertEqual(len(rows), 1)
        self.assertTrue(next(iter(rows)).endswith("deep.dll"))


if __name__ == "__main__":
    unittest.main()
