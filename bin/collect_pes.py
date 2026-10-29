#!/usr/bin/env python3
"""
collect_pes.py: builds a PE corpus from a mounted Windows image or any extracted tree, plus the
evidence that proves what was collected. Mounting is extract-image.ps1's job; this script only
ever sees a directory.

    python collect_pes.py <image-dir> <out-dir>                 collect into <out-dir>
    python collect_pes.py <image-dir> <out-dir> --dry-run       scan and print the counts, write nothing
    python collect_pes.py <image-dir> <out-dir> --resume        continue an interrupted run
    python collect_pes.py <image-dir> <out-dir> --arch x64,x86  keep only these architectures
    python collect_pes.py <image-dir> <out-dir> --jobs 4        hash 4 files at a time

Input
    Every file under <image-dir> whose header is a valid PE (pelib.py), whatever its extension.
    Volatile OS locations (DEFAULT_EXCLUDES) are skipped unless --no-default-excludes.

Selection
    PEs are grouped by (lowercased file name, architecture).
    - Identical bytes in a group are stored once, at the best-ranked path; every other path is a
      row of duplicates.tsv.
    - Different bytes in a group are all stored, each at its own path. The best of them by
      location rank, then highest file version, then path, is canonical=1 in modules.tsv; the
      others are variants (canonical=0).
    - One path found twice, compared without regard to case (only possible on a case-sensitive
      source), is a collision: the first in exact path order is stored, the others are rows of
      collisions.tsv.

Output
    <out>/<image path>                  every stored file, hardlinked when another completed build
                                        under the link root (default <out>/..) has the same bytes
    <report>/manifest.sha256            sha256sum format, one line per stored file; written last
    <report>/modules.tsv                one row per stored file, with its classification
    <report>/duplicates.tsv             paths not stored because their bytes are stored elsewhere
    <report>/collisions.tsv             paths found twice
    <report>/summary.json               counts, bytes, histograms, options, phase times
    <report>/scan-cache.tsv             resume accelerator (digests and module info), not evidence
    <report> defaults to <out>/../manifests/<out-name>. USAGE.md has every column.

Exit code 0 on success, 1 on an error, 2 on bad usage, 3 when collisions.tsv is not empty
(unless --allow-collisions), 130 when interrupted.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import shutil
import sys
import time
from collections import namedtuple
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pelib  # noqa: E402

# ---- CONFIG ----

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_COLLISIONS = 3
EXIT_INTERRUPTED = 130

SUMMARY_SCHEMA = "os-corpus/summary/1"
CACHE_SCHEMA = "os-corpus/scan-cache/2"

# Report columns. verify_corpus.py keeps its own copy on purpose; the tests check they agree.
MODULES_HEADER = ("name", "arch", "canonical", "kind", "location", "format", "machine", "dll",
                  "clr", "embedded_signature", "subsystem", "file_version", "product_version",
                  "size", "sha256", "path")
DUPLICATES_HEADER = ("name", "arch", "sha256", "kept", "duplicate")
COLLISIONS_HEADER = ("path", "sha256", "other", "other_sha256")

REPORT_SCHEMAS = {
    "modules.tsv": "os-corpus/modules/1",
    "duplicates.tsv": "os-corpus/duplicates/1",
    "collisions.tsv": "os-corpus/collisions/1",
}

# pe_info fields a modules.tsv row and the selection need; scan-cache.tsv keeps them per stored
# file, so a resumed run does not read every version resource again.
CACHE_INFO_KEYS = ("magic", "machine", "dll", "clr", "embedded_signature", "subsystem", "kind",
                   "file_version", "product_version")

# Location classes, most authoritative first; a file's rank is its index here.
LOCATIONS = ("system32", "syswow64", "systemapps", "programfiles", "winsxs", "driverstore",
             "windows", "other")

# Volatile or non-runtime locations. A pattern matches a path, or a directory and everything
# under it when it ends in "/**". Matching is case-insensitive.
DEFAULT_EXCLUDES = (
    "$Recycle.Bin/**",
    "**/$Recycle.Bin/**",
    "System Volume Information/**",
    "**/System Volume Information/**",
    "**/Windows/WinSxS/Temp/**",
    "**/Windows/WinSxS/Backup/**",
    "**/Windows/SoftwareDistribution/**",
    "**/Windows/servicing/LCU/**",
    "**/Windows/Prefetch/**",
    "**/Windows/Temp/**",
    "**/Windows/Logs/**",
    "**/Windows/Minidump/**",
    "**/pagefile.sys",
    "**/hiberfil.sys",
    "**/swapfile.sys",
)

# Earlier versions kept the link index in this file under the corpus root; it is now rebuilt from
# the manifests, and a leftover copy is only reported.
OBSOLETE_INDEX = ".hash-index.tsv"

# Suffix of the temporary name a file is written under before it is renamed into place.
TMP_SUFFIX = ".os-corpus-tmp"

MAX_SHOWN = 20


# ---- OUTPUT ----

class Log:
    def __init__(self, quiet):
        self.quiet = quiet

    def step(self, message):
        if not self.quiet:
            print("[>] %s" % message)

    def info(self, message):
        if not self.quiet:
            print("[i] %s" % message)

    def done(self, message):
        if not self.quiet:
            print("[+] %s" % message)

    def same(self, message):
        if not self.quiet:
            print("[=] %s" % message)

    def removed(self, message):
        if not self.quiet:
            print("[-] %s" % message)

    def skip(self, message):
        print("[~] %s" % message)


def fail(message, code=EXIT_ERROR):
    sys.stdout.flush()  # keep stdout lines ahead of the error in a shared log
    print("[!] collect: %s" % message, file=sys.stderr)
    return code


byte_string = pelib.byte_string


# ---- PATHS ----

def lp(path):
    return pelib.long_path(path, True)


def to_native(root, rel):
    return os.path.join(root, rel.replace("/", os.sep))


def is_excluded(rel, is_dir, patterns):
    """True when a path (already lowercased, forward slashes) is excluded.

    Patterns are matched as if anchored anywhere, so ``**/Windows/Temp/**`` covers a tree that
    starts at ``Windows`` as well as one nested deeper.
    """
    candidates = (rel, "/" + rel)
    for pattern in patterns:
        body = pattern[:-3] if pattern.endswith("/**") else None
        for candidate in candidates:
            if fnmatch.fnmatchcase(candidate, pattern):
                return True
            if is_dir and body and fnmatch.fnmatchcase(candidate, body):
                return True
    return False


def location(rel):
    """The location class of an image path (see LOCATIONS)."""
    p = rel.lower()
    if "/driverstore/" in p or p.startswith("driverstore/"):
        return "driverstore"
    if p.startswith("windows/system32/"):
        return "system32"
    if p.startswith("windows/syswow64/"):
        return "syswow64"
    if p.startswith("windows/systemapps/"):
        return "systemapps"
    if p.startswith("program files"):
        return "programfiles"
    if p.startswith("windows/winsxs/"):
        return "winsxs"
    if p.startswith("windows/"):
        return "windows"
    return "other"


def rank(rel):
    """Where a file lives, from most (0) to least authoritative."""
    return LOCATIONS.index(location(rel))


def is_nonempty_dir(path):
    try:
        with os.scandir(lp(path)) as it:
            return any(True for _ in it)
    except OSError:
        return False


def inside(child, parent):
    child = os.path.normcase(os.path.abspath(child))
    parent = os.path.normcase(os.path.abspath(parent))
    try:
        return os.path.commonpath([child, parent]) == parent
    except ValueError:
        return False


def unlink_quiet(path):
    try:
        os.unlink(lp(path))
    except OSError:
        pass


# ---- RECORDS ----

@dataclass
class Record:
    rel: str
    name: str
    arch: str
    size: int
    digest: str
    location: str
    info: Optional[dict] = None    # pe_info of the source; loaded (or cached) for stored files
    canonical: bool = False

    @property
    def rank(self):
        return LOCATIONS.index(self.location)

    @property
    def key(self):
        return (self.name.lower(), self.arch)


def make_record(rel, size, digest, arch):
    return Record(rel=rel, name=rel.rsplit("/", 1)[-1], arch=arch, size=size, digest=digest,
                  location=location(rel))


# One scan-cache.tsv row; info is the CACHE_INFO_KEYS subset of pe_info, or None.
CacheEntry = namedtuple("CacheEntry", "digest arch size mtime info")


def cache_info(info):
    return {k: info[k] for k in CACHE_INFO_KEYS if k in info} if info else None


# ---- SMALL FILES ----

def read_manifest(path):
    rows = {}
    try:
        with open(lp(path), "r", encoding="utf-8") as f:
            for line in f:
                digest, sep, rel = line.rstrip("\n").partition("  ")
                if sep and len(digest) == 64 and rel:
                    rows[rel] = digest
    except OSError:
        return {}
    return rows


def read_cache(path):
    """{rel: CacheEntry}. Module info is used only when the header names this cache schema and
    the current pelib.INFO_VERSION; digests are always usable (5-column rows of an older cache
    included)."""
    cache = {}
    info_valid = False
    try:
        with open(lp(path), "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#"):
                    info_valid = line.split("\t")[1:] == [CACHE_SCHEMA, "info/%d" % pelib.INFO_VERSION]
                    continue
                parts = line.split("\t")
                if len(parts) == 5:
                    digest, arch, size, mtime, rel = parts
                    info = ""
                elif len(parts) == 6:
                    digest, arch, size, mtime, info, rel = parts
                else:
                    continue
                try:
                    cache[rel] = CacheEntry(digest, arch, int(size), int(mtime),
                                            json.loads(info) if info and info_valid else None)
                except ValueError:
                    continue
    except OSError:
        pass
    return cache


def render_cache(entries):
    lines = ["#\t%s\tinfo/%d" % (CACHE_SCHEMA, pelib.INFO_VERSION)]
    for rel in sorted(entries):
        e = entries[rel]
        info = json.dumps(e.info, sort_keys=True, separators=(",", ":")) if e.info else ""
        lines.append("\t".join((e.digest, e.arch, str(e.size), str(e.mtime), info, rel)))
    return "\n".join(lines) + "\n"


def read_json(path):
    try:
        with open(lp(path), "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


class HashIndex:
    """digest -> path of a stored copy, for hardlinking instead of copying.

    Nothing is saved: the index is rebuilt at the start of every run from the manifests of the
    completed builds under the link root (<out>/..), so it cannot go stale, survives moving the
    root, and needs no file of its own. A manifest exists only for a completed run and lists the
    tree that run left. Within the run, storing other bytes at a path forgets whatever digest the
    index had placed there, so a file whose content was replaced is never linked to.
    """

    def __init__(self):
        self.by_digest = {}
        self.by_path = {}

    def add_build(self, rows, build):
        """Index one build: ``rows`` is {rel: digest} from its manifest, ``build`` its corpus
        directory. The first build to know a digest keeps it."""
        for rel in sorted(rows):
            if rel.startswith(("/", "\\")) or ":" in rel or ".." in rel.split("/"):
                continue
            digest = rows[rel]
            if digest not in self.by_digest:
                path = os.path.normpath(to_native(build, rel))
                self.by_digest[digest] = path
                self.by_path[self._key(path)] = digest

    def add_root(self, root, out):
        """Index every other completed build under ``root``: each manifests/<report>/ whose
        manifest.sha256 exists, joined with the corpus directory its summary.json names (the
        report's own name when it names none). Returns the number of builds added."""
        manifests = os.path.join(root, "manifests")
        try:
            names = sorted(os.listdir(lp(manifests)))
        except OSError:
            return 0
        added = 0
        for name in names:
            report = os.path.join(manifests, name)
            rows = read_manifest(os.path.join(report, "manifest.sha256"))
            if not rows:
                continue
            corpus = (read_json(os.path.join(report, "summary.json")) or {}).get("corpus") or name
            if not isinstance(corpus, str) or os.path.basename(corpus) != corpus or corpus in (".", ".."):
                continue
            build = os.path.join(root, corpus)
            if self._key(build) == self._key(out) or not os.path.isdir(lp(build)):
                continue
            self.add_build(rows, build)
            added += 1
        return added

    @staticmethod
    def _key(path):
        return os.path.normcase(os.path.normpath(path)) if path else ""

    def __contains__(self, digest):
        return digest in self.by_digest

    def __len__(self):
        return len(self.by_digest)

    def get(self, digest):
        return self.by_digest.get(digest)

    def record(self, digest, stored, prefer=False):
        """``stored`` now holds ``digest``. With ``prefer`` it becomes the copy later runs link
        to; otherwise only when the index knows no copy yet."""
        key = self._key(stored)
        old = self.by_path.get(key)
        if old is not None and old != digest and self._key(self.by_digest.get(old)) == key:
            del self.by_digest[old]
        self.by_path[key] = digest
        if prefer or digest not in self.by_digest:
            self.by_digest[digest] = os.path.normpath(stored)


def write_if_changed(path, text):
    """Write UTF-8 text through a temporary file and a rename. Returns False when the file
    already held exactly this text, which is then left untouched (timestamp included)."""
    data = text.encode("utf-8")
    try:
        with open(lp(path), "rb") as f:
            if f.read() == data:
                return False
    except OSError:
        pass
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(lp(parent), exist_ok=True)
    tmp = path + TMP_SUFFIX
    with open(lp(tmp), "wb") as f:
        f.write(data)
    os.replace(lp(tmp), lp(path))
    return True


def render_tsv(header, rows):
    def cell(value):
        return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")
    lines = ["\t".join(header)]
    lines += ["\t".join(cell(v) for v in row) for row in rows]
    return "\n".join(lines) + "\n"


def render_manifest(rows):
    return "".join("%s  %s\n" % (digest, rel) for digest, rel in sorted(rows, key=lambda r: r[1]))


# ---- SCAN ----

def scan(image, excludes, arch_filter, cache, rehash, jobs, log):
    """Walk the source; sniff and hash new files on ``jobs`` threads.

    Returns (records, new_cache, counts, unusable). A file whose size and mtime match the scan
    cache, or that is a hardlink of a file already seen in this run, is not read again.
    """
    root = lp(image)
    records = []
    unusable = []
    new_cache = {}
    by_inode = {}
    counts = {"files_seen": 0, "pruned": 0, "hashed": 0, "reused": 0,
              "pe_bytes": 0, "hashed_bytes": 0}
    progress = pelib.Progress(not log.quiet)

    def render():
        line = "scan: %d files, %d PE (%s)" % (counts["files_seen"], len(records),
                                              byte_string(counts["pe_bytes"]))
        if counts["reused"]:
            line += ", %d reused" % counts["reused"]
        if counts["hashed_bytes"]:
            rate = counts["hashed_bytes"] / max(progress.elapsed(), 0.001)
            line += ", hashing %s/s" % byte_string(rate)
        return line

    def candidates():
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
            rel_dir = "" if rel_dir == "." else rel_dir

            kept = []
            for d in dirnames:
                if is_excluded(("%s/%s" % (rel_dir, d)).lstrip("/").lower(), True, excludes):
                    counts["pruned"] += 1
                else:
                    kept.append(d)
            dirnames[:] = kept

            for name in filenames:
                rel = ("%s/%s" % (rel_dir, name)).lstrip("/")
                if is_excluded(rel.lower(), False, excludes):
                    counts["pruned"] += 1
                    continue
                counts["files_seen"] += 1
                path = os.path.join(dirpath, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if st.st_size < 0x40:
                    continue
                known = by_inode.get((st.st_dev, st.st_ino)) if st.st_ino else None
                if known is None and not rehash:
                    cached = cache.get(rel)
                    if cached and (cached.size, cached.mtime) == (st.st_size, st.st_mtime_ns):
                        known = cached
                yield rel, path, st, known

    def examine(candidate):
        """(CacheEntry, hashed) for a PE, None otherwise. Runs on a worker thread."""
        rel, path, st, known = candidate
        if known is not None:
            return known, False
        info = pelib.sniff_bytes(pelib.read_head(path), st.st_size)
        if info is None:
            return None
        try:
            digest = pelib.sha256_file(path)
        except OSError:
            return None
        return CacheEntry(digest, info["arch"], st.st_size, st.st_mtime_ns, None), True

    for (rel, path, st, _), result in pelib.ordered_map(examine, candidates(), jobs):
        progress.tick(render)
        if result is None:
            continue
        entry, hashed = result
        if hashed:
            counts["hashed"] += 1
            counts["hashed_bytes"] += st.st_size
        else:
            counts["reused"] += 1
        if st.st_ino:
            by_inode[(st.st_dev, st.st_ino)] = entry
        new_cache[rel] = entry._replace(size=st.st_size, mtime=st.st_mtime_ns)

        if any(c in rel for c in "\t\r\n"):
            unusable.append(rel)
            continue
        if arch_filter and entry.arch not in arch_filter:
            continue
        rec = make_record(rel, st.st_size, entry.digest, entry.arch)
        rec.info = dict(entry.info) if entry.info else None
        records.append(rec)
        counts["pe_bytes"] += st.st_size

    progress.clear()
    counts["seconds"] = progress.elapsed()
    log.info("scanned %d files, %d PE, %s in %s (%d hashed, %d reused)" % (
        counts["files_seen"], len(records), byte_string(counts["pe_bytes"]),
        pelib.duration(counts["seconds"]), counts["hashed"], counts["reused"]))
    return records, new_cache, counts, unusable


# ---- SELECTION ----

def find_collisions(records):
    """Split off paths found twice without regard to case. Returns (kept, collision rows); the
    first record of a path in exact order is kept."""
    by_path = {}
    for rec in records:
        by_path.setdefault(rec.rel.lower(), []).append(rec)
    kept = []
    collisions = []
    for key in sorted(by_path):
        same = sorted(by_path[key], key=lambda r: r.rel)
        kept.append(same[0])
        for other in same[1:]:
            collisions.append((same[0].rel, same[0].digest, other.rel, other.digest))
    return kept, collisions


def _path_order(rec):
    return (rec.rank, rec.rel.lower(), rec.rel)


def _canonical_order(rec):
    version = pelib.version_tuple(rec.info.get("file_version", ""))
    return (rec.rank, tuple(-x for x in version), rec.rel.lower(), rec.rel)


def split_duplicates(items):
    """Identical bytes of one (name, arch) group stored once, at the best-ranked path.
    Returns (stored, duplicate rows). Needs no file access."""
    by_digest = {}
    for rec in items:
        by_digest.setdefault(rec.digest, []).append(rec)
    stored = []
    duplicates = []
    for digest in sorted(by_digest):
        copies = sorted(by_digest[digest], key=_path_order)
        keep = copies[0]
        stored.append(keep)
        for other in copies[1:]:
            duplicates.append((keep.name, keep.arch, digest, keep.rel, other.rel))
    return stored, duplicates


def mark_canonical(stored):
    """Sort one group's stored records best first and mark the first canonical. Every record
    needs its info (the file version) loaded."""
    stored.sort(key=_canonical_order)
    for i, rec in enumerate(stored):
        rec.canonical = i == 0


def select_group(items, load_info):
    """Choose what to store from one (name, arch) group.

    Returns (stored, duplicate rows). Identical bytes are stored once, at the best-ranked path.
    Every distinct content is stored; the best one is marked canonical. ``load_info(record)``
    returns the pe_info of a record and is called once per stored record without info. The
    result depends on the records and their bytes only, never on the order they were found in.
    """
    stored, duplicates = split_duplicates(items)
    for rec in stored:
        if rec.info is None:
            rec.info = load_info(rec) or {}
    mark_canonical(stored)
    return stored, duplicates


# ---- PLACEMENT ----

def _is_current(dest, digest, size, index, previous_digest):
    """True when dest already holds digest: it has the right size and either the previous
    manifest listed it with this digest or it is the same file as the index's copy."""
    try:
        if os.path.getsize(lp(dest)) != size:
            return False
    except OSError:
        return False
    if previous_digest == digest:
        return True
    stored = index.get(digest)
    if not stored:
        return False
    try:
        return os.path.samefile(lp(stored), lp(dest))
    except OSError:
        return False


def place(src, dest, digest, size, index, allow_link, previous_digest):
    """Copy, hardlink or keep one stored file. Returns (action, bytes copied).

    Nothing is ever written into an existing file. New content is written under a temporary
    name and renamed over dest, so a dest that is a hardlink shared with another build is
    replaced, and the other build keeps its bytes.
    """
    if _is_current(dest, digest, size, index, previous_digest):
        index.record(digest, dest)
        return "skip", 0

    os.makedirs(lp(os.path.dirname(dest)), exist_ok=True)
    tmp = dest + TMP_SUFFIX
    unlink_quiet(tmp)

    prev = index.get(digest)
    if allow_link and prev and HashIndex._key(prev) != HashIndex._key(dest):
        try:
            if os.path.getsize(lp(prev)) == size:
                os.link(lp(prev), lp(tmp))
                os.replace(lp(tmp), lp(dest))
                index.record(digest, dest)
                return "link", 0
        except OSError:
            unlink_quiet(tmp)

    shutil.copyfile(lp(src), lp(tmp))
    os.replace(lp(tmp), lp(dest))
    index.record(digest, dest, prefer=True)
    return "copy", size


def find_stale(out, stored_rels):
    """Files under out that the new manifest does not list. Leftover temporary files of this
    tool are removed instead of reported."""
    root = lp(out)
    wanted = set(stored_rels)
    stale = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if name.endswith(TMP_SUFFIX):
                unlink_quiet(path)
                continue
            rel = os.path.relpath(path, root).replace("\\", "/")
            if rel not in wanted:
                stale.append(rel)
    return stale


# ---- REPORTS ----

def module_row(rec):
    info = rec.info or {}
    subsystem = info.get("subsystem")
    machine = info.get("machine")
    return (
        rec.name, rec.arch, int(rec.canonical), info.get("kind", ""), rec.location,
        info.get("magic", ""), "" if machine is None else "0x%04x" % machine,
        int(bool(info.get("dll"))), int(bool(info.get("clr"))),
        int(bool(info.get("embedded_signature"))),
        pelib.SUBSYSTEMS.get(subsystem, "" if subsystem is None else str(subsystem)),
        info.get("file_version", ""), info.get("product_version", ""),
        rec.size, rec.digest, rec.rel,
    )


def histogram(values):
    counts = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def phase_line(phases):
    return ", ".join("%s %s" % (name, pelib.duration(seconds)) for name, seconds in phases.items())


# ---- MAIN ----

def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="collect_pes.py",
        description="Build a PE corpus from a mounted Windows image or an extracted tree.")
    ap.add_argument("image", help="directory to scan (a mount point or a tree)")
    ap.add_argument("out", help="corpus directory; stored files keep their image path inside it")
    ap.add_argument("--report", default="",
                    help="evidence directory (default: <out>/../manifests/<out-name>)")
    ap.add_argument("--link-root", default="", metavar="DIR",
                    help="corpus root whose other builds are hardlinked to (default: <out>/..; "
                         "'none' links only within this build)")
    ap.add_argument("--label", default="", help="name recorded in summary.json (default: out name)")
    ap.add_argument("--resume", action="store_true",
                    help="reuse scan-cache.tsv and keep files already in place")
    ap.add_argument("--rehash", action="store_true",
                    help="ignore the scan cache even with --resume")
    ap.add_argument("--dry-run", action="store_true", help="scan and print the counts, write nothing")
    ap.add_argument("--no-link", action="store_true", help="always copy, never hardlink")
    ap.add_argument("--arch", default="", help="comma separated architecture filter, e.g. x64,x86")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="additional exclusion pattern (repeatable)")
    ap.add_argument("--no-default-excludes", action="store_true",
                    help="do not skip the volatile OS locations")
    ap.add_argument("--allow-collisions", action="store_true",
                    help="exit 0 even when collisions.tsv is not empty")
    ap.add_argument("--force", action="store_true", help="allow a non-empty output directory")
    ap.add_argument("--jobs", type=int, default=pelib.default_jobs(), metavar="N",
                    help="files read and hashed in parallel (default: CPU count, at most %d)"
                    % pelib.MAX_DEFAULT_JOBS)
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="print only warnings, errors and the closing line")
    ap.add_argument("--version", action="version", version="os-corpus %s" % pelib.VERSION)
    return ap.parse_args(argv)


def default_report(out):
    parent = os.path.dirname(os.path.abspath(out))
    return os.path.join(parent, "manifests", os.path.basename(os.path.abspath(out)))


def default_link_root(out):
    return os.path.dirname(os.path.abspath(out))


def main(argv=None):
    # Line by line even into a pipe (extract-image.ps1, a log file), so progress is never held
    # back in a buffer.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        return fail("interrupted: no manifest written; re-run with --resume", EXIT_INTERRUPTED)


def run(args):
    log = Log(args.quiet)
    image = os.path.abspath(args.image)
    out = os.path.abspath(args.out)

    if args.jobs < 1:
        return fail("--jobs must be at least 1", EXIT_USAGE)
    if not os.path.isdir(lp(image)):
        return fail("source is not a directory: %s" % image, EXIT_USAGE)
    if inside(out, image) or inside(image, out):
        return fail("source and output must not contain each other; put the corpus in a "
                    "separate folder tree", EXIT_USAGE)
    if os.path.exists(lp(out)) and not os.path.isdir(lp(out)):
        return fail("output exists and is not a directory: %s" % out, EXIT_USAGE)
    if is_nonempty_dir(out) and not (args.resume or args.force or args.dry_run):
        return fail("output is not empty: %s; pass --resume to continue a run, or --force to "
                    "add to it" % out, EXIT_USAGE)

    report = os.path.abspath(args.report) if args.report else default_report(out)
    if inside(report, out):
        return fail("report directory must be outside the corpus: %s" % report, EXIT_USAGE)

    link_root = args.link_root
    if link_root.lower() == "none":
        link_root = ""
    else:
        link_root = os.path.abspath(link_root) if link_root else default_link_root(out)

    patterns = [p.replace("\\", "/").lower() for p in args.exclude]
    if not args.no_default_excludes:
        patterns = [p.lower() for p in DEFAULT_EXCLUDES] + patterns
    arch_filter = {a.strip().lower() for a in args.arch.split(",") if a.strip()}

    started = time.time()
    phases = {}
    manifest_path = os.path.join(report, "manifest.sha256")
    cache = read_cache(os.path.join(report, "scan-cache.tsv")) if args.resume else {}
    previous = read_manifest(manifest_path) if args.resume else {}
    # This build's last completed run first, then every other build under the link root.
    index = HashIndex()
    index.add_build(read_manifest(manifest_path), out)
    builds = index.add_root(link_root, out) if link_root else 0

    log.info("source   %s" % image)
    log.info("output   %s" % out)
    log.info("report   %s" % report)
    if link_root:
        log.info("link     %s (%d other build(s), %d contents indexed)" % (link_root, builds, len(index)))
    else:
        log.info("link     none: identical bytes are linked within this build only")
    obsolete = os.path.join(link_root, OBSOLETE_INDEX) if link_root else ""
    if obsolete and os.path.exists(lp(obsolete)):
        log.skip("%s is no longer used (the link index is rebuilt from the manifests); it can "
                 "be deleted" % obsolete)
    log.info("jobs     %d" % args.jobs)
    if args.resume:
        log.info("resume   %d cached PEs (%d with module info), %d manifest rows" % (
            len(cache), sum(1 for e in cache.values() if e.info), len(previous)))

    log.step("scanning %s" % image)
    records, new_cache, scanned, unusable = scan(
        image, patterns, arch_filter, cache, args.rehash or not args.resume, args.jobs, log)
    phases["scan"] = scanned["seconds"]
    for rel in unusable[:MAX_SHOWN]:
        log.skip("tab or line break in the path, not collected: %r" % rel)
    if not records:
        return fail("no PE files found under %s" % image)

    records, collisions = find_collisions(records)
    groups = {}
    for rec in records:
        groups.setdefault(rec.key, []).append(rec)

    stored_groups = []
    duplicates = []
    for key in sorted(groups):
        kept, dups = split_duplicates(groups[key])
        stored_groups.append(kept)
        duplicates += dups
    stored = [rec for kept in stored_groups for rec in kept]
    need = [rec for rec in stored if rec.info is None]
    log.step("selecting: %d PEs in %d (name, arch) groups, %d files to store; reading versions "
             "of %d (%d cached)" % (len(records), len(groups), len(stored), len(need),
                                    len(stored) - len(need)))
    progress = pelib.Progress(not log.quiet)
    done = 0
    for rec, info in pelib.ordered_map(
            lambda r: pelib.pe_info(to_native(image, r.rel), r.size), need, args.jobs):
        rec.info = info or {}
        done += 1
        progress.tick(lambda: "select: %d/%d files read (%d%%)%s" % (
            done, len(need), 100 * done // len(need), pelib.eta(progress.elapsed(), done, len(need))))
    for kept in stored_groups:
        mark_canonical(kept)
    progress.clear()
    phases["select"] = progress.elapsed()
    log.info("selected %d files to store in %s" % (len(stored), pelib.duration(phases["select"])))
    stored.sort(key=lambda r: r.rel)
    duplicates.sort(key=lambda d: (d[0].lower(), d[1], d[3], d[4]))
    canonical = [r for r in stored if r.canonical]
    for rec in stored:
        if rec.rel in new_cache:
            new_cache[rec.rel] = new_cache[rec.rel]._replace(info=cache_info(rec.info))

    copied_bytes = linked_bytes = skipped = 0
    stale = []
    if args.dry_run:
        known = set()
        for rec in stored:
            if rec.digest in index or rec.digest in known:
                linked_bytes += rec.size
            else:
                copied_bytes += rec.size
                known.add(rec.digest)
    else:
        if os.path.exists(lp(manifest_path)):
            os.unlink(lp(manifest_path))
            log.removed("manifest.sha256 (written again when this run completes)")
        total_bytes = sum(r.size for r in stored)
        done_bytes = 0
        log.step("placing %d files (%s)" % (len(stored), byte_string(total_bytes)))
        progress = pelib.Progress(not log.quiet)
        try:
            for i, rec in enumerate(stored):
                progress.tick(lambda: "place: %d/%d files (%d%%), %s of %s%s" % (
                    i, len(stored), 100 * done_bytes // max(total_bytes, 1),
                    byte_string(done_bytes), byte_string(total_bytes),
                    pelib.eta(progress.elapsed(), done_bytes, total_bytes)))
                action, size = place(to_native(image, rec.rel), to_native(out, rec.rel),
                                     rec.digest, rec.size, index, not args.no_link,
                                     previous.get(rec.rel))
                if action == "copy":
                    copied_bytes += size
                elif action == "link":
                    linked_bytes += rec.size
                else:
                    skipped += 1
                done_bytes += rec.size
        finally:
            progress.clear()
        log.step("checking the output for stale files")
        stale = find_stale(out, [r.rel for r in stored])
        phases["place"] = progress.elapsed()
        log.info("placed %d files: %s copied, %s linked, %d already in place, in %s"
                 % (len(stored), byte_string(copied_bytes), byte_string(linked_bytes), skipped,
                    pelib.duration(phases["place"])))
        if stale:
            log.skip("%d file(s) in the output are not in the manifest, first: %s; "
                     "verification fails until they are removed" % (len(stale), stale[0]))

    finished = time.time()
    summary = {
        "schema": SUMMARY_SCHEMA,
        "tool": {"name": "os-corpus", "version": pelib.VERSION},
        # The corpus directory's name, so a later build under the same root can find these files
        # to link to even when the report directory is named otherwise (wrapper -Label).
        "corpus": os.path.basename(os.path.normpath(out)),
        "source": {"name": os.path.basename(os.path.normpath(image)),
                   "kind": "directory",
                   "label": args.label or os.path.basename(os.path.normpath(out))},
        "counts": {
            "files_seen": scanned["files_seen"],
            "pe_files": len(records) + len(collisions),
            "stored_files": len(stored),
            "distinct_modules": len(canonical),
            "variants": len(stored) - len(canonical),
            "duplicate_paths": len(duplicates),
            "collisions": len(collisions),
            "pruned_paths": scanned["pruned"],
            "skipped_existing": skipped,
            "stale_files": len(stale),
            "hashed_files": scanned["hashed"],
            "reused_files": scanned["reused"],
        },
        "bytes": {
            "stored_total": sum(r.size for r in stored),
            "copied_unique": copied_bytes,
            "linked_existing": linked_bytes,
        },
        "arch": histogram(r.arch for r in canonical),
        "kinds": histogram((r.info or {}).get("kind", "") for r in stored),
        "locations": histogram(r.location for r in stored),
        "reports": dict(REPORT_SCHEMAS),
        "excludes": patterns,
        "options": {"arch": sorted(arch_filter), "link": not args.no_link,
                    "linkRoot": bool(link_root), "jobs": args.jobs},
        "dryRun": bool(args.dry_run),
        "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished)),
        "elapsed_seconds": round(finished - started, 1),
    }

    if not args.dry_run:
        clock = time.monotonic()
        module_rows = sorted((module_row(r) for r in stored),
                             key=lambda m: (m[0].lower(), m[1], -m[2], m[15].lower(), m[15]))
        outputs = [
            ("modules.tsv", render_tsv(MODULES_HEADER, module_rows)),
            ("duplicates.tsv", render_tsv(DUPLICATES_HEADER, duplicates)),
            ("collisions.tsv", render_tsv(COLLISIONS_HEADER, collisions)),
            ("scan-cache.tsv", render_cache(new_cache)),
        ]
        log.step("writing reports to %s" % report)
        for name, text in outputs:
            if write_if_changed(os.path.join(report, name), text):
                log.done(name)
            else:
                log.same("%s unchanged" % name)
        phases["reports"] = time.monotonic() - clock
        # A list, not an object: summary.json sorts its keys, and the order is the run order.
        summary["phases"] = [[name, round(seconds, 1)] for name, seconds in phases.items()]
        # Last: a manifest exists only for a run that completed.
        for name, text in (("summary.json", json.dumps(summary, indent=2, sort_keys=True) + "\n"),
                           ("manifest.sha256", render_manifest((r.digest, r.rel) for r in stored))):
            if write_if_changed(os.path.join(report, name), text):
                log.done(name)
            else:
                log.same("%s unchanged" % name)

    print_counts(summary, log)
    log.info("time              %s" % phase_line(phases))
    for row in collisions[:MAX_SHOWN]:
        fail("collision: %s and %s are one path" % (row[0], row[2]), EXIT_COLLISIONS)
    if len(collisions) > MAX_SHOWN:
        fail("... %d more, see collisions.tsv" % (len(collisions) - MAX_SHOWN), EXIT_COLLISIONS)

    counts = summary["counts"]
    line = "%d files stored (%d modules, %d variants), %d duplicate paths, %d collisions" % (
        counts["stored_files"], counts["distinct_modules"], counts["variants"],
        counts["duplicate_paths"], counts["collisions"])
    if args.dry_run:
        line = "dry run, nothing written: " + line.replace("stored", "would be stored")
    if collisions and not args.allow_collisions:
        return fail(line, EXIT_COLLISIONS)
    print("[+] collect: %s" % line)
    return EXIT_OK


def print_counts(summary, log):
    counts = summary["counts"]
    data = summary["bytes"]
    log.info("files seen        %d" % counts["files_seen"])
    log.info("PE files          %d" % counts["pe_files"])
    log.info("stored files      %d" % counts["stored_files"])
    log.info("  canonical       %d" % counts["distinct_modules"])
    log.info("  variants        %d" % counts["variants"])
    log.info("duplicate paths   %d" % counts["duplicate_paths"])
    log.info("collisions        %d" % counts["collisions"])
    log.info("architectures     %s" % (", ".join("%s=%d" % kv for kv in summary["arch"].items()) or "-"))
    log.info("kinds             %s" % (", ".join("%s=%d" % kv for kv in summary["kinds"].items()) or "-"))
    log.info("stored bytes      %s" % byte_string(data["stored_total"]))
    log.info("copied this run   %s" % byte_string(data["copied_unique"]))
    log.info("linked existing   %s" % byte_string(data["linked_existing"]))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(EXIT_ERROR)
