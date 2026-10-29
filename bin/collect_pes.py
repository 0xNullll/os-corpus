#!/usr/bin/env python3
"""
collect_pes.py: builds a PE corpus from a mounted Windows image or any extracted tree, plus the
evidence that proves what was collected. Mounting is extract-image.ps1's job; this script only
ever sees a directory.

    python collect_pes.py <image-dir> <out-dir>                 collect into <out-dir>
    python collect_pes.py <image-dir> <out-dir> --dry-run       scan and print the counts, write nothing
    python collect_pes.py <image-dir> <out-dir> --resume        continue an interrupted run
    python collect_pes.py <image-dir> <out-dir> --arch x64,x86  keep only these architectures

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
    <out>/<image path>                  every stored file, hardlinked when an earlier run stored
                                        the same bytes (shared index, default <out>/../.hash-index.tsv)
    <report>/manifest.sha256            sha256sum format, one line per stored file; written last
    <report>/modules.tsv                one row per stored file, with its classification
    <report>/duplicates.tsv             paths not stored because their bytes are stored elsewhere
    <report>/collisions.tsv             paths found twice
    <report>/summary.json               counts, bytes, histograms, options, timing
    <report>/scan-cache.tsv             resume accelerator, not evidence
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

# Suffix of the temporary name a file is written under before it is renamed into place.
TMP_SUFFIX = ".os-corpus-tmp"

MAX_SHOWN = 20
PROGRESS_SECONDS = 2.0


# ---- OUTPUT ----

class Log:
    def __init__(self, quiet):
        self.quiet = quiet

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


def byte_string(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%d B" % n if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%d B" % n


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
    info: Optional[dict] = None    # pelib.pe_info of the source; loaded for stored files only
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
    cache = {}
    try:
        with open(lp(path), "r", encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) != 5:
                    continue
                digest, arch, size, mtime, rel = parts
                try:
                    cache[rel] = (digest, arch, int(size), int(mtime))
                except ValueError:
                    continue
    except OSError:
        pass
    return cache


class HashIndex:
    """digest -> path of a stored copy, shared by every build under one corpus root.

    A path the index points at always holds that digest as far as this tool knows: storing other
    bytes at a path forgets whatever digest the index had placed there, so a later run never
    links to a file whose content was replaced.
    """

    def __init__(self, path):
        self.path = path
        self.by_digest = {}
        self.by_path = {}
        if not path:
            return
        try:
            with open(lp(path), "r", encoding="utf-8") as f:
                for line in f:
                    digest, sep, stored = line.rstrip("\n").partition("\t")
                    if sep and len(digest) == 64 and stored:
                        self.by_digest[digest] = stored
                        self.by_path[self._key(stored)] = digest
        except OSError:
            pass

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

    def save(self):
        if not self.path:
            return
        text = "".join("%s\t%s\n" % (d, self.by_digest[d]) for d in sorted(self.by_digest))
        write_if_changed(self.path, text)


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

def scan(image, excludes, arch_filter, cache, rehash, log):
    """Walk the source. Returns (records, files_seen, pruned, unusable, new_cache)."""
    root = lp(image)
    records = []
    files_seen = 0
    pruned = 0
    unusable = []
    new_cache = {}
    by_inode = {}
    pe_bytes = 0
    live = not log.quiet and sys.stderr.isatty()
    last = time.monotonic()

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir

        kept = []
        for d in dirnames:
            if is_excluded(("%s/%s" % (rel_dir, d)).lstrip("/").lower(), True, excludes):
                pruned += 1
            else:
                kept.append(d)
        dirnames[:] = kept

        for name in filenames:
            rel = ("%s/%s" % (rel_dir, name)).lstrip("/")
            if is_excluded(rel.lower(), False, excludes):
                pruned += 1
                continue
            files_seen += 1
            path = os.path.join(dirpath, name)
            try:
                st = os.stat(path)
            except OSError:
                continue
            if st.st_size < 0x40:
                continue

            cached = None if rehash else cache.get(rel)
            hit = by_inode.get((st.st_dev, st.st_ino)) if st.st_ino else None
            if hit:
                digest, arch = hit
            elif cached and cached[2] == st.st_size and cached[3] == st.st_mtime_ns:
                digest, arch = cached[0], cached[1]
            else:
                info = pelib.sniff_bytes(pelib.read_head(path), st.st_size)
                if info is None:
                    continue
                try:
                    digest = pelib.sha256_file(path)
                except OSError:
                    continue
                arch = info["arch"]
            if st.st_ino:
                by_inode[(st.st_dev, st.st_ino)] = (digest, arch)
            new_cache[rel] = "%s\t%s\t%d\t%d" % (digest, arch, st.st_size, st.st_mtime_ns)

            if any(c in rel for c in "\t\r\n"):
                unusable.append(rel)
                continue
            if arch_filter and arch not in arch_filter:
                continue
            records.append(make_record(rel, st.st_size, digest, arch))
            pe_bytes += st.st_size

            if live and time.monotonic() - last > PROGRESS_SECONDS:
                last = time.monotonic()
                sys.stderr.write("\r[i] scanned %d files, %d PE, %s   "
                                 % (files_seen, len(records), byte_string(pe_bytes)))
                sys.stderr.flush()

    if live:
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()
    log.info("scanned %d files, %d PE, %s" % (files_seen, len(records), byte_string(pe_bytes)))
    return records, files_seen, pruned, unusable, new_cache


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


def select_group(items, load_info):
    """Choose what to store from one (name, arch) group.

    Returns (stored, duplicate rows). Identical bytes are stored once, at the best-ranked path.
    Every distinct content is stored; the best one is marked canonical. ``load_info(record)``
    returns the pe_info of a record and is called once per stored record. The result depends
    on the records and their bytes only, never on the order they were found in.
    """
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

    for rec in stored:
        if rec.info is None:
            rec.info = load_info(rec) or {}
    stored.sort(key=_canonical_order)
    for i, rec in enumerate(stored):
        rec.canonical = i == 0
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


# ---- MAIN ----

def parse_args(argv):
    ap = argparse.ArgumentParser(
        prog="collect_pes.py",
        description="Build a PE corpus from a mounted Windows image or an extracted tree.")
    ap.add_argument("image", help="directory to scan (a mount point or a tree)")
    ap.add_argument("out", help="corpus directory; stored files keep their image path inside it")
    ap.add_argument("--report", default="",
                    help="evidence directory (default: <out>/../manifests/<out-name>)")
    ap.add_argument("--index", default="",
                    help="shared hardlink index (default: <out>/../.hash-index.tsv; 'none' disables)")
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
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="print only warnings, errors and the closing line")
    ap.add_argument("--version", action="version", version="os-corpus %s" % pelib.VERSION)
    return ap.parse_args(argv)


def default_report(out):
    parent = os.path.dirname(os.path.abspath(out))
    return os.path.join(parent, "manifests", os.path.basename(os.path.abspath(out)))


def default_index(out):
    return os.path.join(os.path.dirname(os.path.abspath(out)), ".hash-index.tsv")


def main(argv=None):
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

    index_path = args.index
    if index_path.lower() == "none":
        index_path = ""
    else:
        index_path = os.path.abspath(index_path) if index_path else default_index(out)
    if index_path and inside(index_path, out):
        return fail("index file must be outside the corpus: %s" % index_path, EXIT_USAGE)

    patterns = [p.replace("\\", "/").lower() for p in args.exclude]
    if not args.no_default_excludes:
        patterns = [p.lower() for p in DEFAULT_EXCLUDES] + patterns
    arch_filter = {a.strip().lower() for a in args.arch.split(",") if a.strip()}

    started = time.time()
    manifest_path = os.path.join(report, "manifest.sha256")
    cache = read_cache(os.path.join(report, "scan-cache.tsv")) if args.resume else {}
    previous = read_manifest(manifest_path) if args.resume else {}
    index = HashIndex(index_path)

    log.info("source   %s" % image)
    log.info("output   %s" % out)
    log.info("report   %s" % report)
    log.info("index    %s" % (index_path or "none"))
    if args.resume:
        log.info("resume   %d cached PEs, %d manifest rows" % (len(cache), len(previous)))

    records, files_seen, pruned, unusable, new_cache = scan(
        image, patterns, arch_filter, cache, args.rehash or not args.resume, log)
    for rel in unusable[:MAX_SHOWN]:
        log.skip("tab or line break in the path, not collected: %r" % rel)
    if not records:
        return fail("no PE files found under %s" % image)

    records, collisions = find_collisions(records)
    groups = {}
    for rec in records:
        groups.setdefault(rec.key, []).append(rec)

    stored = []
    duplicates = []
    for key in sorted(groups):
        kept, dups = select_group(groups[key],
                                  lambda r: pelib.pe_info(to_native(image, r.rel), r.size))
        stored += kept
        duplicates += dups
    stored.sort(key=lambda r: r.rel)
    duplicates.sort(key=lambda d: (d[0].lower(), d[1], d[3], d[4]))
    canonical = [r for r in stored if r.canonical]

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
        try:
            for rec in stored:
                action, size = place(to_native(image, rec.rel), to_native(out, rec.rel),
                                     rec.digest, rec.size, index, not args.no_link,
                                     previous.get(rec.rel))
                if action == "copy":
                    copied_bytes += size
                elif action == "link":
                    linked_bytes += rec.size
                else:
                    skipped += 1
        finally:
            index.save()
        log.info("placed %d files: %s copied, %s linked, %d already in place"
                 % (len(stored), byte_string(copied_bytes), byte_string(linked_bytes), skipped))
        stale = find_stale(out, [r.rel for r in stored])
        if stale:
            log.skip("%d file(s) in the output are not in the manifest, first: %s; "
                     "verification fails until they are removed" % (len(stale), stale[0]))

    finished = time.time()
    summary = {
        "schema": SUMMARY_SCHEMA,
        "tool": {"name": "os-corpus", "version": pelib.VERSION},
        "source": {"name": os.path.basename(os.path.normpath(image)),
                   "kind": "directory",
                   "label": args.label or os.path.basename(os.path.normpath(out))},
        "counts": {
            "files_seen": files_seen,
            "pe_files": len(records) + len(collisions),
            "stored_files": len(stored),
            "distinct_modules": len(canonical),
            "variants": len(stored) - len(canonical),
            "duplicate_paths": len(duplicates),
            "collisions": len(collisions),
            "pruned_paths": pruned,
            "skipped_existing": skipped,
            "stale_files": len(stale),
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
                    "sharedIndex": bool(index_path)},
        "dryRun": bool(args.dry_run),
        "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished)),
        "elapsed_seconds": round(finished - started, 1),
    }

    if not args.dry_run:
        module_rows = sorted((module_row(r) for r in stored),
                             key=lambda m: (m[0].lower(), m[1], -m[2], m[15].lower(), m[15]))
        outputs = [
            ("modules.tsv", render_tsv(MODULES_HEADER, module_rows)),
            ("duplicates.tsv", render_tsv(DUPLICATES_HEADER, duplicates)),
            ("collisions.tsv", render_tsv(COLLISIONS_HEADER, collisions)),
            ("summary.json", json.dumps(summary, indent=2, sort_keys=True) + "\n"),
            ("scan-cache.tsv", "".join("%s\t%s\n" % (new_cache[r], r) for r in sorted(new_cache))),
            # Last: a manifest exists only for a run that completed.
            ("manifest.sha256", render_manifest((r.digest, r.rel) for r in stored)),
        ]
        for name, text in outputs:
            if write_if_changed(os.path.join(report, name), text):
                log.done(name)
            else:
                log.same("%s unchanged" % name)

    print_counts(summary, log)
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
