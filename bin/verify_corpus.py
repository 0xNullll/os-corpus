#!/usr/bin/env python3
"""
verify_corpus.py: independently re-checks a corpus built by collect_pes.py. Nothing here trusts
the collection run: every file is re-read from disk and every report is cross-checked against
the manifest, so the result means the same on a machine that did not build the corpus.

    python verify_corpus.py <out-dir>                       every check, every file re-hashed
    python verify_corpus.py <out-dir> --fast                existence and sizes only, no re-hash
    python verify_corpus.py <out-dir> --allow-collisions    a non-empty collisions.tsv only warns

Input
    <out-dir> and its report directory (default <out-dir>/../manifests/<out-name>): manifest.sha256,
    modules.tsv, duplicates.tsv, collisions.tsv, summary.json and, when the wrapper wrote one,
    source.json.

Checks, in order (USAGE.md has the failure conditions)
    manifest    parses: lowercase hex digests, relative paths that stay inside the corpus
    tree        the files on disk are exactly the manifest's
    hashes      every file hashes to its manifest digest (skipped with --fast)
    sizes       every file has the size modules.tsv records
    modules     modules.tsv lists the manifest exactly, one canonical row per (name, arch)
    duplicates  every kept path is stored, no duplicate path is stored
    collisions  collisions.tsv is empty
    summary     summary.json counts and bytes agree with the manifest and the tree
    identity    source.json binds the manifest by its SHA-256
    revision    source.json revision is the version of System32/ntdll.dll
    presence    System32/ntdll.dll exists (warning only)

Exit code 0 when nothing failed, 1 when the manifest is missing or unreadable, 2 on bad usage,
3 when only collisions failed, 4 on a content mismatch (manifest, tree, hashes, sizes, identity,
revision), 5 when a report disagrees with the manifest (modules, duplicates, summary).
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pelib  # noqa: E402

# ---- CONFIG ----

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_COLLISIONS = 3
EXIT_MISMATCH = 4
EXIT_SANITY = 5

# Report columns, kept apart from collect_pes.py on purpose so the two tools are checked
# against each other; tests/test_verify.py fails when they disagree.
MODULES_HEADER = ("name", "arch", "canonical", "kind", "location", "format", "machine", "dll",
                  "clr", "embedded_signature", "subsystem", "file_version", "product_version",
                  "size", "sha256", "path")
DUPLICATES_HEADER = ("name", "arch", "sha256", "kept", "duplicate")
COLLISIONS_HEADER = ("path", "sha256", "other", "other_sha256")

NTDLL = "windows/system32/ntdll.dll"
HEX = frozenset("0123456789abcdef")


def lp(path):
    return pelib.long_path(path, True)


def fail(message, code=EXIT_ERROR):
    sys.stdout.flush()  # keep stdout lines ahead of the error in a shared log
    print("[!] verify: %s" % message, file=sys.stderr)
    return code


# ---- READERS ----

def walk_tree(out):
    """{rel: size} for every file in the corpus."""
    root = lp(out)
    files = {}
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace("\\", "/")
            try:
                files[rel] = os.path.getsize(path)
            except OSError:
                files[rel] = -1
    return files


def read_manifest(path):
    """Parse manifest.sha256. Returns (rows, problems); rows is None when it cannot be read."""
    try:
        with open(lp(path), "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as exc:
        return None, ["cannot read %s: %s" % (path, exc)]

    rows = []
    problems = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        digest, sep, rel = line.partition("  ")
        if not sep:
            problems.append("line %d: missing double-space separator" % number)
        elif len(digest) != 64 or not set(digest) <= HEX:
            problems.append("line %d: digest is not lowercase hex" % number)
        elif not rel or rel.startswith(("/", "\\")) or ":" in rel:
            problems.append("line %d: path is not relative" % number)
        elif ".." in rel.split("/"):
            problems.append("line %d: path escapes the corpus" % number)
        else:
            rows.append((digest, rel))
    return rows, problems


def read_tsv(path):
    """(header, rows as dicts), or (None, None) when the file cannot be read."""
    try:
        with open(lp(path), "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return None, None
    if not lines:
        return (), []
    header = tuple(lines[0].split("\t"))
    rows = [dict(zip(header, line.split("\t"))) for line in lines[1:] if line.strip()]
    return header, rows


def read_json(path):
    try:
        with open(lp(path), "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# ---- CHECKS ----

class Checks:
    """Collects (status, name, detail, code) and prints each line as it is added."""

    def __init__(self, quiet):
        self.quiet = quiet
        self.items = []

    def add(self, status, name, detail, code=EXIT_OK):
        self.items.append((status, name, detail, code))
        line = "%-11s %s" % (name, detail)
        if status == "FAIL":
            fail(line, code)
        elif status == "WARN":
            print("[~] %s" % line)
        elif not self.quiet:
            print("[+] %s" % line)

    def passed(self, name, detail):
        self.add("PASS", name, detail)

    def warn(self, name, detail):
        self.add("WARN", name, detail)

    def failed(self, name, detail, code):
        self.add("FAIL", name, detail, code)

    def exit_code(self):
        codes = {code for status, _, _, code in self.items if status == "FAIL"}
        for code in (EXIT_MISMATCH, EXIT_SANITY, EXIT_COLLISIONS):
            if code in codes:
                return code
        return EXIT_OK


def check_header(checks, name, header, expected, code):
    if header != expected:
        checks.failed(name, "unexpected columns: %s" % "\t".join(header or ()), code)
        return False
    return True


def check_modules(checks, out_tree, manifest_map, modules_path):
    """sizes and modules. Returns the canonical row count, or None."""
    header, rows = read_tsv(modules_path)
    if rows is None:
        checks.failed("modules", "modules.tsv missing", EXIT_SANITY)
        return None
    if not check_header(checks, "modules", header, MODULES_HEADER, EXIT_SANITY):
        return None

    wrong_size = [r["path"] for r in rows
                  if r["path"] in out_tree and str(out_tree[r["path"]]) != r["size"]]
    if wrong_size:
        checks.failed("sizes", "%d file(s) differ from modules.tsv, first: %s"
                      % (len(wrong_size), wrong_size[0]), EXIT_MISMATCH)
    else:
        checks.passed("sizes", "%d files" % len(rows))

    listed = {r["path"]: r["sha256"] for r in rows}
    groups = {}
    for r in rows:
        if r["canonical"] == "1":
            key = (r["name"].lower(), r["arch"])
            groups[key] = groups.get(key, 0) + 1
    all_keys = {(r["name"].lower(), r["arch"]) for r in rows}

    if len(listed) != len(rows):
        checks.failed("modules", "a path is listed twice", EXIT_SANITY)
    elif set(listed) != set(manifest_map):
        missing = sorted(set(manifest_map) - set(listed))
        extra = sorted(set(listed) - set(manifest_map))
        checks.failed("modules", "%d manifest path(s) not listed, %d listed path(s) not in the "
                      "manifest, first: %s" % (len(missing), len(extra), (missing + extra)[0]),
                      EXIT_SANITY)
    elif any(listed[p] != manifest_map[p] for p in listed):
        first = next(p for p in sorted(listed) if listed[p] != manifest_map[p])
        checks.failed("modules", "sha256 differs from the manifest: %s" % first, EXIT_SANITY)
    elif set(groups) != all_keys or any(n != 1 for n in groups.values()):
        bad = sorted(k for k in all_keys if groups.get(k, 0) != 1)
        checks.failed("modules", "%d (name, arch) group(s) without exactly one canonical row, "
                      "first: %s [%s]" % (len(bad), bad[0][0], bad[0][1]), EXIT_SANITY)
    else:
        checks.passed("modules", "%d rows, %d canonical" % (len(rows), len(groups)))
    return len(groups)


def check_duplicates(checks, manifest_map, path):
    header, rows = read_tsv(path)
    if rows is None:
        checks.warn("duplicates", "duplicates.tsv missing")
        return
    if not check_header(checks, "duplicates", header, DUPLICATES_HEADER, EXIT_SANITY):
        return
    dangling = [r for r in rows if r["kept"] not in manifest_map]
    stored = [r for r in rows if r["duplicate"] in manifest_map]
    if dangling:
        checks.failed("duplicates", "%d row(s) point at a path that is not stored, first: %s"
                      % (len(dangling), dangling[0]["kept"]), EXIT_SANITY)
    elif stored:
        checks.failed("duplicates", "%d recorded duplicate(s) are also stored, first: %s"
                      % (len(stored), stored[0]["duplicate"]), EXIT_SANITY)
    else:
        checks.passed("duplicates", "%d recorded, none stored" % len(rows) if rows else "none")


def check_collisions(checks, path, allow):
    header, rows = read_tsv(path)
    if rows is None:
        checks.warn("collisions", "collisions.tsv missing")
        return
    if not check_header(checks, "collisions", header, COLLISIONS_HEADER, EXIT_SANITY):
        return
    if not rows:
        checks.passed("collisions", "none")
        return
    detail = "%d path(s) found twice, first: %s" % (len(rows), rows[0]["path"])
    if allow:
        checks.warn("collisions", detail)
    else:
        checks.failed("collisions", detail, EXIT_COLLISIONS)


def check_summary(checks, summary, manifest_rows, canonical, tree):
    if summary is None:
        checks.warn("summary", "summary.json missing or unreadable")
        return
    counts = summary.get("counts", {})
    stored_total = summary.get("bytes", {}).get("stored_total")
    actual = sum(size for size in tree.values() if size > 0)
    if counts.get("stored_files") != manifest_rows:
        checks.failed("summary", "stored_files=%s but the manifest has %d"
                      % (counts.get("stored_files"), manifest_rows), EXIT_SANITY)
    elif canonical is not None and counts.get("distinct_modules") != canonical:
        checks.failed("summary", "distinct_modules=%s but modules.tsv has %d canonical rows"
                      % (counts.get("distinct_modules"), canonical), EXIT_SANITY)
    elif stored_total != actual:
        checks.failed("summary", "stored_total=%s but the tree holds %d bytes"
                      % (stored_total, actual), EXIT_SANITY)
    else:
        checks.passed("summary", "%d files, %d bytes" % (manifest_rows, actual))


def check_source(checks, source, manifest_path, out, tree):
    if source is None:
        checks.warn("identity", "source.json missing; the corpus has no media record")
        return
    recorded = source.get("manifestSha256")
    if not recorded:
        checks.warn("identity", "source.json has no manifestSha256")
    elif pelib.sha256_file(manifest_path) != recorded:
        checks.failed("identity", "manifest sha256 does not match source.json", EXIT_MISMATCH)
    else:
        checks.passed("identity", "manifest bound to %s"
                      % ((source.get("image") or {}).get("name") or "media"))

    revision = source.get("revision")
    ntdll = next((rel for rel in tree if rel.lower() == NTDLL), None)
    if not revision:
        checks.warn("revision", "source.json has no revision")
    elif ntdll is None:
        checks.warn("revision", "no System32/ntdll.dll to check against")
    else:
        actual = pelib.version_of(os.path.join(out, ntdll.replace("/", os.sep))).get(
            "file_version", "")
        if not actual:
            checks.warn("revision", "ntdll.dll has no version resource")
        elif actual != revision:
            checks.failed("revision", "source.json says %s, ntdll.dll is %s"
                          % (revision, actual), EXIT_MISMATCH)
        else:
            checks.passed("revision", actual)


# ---- MAIN ----

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="verify_corpus.py",
        description="Verify a corpus against its manifest and reports.")
    ap.add_argument("out", help="corpus directory to verify")
    ap.add_argument("--report", default="",
                    help="report directory (default: <out>/../manifests/<out-name>)")
    ap.add_argument("--fast", action="store_true",
                    help="existence and sizes only; do not re-hash")
    ap.add_argument("--allow-collisions", action="store_true",
                    help="treat a non-empty collisions.tsv as a warning")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="print only warnings, failures and the closing line")
    ap.add_argument("--version", action="version", version="os-corpus %s" % pelib.VERSION)
    args = ap.parse_args(sys.argv[1:] if argv is None else argv)

    out = os.path.abspath(args.out)
    if not os.path.isdir(lp(out)):
        return fail("not a directory: %s" % out, EXIT_USAGE)
    report = os.path.abspath(args.report) if args.report else os.path.join(
        os.path.dirname(out), "manifests", os.path.basename(out))
    if not os.path.isdir(lp(report)):
        return fail("no report directory: %s" % report, EXIT_USAGE)

    if not args.quiet:
        print("[i] corpus      %s" % out)
        print("[i] report      %s" % report)

    manifest_path = os.path.join(report, "manifest.sha256")
    rows, problems = read_manifest(manifest_path)
    if rows is None:
        return fail(problems[0] + "; was the collection run interrupted?")

    checks = Checks(args.quiet)
    if problems:
        checks.failed("manifest", "%d malformed line(s), first: %s"
                      % (len(problems), problems[0]), EXIT_MISMATCH)
    else:
        checks.passed("manifest", "%d entries" % len(rows))

    tree = walk_tree(out)
    manifest_map = {rel: digest for digest, rel in rows}
    missing = sorted(set(manifest_map) - set(tree))
    extra = sorted(set(tree) - set(manifest_map))
    if missing or extra:
        checks.failed("tree", "%d missing, %d unexpected, first: %s"
                      % (len(missing), len(extra), (missing + extra)[0]), EXIT_MISMATCH)
    else:
        checks.passed("tree", "%d files, no extras" % len(tree))

    if args.fast:
        checks.warn("hashes", "skipped (--fast)")
    else:
        bad = []
        for digest, rel in rows:
            if rel not in tree:
                continue
            try:
                if pelib.sha256_file(os.path.join(out, rel.replace("/", os.sep))) != digest:
                    bad.append(rel)
            except OSError as exc:
                bad.append("%s (%s)" % (rel, exc))
        if bad:
            checks.failed("hashes", "%d mismatch(es), first: %s" % (len(bad), bad[0]),
                          EXIT_MISMATCH)
        else:
            checks.passed("hashes", "%d verified" % len(rows))

    canonical = check_modules(checks, tree, manifest_map,
                              os.path.join(report, "modules.tsv"))
    check_duplicates(checks, manifest_map, os.path.join(report, "duplicates.tsv"))
    check_collisions(checks, os.path.join(report, "collisions.tsv"), args.allow_collisions)
    check_summary(checks, read_json(os.path.join(report, "summary.json")), len(rows),
                  canonical, tree)
    check_source(checks, read_json(os.path.join(report, "source.json")), manifest_path, out, tree)

    if not any(rel.lower() == NTDLL for rel in tree):
        checks.warn("presence", "no Windows/System32/ntdll.dll; partial tree?")

    failed = sum(1 for c in checks.items if c[0] == "FAIL")
    warned = sum(1 for c in checks.items if c[0] == "WARN")
    code = checks.exit_code()
    if failed:
        return fail("%d of %d checks failed, %d warning(s); the corpus is not trustworthy"
                    % (failed, len(checks.items), warned), code)
    print("[+] verify: %d checks passed, %d warning(s)" % (len(checks.items) - warned, warned))
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(EXIT_ERROR)
