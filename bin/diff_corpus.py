#!/usr/bin/env python3
"""
diff_corpus.py: compares two corpora built by collect_pes.py, module by module, from their
modules.tsv. Reads reports only; the corpus files themselves are never opened.

    python diff_corpus.py <old> <new>                      counts, then the first changes of each kind
    python diff_corpus.py <old> <new> --tsv diff.tsv       every change as TSV (os-corpus/diff/1)
    python diff_corpus.py <old> <new> --limit 0            list every change in the terminal
    python diff_corpus.py <old> <new> --only added,removed list only these kinds

Input
    <old> and <new> are each a corpus directory (its reports are <dir>/../manifests/<name>, the
    collect_pes.py default) or a report directory (one that holds modules.tsv).

Changes
    Canonical rows (canonical=1) are matched by (lowercased file name, architecture):
    added      only in new
    removed    only in old
    updated    different bytes, different file version
    rebuilt    different bytes, same file version (or neither has one)
    moved      same bytes, different path
    unchanged  same bytes, same path
    Variants (canonical=0) are counted for each side but not compared.

Exit code 0 on success, 1 when a modules.tsv is missing or not os-corpus/modules/1, 2 on bad
usage.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collect_pes  # noqa: E402
import pelib  # noqa: E402

# ---- CONFIG ----

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

DIFF_SCHEMA = "os-corpus/diff/1"
DIFF_HEADER = ("change", "name", "arch", "old_version", "new_version", "old_sha256",
               "new_sha256", "old_size", "new_size", "old_path", "new_path")

# Every kind of change, in report order. Listed and written unless --only says otherwise.
CHANGES = ("added", "removed", "updated", "rebuilt", "moved", "unchanged")
DEFAULT_ONLY = ("added", "removed", "updated", "rebuilt", "moved")

DEFAULT_LIMIT = 20


def fail(message, code=EXIT_ERROR):
    sys.stdout.flush()  # keep stdout lines ahead of the error in a shared log
    print("[!] diff: %s" % message, file=sys.stderr)
    return code


# ---- INPUT ----

def report_dir(path):
    """The report directory of a corpus or report directory argument."""
    path = os.path.abspath(path)
    if os.path.isfile(os.path.join(path, "modules.tsv")):
        return path
    return collect_pes.default_report(path)


def read_side(path):
    """(label, description, canonical rows by key, variant count) of one corpus."""
    report = report_dir(path)
    modules = os.path.join(report, "modules.tsv")
    try:
        with open(pelib.long_path(modules, True), "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError as exc:
        raise ValueError("cannot read %s: %s" % (modules, exc))
    if not lines or tuple(lines[0].split("\t")) != collect_pes.MODULES_HEADER:
        raise ValueError("%s does not have the os-corpus/modules/1 columns" % modules)

    canonical = {}
    variants = 0
    for line in lines[1:]:
        if not line.strip():
            continue
        row = dict(zip(collect_pes.MODULES_HEADER, line.split("\t")))
        if row["canonical"] != "1":
            variants += 1
            continue
        key = (row["name"].lower(), row["arch"])
        if key in canonical:
            raise ValueError("%s has two canonical rows for %s [%s]" % (modules, key[0], key[1]))
        canonical[key] = row

    label = os.path.basename(report)
    description = ""
    for name in ("source.json", "summary.json"):
        try:
            with open(os.path.join(report, name), "r", encoding="utf-8-sig") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        container = data.get("container") or {}
        if container.get("imageName"):
            description = "%s, %s" % (container["imageName"], container.get("build") or "?")
            break
        label = (data.get("source") or {}).get("label") or label
    return label, description, canonical, variants


# ---- COMPARISON ----

def classify(old, new):
    """The change between two rows of one (name, arch), either of which may be None."""
    if old is None:
        return "added"
    if new is None:
        return "removed"
    if old["sha256"] != new["sha256"]:
        return "updated" if old["file_version"] != new["file_version"] else "rebuilt"
    return "moved" if old["path"] != new["path"] else "unchanged"


def compare(old_rows, new_rows):
    """[(change, key, old row, new row)] for every key of either side, sorted by change kind,
    then name and architecture."""
    result = []
    for key in set(old_rows) | set(new_rows):
        old, new = old_rows.get(key), new_rows.get(key)
        result.append((classify(old, new), key, old, new))
    result.sort(key=lambda item: (CHANGES.index(item[0]), item[1]))
    return result


def diff_row(change, key, old, new):
    old, new = old or {}, new or {}
    name = (new or old).get("name", key[0])
    return (change, name, key[1], old.get("file_version", ""), new.get("file_version", ""),
            old.get("sha256", ""), new.get("sha256", ""), old.get("size", ""), new.get("size", ""),
            old.get("path", ""), new.get("path", ""))


def describe(change, key, old, new):
    """One terminal line for a change."""
    old, new = old or {}, new or {}
    name = (new or old).get("name", key[0])
    if change == "added":
        detail = "%s  %s" % (new.get("file_version") or "-", new.get("path"))
    elif change == "removed":
        detail = "%s  %s" % (old.get("file_version") or "-", old.get("path"))
    elif change == "updated":
        detail = "%s -> %s  %s" % (old.get("file_version") or "-", new.get("file_version") or "-",
                                  new.get("path"))
    elif change == "moved":
        detail = "%s -> %s" % (old.get("path"), new.get("path"))
    else:
        detail = "%s  %s" % (new.get("file_version") or "-", new.get("path"))
    return "%-7s %-40s %s" % (key[1], name, detail)


# ---- MAIN ----

def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(
        prog="diff_corpus.py",
        description="Compare the canonical modules of two os-corpus corpora.")
    ap.add_argument("old", help="corpus or report directory of the older build")
    ap.add_argument("new", help="corpus or report directory of the newer build")
    ap.add_argument("--tsv", default="", metavar="FILE",
                    help="write the selected changes to FILE (%s)" % DIFF_SCHEMA)
    ap.add_argument("--only", default=",".join(DEFAULT_ONLY), metavar="KINDS",
                    help="comma separated change kinds to list and write (default: %s)"
                    % ",".join(DEFAULT_ONLY))
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT, metavar="N",
                    help="changes listed per kind in the terminal, 0 for all (default: %d)"
                    % DEFAULT_LIMIT)
    ap.add_argument("-q", "--quiet", action="store_true", help="print only the closing line")
    ap.add_argument("--version", action="version", version="os-corpus %s" % pelib.VERSION)
    args = ap.parse_args(sys.argv[1:] if argv is None else argv)

    only = [k.strip().lower() for k in args.only.split(",") if k.strip()]
    unknown = [k for k in only if k not in CHANGES]
    if unknown or not only:
        return fail("--only takes %s; got %s" % (", ".join(CHANGES), args.only), EXIT_USAGE)
    if args.limit < 0:
        return fail("--limit must be 0 or more", EXIT_USAGE)

    try:
        old_label, old_desc, old_rows, old_variants = read_side(args.old)
        new_label, new_desc, new_rows, new_variants = read_side(args.new)
    except ValueError as exc:
        return fail(str(exc))

    changes = compare(old_rows, new_rows)
    counts = {kind: 0 for kind in CHANGES}
    for change, _, _, _ in changes:
        counts[change] += 1

    if not args.quiet:
        for side, label, desc, rows, variants in (("old", old_label, old_desc, old_rows, old_variants),
                                                  ("new", new_label, new_desc, new_rows, new_variants)):
            print("[i] %s   %s%s: %d modules, %d variants" % (
                side, label, " (%s)" % desc if desc else "", len(rows), variants))
        print("[>] comparing canonical modules by (name, arch)")
        for kind in CHANGES:
            print("[i] %-10s %d" % (kind, counts[kind]))
        for kind in only:
            selected = [c for c in changes if c[0] == kind]
            if not selected:
                continue
            shown = selected if args.limit == 0 else selected[:args.limit]
            print("[i] %s: %s" % (kind, "all %d" % len(selected) if len(shown) == len(selected)
                                  else "first %d of %d" % (len(shown), len(selected))))
            for change in shown:
                print("[i]   %s" % describe(*change))

    if args.tsv:
        rows = [diff_row(*c) for c in changes if c[0] in only]
        collect_pes.write_if_changed(os.path.abspath(args.tsv),
                                     collect_pes.render_tsv(DIFF_HEADER, rows))
        if not args.quiet:
            print("[+] %s: %d rows" % (args.tsv, len(rows)))

    print("[+] diff: %s -> %s: %s" % (old_label, new_label,
                                     ", ".join("%d %s" % (counts[k], k) for k in CHANGES)))
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(EXIT_ERROR)
