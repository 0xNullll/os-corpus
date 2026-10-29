# os-corpus - design

`os-corpus` is a small, dependency-free extraction tool. Point it at a mounted
Windows installation image (or an already-extracted tree) and it produces a
deduplicated, classified PE corpus plus the evidence needed to prove exactly
what was collected and what was skipped.

The tool is the product. This repository does not contain images, mount points,
or extracted corpora. Those live outside the repo, on whatever local NTFS folder
the user picks. It feeds the AXIS tooling (AXIS-Tools, the noreturn table
generator), which reads the corpus and `modules.tsv`.

This file is the design: why the tool works the way it does. How each script
behaves, every option and every output column are specified in
[USAGE.md](USAGE.md).

- Version: 0.1.0
- Runtime: Python 3.10+ (3.10, 3.13 and 3.14 tested), standard library only
- Host: Windows for ISO/WIM/ESD/VHD sources; any OS for directory sources
- License: MIT

---

## 1. Scope

In scope:

- Discover PE files by **signature**, not by extension and not by a hardcoded
  module list.
- Store every distinct content once, mark one canonical file per
  `(module name, architecture)`, and record every path that was not stored.
- Classify every stored file from its headers: kind, location, .NET, signature.
- Produce a byte-exact manifest and machine-readable reports with frozen
  columns.
- Do all of that deterministically, resumably, and idempotently.
- Run on Windows media (ISO -> WIM/ESD -> read-only mount) without installing,
  booting, or activating anything.

Out of scope for 0.1.0:

- Reading WIM/ESD containers natively. The PowerShell wrapper delegates to DISM.
- Impersonating a specific project's data model. The corpus is generic: path +
  hash + architecture + version + classification.
- Deleting anything the user did not ask to delete.
- Publishing corpora. Only reports travel; the tree stays local.

## 2. Invariants

1. **Signature first.** A file is a PE only if its header checks out
   (USAGE.md §5.2). Extension is never consulted.
2. **Each content once per name.** Identical bytes under one
   `(name, arch)` are stored once; the other paths are recorded, not stored.
   A consumer never sees the same module bytes twice under one name.
3. **Nothing real is dropped.** Different bytes under one `(name, arch)` are
   all stored, each at its image path. Windows ships such versions on
   purpose (WinSxS side-by-side components, .NET, driver packages).
4. **Exactly one canonical file per `(name, arch)`.** Chosen by location rank,
   then file version, then path: a pure function of paths and bytes, never of
   walk order. Consumers that need one file per module filter `canonical=1`.
5. **Impossible paths are visible.** One path found twice in different case is
   a collision, a gate (exit 3), never a silent pick.
6. **The manifest is the identity.** A corpus is identified by the SHA-256 of
   `manifest.sha256`, not by the media it came from. A manifest exists only for
   a completed run.
7. **Nothing is imported.** Outputs are files; the repo never reads them back.
   The corpus root is disposable and rebuildable.
8. **Deterministic output.** Same input + same options => byte-identical
   `manifest.sha256`, `modules.tsv`, `duplicates.tsv`, `collisions.tsv`.
   Only `summary.json` and `source.json` carry time.
9. **Never write through a link.** New bytes go to a temporary file renamed
   into place, so one build can never change another build's files.

## 3. Architecture

```
bin/extract-image.ps1     Windows orchestration: hash, mount, collect, record, verify, unmount
      |
      +-- bin/collect_pes.py     scan -> select -> place -> report
      |         |
      |         +-- bin/pelib.py    PE sniffing, classification, versions, hashing, long paths
      |
      +-- bin/verify_corpus.py   independent re-check of a finished corpus
```

`collect_pes.py` and `verify_corpus.py` take a **directory** and nothing else.
Mounting is deliberately outside them, so the same engine runs against a WIM
mount, a VHD mount, an unpacked ISO, a VM disk image already mounted by the
host, or a live installation the user wants to sample.

`extract-image.ps1` is the only component that knows about containers, admin
rights, or DISM.

`verify_corpus.py` keeps its own copy of the report columns instead of importing
them from `collect_pes.py`, so the two tools check each other; a test fails when
the copies disagree.

## 4. Pipeline

```
1  hash        SHA-256 of the container (ISO/WIM/ESD/VHD) before mounting
2  mount       read-only; locate install.wim; list indexes
3  pick        an index (Desktop Experience for server media)
4  scan        walk the mounted root, sniff headers, hash PEs
5  select      collisions, duplicates, variants, one canonical per (name, arch)
6  place       copy or hardlink stored files into the output mirror
7  report      modules, duplicates, collisions, summary; manifest last
8  record      source.json binds the media to the manifest hash
9  verify      a second process re-hashes the output and cross-checks the reports
10 unmount     always in `finally`; mount point and temporary WIM removed
```

Step 9 is not optional for `-DeleteSource`. `collect_pes.py` alone does not
verify its own output; a second process re-reads the bytes from disk.

## 5. Why these selection rules

- **Grouping by `(name, arch)`** is how consumers look modules up: an import
  names a DLL, not a path. The AXIS noreturn tables are keyed exactly this way.
- **Location rank** prefers where the loader finds a module (`System32`,
  `SysWOW64`) over stores that hold copies for servicing (`WinSxS`,
  `DriverStore`).
- **File version** breaks a tie inside one location: serviced media can hold an
  old and a new copy side by side.
- **Storing variants** keeps the corpus a faithful record of the media. The
  first design kept only the canonical file and treated every other version as a
  conflict; on real media that gate would fire on legitimate side-by-side
  components and lose their bytes for good.
- **Collisions** remain a gate because they cannot be stored on NTFS and cannot
  come from Windows media; they mean the source is not what it claims to be.

## 6. Windows specifics

- **Long paths.** `WinSxS` component directories exceed 260 characters. All
  path operations go through a `\\?\` prefix helper, and the wrapper warns when
  `LongPathsEnabled` is not set.
- **Admin.** `Mount-WindowsImage` needs elevation. `collect_pes.py` never does.
- **Mount hygiene.** A stale mount point blocks the next run. The wrapper uses
  one empty directory per label and dismounts in `finally`.
- **Server media.** Pick the *Desktop Experience* index. Server Core has no
  `SysWOW64`, so the x86 half of a corpus would be silently empty.
- **ESD.** Export the chosen index once to a temporary WIM (index 1 in it); do
  not extract the whole image.
- **Anti-virus.** Reading thousands of system binaries can trip real-time
  scanners. An exclusion for the output root is legitimate; disabling the
  scanner is not.

## 7. Failure modes and guardrails

| Risk | Handling |
|---|---|
| Two versions of a module share a name | both stored; one `canonical=1`, the other a variant |
| Duplicate stored twice | forbidden; duplicates go to TSV only, verify fails on a stored one |
| One path twice in different case | `collisions.tsv` gate, exit 3 |
| New bytes written through a hardlink into another build | temporary file + rename; never opened for writing |
| Hardlink index points at a replaced or deleted file | replaced paths are dropped from the index; size check, fall back to copy |
| Interrupted run | old manifest removed first, new one written last; index saved; `--resume` continues |
| Files left from an earlier run with other options | reported as stale, never deleted; verify fails until removed |
| Mount or temporary WIM left behind | wrapper cleans up in `finally`; next run refuses a dirty mount point |
| ISO deleted by accident | `-DeleteSource` is opt-in, ISO-only, refused with `-NoVerify` |
| Source has no PEs (wrong index) | an error, not a success |
| Wrong architecture subset | `arch` histogram in `summary.json` shows an empty bucket |
| Malformed or hostile headers | sniffing never raises; every resource read is bounds-checked |

## 8. Testing

No real Windows image is required, and none is committed.

- `tests/pefixtures.py` builds synthetic PE32/PE32+ files in a temporary
  directory: entry points, subsystems, CLR and certificate directories, and a
  `.rsrc` section with a hand-built `VS_VERSIONINFO`.
- Unit coverage: sniff accept/reject cases and every truncation, classification,
  version parsing (fixed info and string fallback), long paths, exclusions,
  locations, selection and collisions as pure functions, the hash index.
- End to end: a fake image tree with a duplicate, a variant, a resource DLL, a
  driver, a .NET assembly, excluded and non-PE files. Collection, re-runs,
  resume determinism, cross-build hardlinks, the hardlink write-through case,
  stale files and a >260-character path.
- `verify_corpus.py` runs against real collect output and against one tampered
  copy per failure class, so the two tools cannot drift apart silently.
- `extract-image.ps1` runs with a directory source on Windows.

`python -m unittest discover -s tests -v`

## 9. Milestones

- **0.1.0** - engine + wrapper + verifier + tests. Directory and WIM sources.
  Classification and frozen report schemas.
- **0.2.0** - ESD conversion path and VHD source exercised on real media,
  parallel hashing for large trees if measurements justify it.
- **0.3.0** - optional export-table extraction, so a corpus can be turned into
  per-build symbol tables without a second tool; import-based `driver` kind.
- **Later** - ELF/ELF64 collector behind the same report contract, sharing the
  manifest and selection rules.

## 10. Open questions

1. **Canonical-only corpora.** Storing every variant costs disk per version. A
   `--canonical-only` option would bring back the smaller tree for consumers that
   never read variants. Measure the variant share on real media first.
2. **Parallel hashing.** A mount of a compressed WIM is CPU-bound on
   decompression; threads may not help while the image is cold. Measure first.
3. **Compression.** The tree is stored uncompressed so hardlinks work. A
   secondary `zstd` archive could cut cold storage, at the cost of losing
   dedupe across builds.
4. **Relative index paths.** `.hash-index.tsv` stores absolute paths, so moving
   the corpus root loses the links until a run rebuilds it.
