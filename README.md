# os-corpus

[![Windows](https://github.com/0xNullll/os-corpus/actions/workflows/ci-windows.yml/badge.svg?branch=main)](https://github.com/0xNullll/os-corpus/actions/workflows/ci-windows.yml)
[![Linux](https://github.com/0xNullll/os-corpus/actions/workflows/ci-linux.yml/badge.svg?branch=main)](https://github.com/0xNullll/os-corpus/actions/workflows/ci-linux.yml)

Extract a deduplicated PE corpus from Windows installation media (or any
extracted tree), with the evidence needed to prove exactly what was
collected, and verify it independently.

Point it at a mounted image. It walks the tree and validates every file as a
PE by header. It stores each distinct content once and marks one canonical
file per `(module name, architecture)`. Then it writes a manifest and a
classified module table, and a second process re-checks all of it. Nothing
is installed, booted or activated, and there is no hardcoded module list.

```text
media (ISO / WIM / ESD / VHD)  or  a directory
        |
        |  extract-image.ps1   hash, mount read-only, collect, record, verify, dismount
        v
  corpus/<build>/Windows/System32/...       every distinct PE, at its image path
  corpus/manifests/<build>/
      manifest.sha256                       sha256sum-compatible; the corpus identity
      modules.tsv                           one classified row per stored file
      duplicates.tsv                        paths not stored: same name, arch and bytes
      collisions.tsv                        paths found twice (case-sensitive sources)
      summary.json                          counts, bytes, histograms, phase times
      source.json                           the media: hash, edition, build (wrapper)
  corpus/logs/<build>-<time>.log            everything the run printed (wrapper)
```

## Scripts

| Script | Role | Does | Elevation |
|---|---|---|---|
| `bin/extract-image.ps1` | orchestrator | hashes and mounts the media read-only, runs collect and verify, records `source.json`, always dismounts | ISO, WIM, ESD, VHD |
| `bin/collect_pes.py` | engine | directory in, corpus and reports out | never |
| `bin/verify_corpus.py` | check | re-hashes the corpus and cross-checks every report | never |
| `bin/diff_corpus.py` | report | what changed between two builds: added, removed, updated, rebuilt, moved | never |
| `bin/pelib.py` | library + CLI | PE sniffing, classification, versions, long paths; `pelib.py info <file>` | never |

**[USAGE.md](USAGE.md)** is the full specification of each script: options,
selection rules, checks, every output column, exit codes and known gaps.

## Requirements

- Python 3.10+ (tested on 3.10, 3.13 and 3.14). Standard library only.
- Windows with DISM for ISO/WIM/ESD sources; the Hyper-V module for VHD.
- Administrator for mounting. Collection and verification never need it.
- A local NTFS volume for the corpus, so identical bytes can be hardlinked.

## Quick start

```powershell
# 1. list the editions on the media (exits with code 2)
.\bin\extract-image.ps1 -Iso D:\media\Win11.iso -Out D:\corpus\10.0.26300

# 2. collect one edition by name, the same on every ISO; verification runs automatically
.\bin\extract-image.ps1 -Iso D:\media\Win11.iso -Out D:\corpus\10.0.26300 -Edition "Windows 11 Pro"

# 3. one file per module and architecture, for consumers that need exactly one
Import-Csv -Delimiter "`t" D:\corpus\manifests\10.0.26300\modules.tsv |
    Where-Object canonical -eq 1

# 4. what changed since an earlier build
python .\bin\diff_corpus.py D:\corpus\10.0.19045 D:\corpus\10.0.26300 --tsv changes.tsv
```

Every phase prints progress and its duration, a run ends with the time of
each phase and its result, and the whole output is kept in
`corpus\logs\`. An interrupted run continues with `-Resume`, which reuses
what the earlier run hashed and read.

An already-mounted or extracted tree needs no wrapper and no elevation:

```powershell
python .\bin\collect_pes.py D:\mnt\windows D:\corpus\sample
python .\bin\verify_corpus.py D:\corpus\sample
```

## What gets collected

- **Every PE, by header.** `.dll`, `.exe`, `.sys`, `.mui`, `.efi`, `.pyd`
  and extensionless files all qualify when the header is valid. Volatile
  locations (`$Recycle.Bin`, `WinSxS\Temp`, `SoftwareDistribution` and
  others) are skipped by default.
- **Identical bytes once.** The same name, architecture and bytes in
  several folders are stored at the most authoritative path; the other
  paths go to `duplicates.tsv`.
- **Every distinct version.** The same name and architecture with
  different bytes, such as two WinSxS versions of `comctl32.dll`, are all
  stored. The best one is `canonical=1`: by location rank
  (`System32 > SysWOW64 > SystemApps > Program Files > WinSxS > DriverStore > other`),
  then file version, then path.
- **Classified.** Each row of `modules.tsv` carries its `kind` (`exe`,
  `dll`, `native`, `resource`, `efi`), `location`, `clr` (.NET),
  `embedded_signature`, subsystem and version.
- **Both architectures from one x64 image.** `System32` is x64 and
  `SysWOW64` is x86.

Identical binaries are hardlinked across builds kept under one corpus root,
so a second build costs only the bytes that changed. The links are found
from the other builds' manifests at the start of each run; there is no
index file to keep in sync, and the root can be moved. Files are hashed in
parallel (`--jobs`, default the CPU count, at most 8). Re-runs are
resumable, and reports are rewritten byte for byte.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | error |
| 2 | bad usage, or an edition listing was requested |
| 3 | collisions: one path found twice |
| 4 | verification: content mismatch |
| 5 | verification: a report disagrees with the manifest |
| 130 | interrupted |

## Tests

No Windows image is needed, and none is committed. Synthetic PE32/PE32+
files, version resources and a fake image tree are built in a temporary
directory, and the real tools run as subprocesses. On Windows that
includes `extract-image.ps1` with a directory source.

```powershell
python -m unittest discover -s tests -v
```

CI runs the same suite on Windows and Linux with Python 3.10 and 3.13. It is
manual: start it from the Actions tab (*Run workflow*); the badges above show
the latest run on `main`. Real installation media is never mounted in CI.

| Module | Covers |
|---|---|
| `tests/test_pelib.py` | sniffing and malformed headers, classification, versions, long paths, progress, parallel map, the CLI |
| `tests/test_collect.py` | locations, selection and collisions as pure functions; collection end to end, re-runs, the scan cache, `--jobs`, hardlink safety, deep paths |
| `tests/test_verify.py` | every failure class against a tampered corpus, parallel re-hashing, the report columns shared with collect |
| `tests/test_diff.py` | every kind of change between two collected corpora, the TSV |
| `tests/test_extract_image.py` | the wrapper's directory path, its run log and closing lines, relative paths, its argument checks |

## License

This project is released under the **MIT license**. See [LICENSE](LICENSE) for full text.