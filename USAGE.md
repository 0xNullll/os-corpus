# os-corpus Usage and Specification (v0.1.0)

This file is the reference for every script in `bin/`: what each one
reads, writes, checks and returns. `README.md` is the overview;
`PLAN.md` holds the design rationale. When a script and this file
disagree, the difference is either a bug or listed in §7.

| Section | Covers |
|---|---|
| §1 Conventions | command line, log lines, exit codes, files, paths |
| §2 `extract-image.ps1` | mounting media, `source.json` |
| §3 `collect_pes.py` | discovery, selection, storage, re-runs |
| §4 `verify_corpus.py` | the checks and what fails them |
| §5 `pelib.py` | PE sniffing and classification, the inspection CLI |
| §6 Output formats | every column and field of every output file |
| §7 Known implementation gaps | where the scripts fall short of this file |

---

## 1. Conventions

Every script follows these, so its output reads the same in a terminal,
in a log file and in CI.

### Scripts

| Script | Role | Runs on | Elevation |
|---|---|---|---|
| `extract-image.ps1` | orchestrator: hash, mount, collect, record, verify, dismount | Windows (PowerShell 5.1+) | for ISO, WIM, ESD, VHD |
| `collect_pes.py` | engine: directory in, corpus and reports out | any OS, Python 3.10+ | never |
| `verify_corpus.py` | independent check of a finished corpus | any OS, Python 3.10+ | never |
| `pelib.py` | shared PE primitives, plus a one-file inspection CLI | any OS, Python 3.10+ | never |

The Python scripts use the standard library only and find each other
through their own folder, so `bin/` must stay together.

### Command line
- Python: `argparse`, long options with two dashes, `-h` / `--help`,
  `--version`. PowerShell: named parameters, `Get-Help .\extract-image.ps1 -Full`.
- `-q` / `--quiet` keeps warnings, errors and the closing line.
- Nothing is written inside the source, ever.

### Log lines
One tag per line, then the message:

| Tag | Meaning |
|---|---|
| `[i]` | information: what was found, what will happen |
| `[>]` | a step being run (wrapper) |
| `[+]` | created or written; a passing check; the closing summary |
| `[=]` | already up to date, not rewritten |
| `[-]` | removed |
| `[~]` | skipped or a warning, with the reason |
| `[!]` | an error or a failed check, on stderr after stdout is flushed |

A run ends with one line naming the script, for example
`[+] collect: 4183 files stored (4100 modules, 83 variants), 4820 duplicate paths, 0 collisions`
or `[!] verify: 2 of 11 checks failed, ...`.

### Exit codes

| Code | Meaning | Returned by |
|---|---|---|
| 0 | success | all |
| 1 | error: I/O, mount, no PE found, unreadable manifest, not a PE (`pelib info`) | all |
| 2 | bad usage; also an edition listing (`extract-image.ps1 -Index 0`) | all |
| 3 | collisions: one path found twice (§3.5) | collect, verify, extract-image |
| 4 | content mismatch: manifest, tree, hashes, sizes, identity, revision | verify, extract-image |
| 5 | a report disagrees with the manifest: modules, duplicates, summary | verify, extract-image |
| 130 | interrupted (Ctrl+C) | collect, extract-image |

When several failures meet, verify returns 4 before 5 before 3.

### Files
- Reports are UTF-8 without a BOM, LF line ends, written to a temporary
  name and renamed into place.
- A report whose content would not change is not rewritten, so its
  timestamp stays (`[=]`).
- Paths inside reports are relative to the corpus root, with forward
  slashes. No report holds an absolute path, a user name or a host name,
  so reports can be published; the corpus itself stays local.

### Default layout

```text
<root>/
  .hash-index.tsv           shared by every build under <root> (§6.8)
  <build>/                  a corpus (collect_pes.py <image> <root>/<build>)
  manifests/<build>/        its reports
  .mnt/<label>/             the wrapper's mount point while it runs
  .tmp/<label>.wim          the wrapper's exported ESD while it runs
```

---

## 2. `extract-image.ps1`

### 2.1 Purpose
Turns installation media into a verified corpus in one command. It is
the only script that knows about containers, DISM or elevation; it hands
`collect_pes.py` a directory.

### 2.2 Sources

| Parameter | Mounted with | Scanned | Notes |
|---|---|---|---|
| `-Iso <file>` | `Mount-DiskImage -Access ReadOnly` | `\sources\install.wim` or `install.esd` | ISO hashed first; an ISO already mounted is used and left mounted |
| `-Wim <file>` | `Mount-WindowsImage -ReadOnly` | the chosen index | an `.esd` needs `-ConvertEsd` |
| `-Vhd <file>` | `Mount-VHD -ReadOnly` | the volume holding `Windows\System32\ntdll.dll`, else its `sources\install.wim` | needs the Hyper-V module |
| `-Directory <dir>` | nothing | the directory | no elevation, works on any tree |

ESD images cannot be mounted. With `-ConvertEsd` the chosen index is
exported (`dism /Export-Image /Compress:max`) to `<Out>\..\.tmp\<Label>.wim`,
which then holds that image at index 1. The temporary WIM is deleted in
`finally`. An existing file of that name stops the run instead of being
overwritten.

### 2.3 Parameters

| Parameter | Default | Effect |
|---|---|---|
| `-Out <dir>` | required | corpus directory |
| `-Report <dir>` | `<Out>\..\manifests\<Label>` | report directory; must be outside `-Out` |
| `-Index <n>` | 0 | image index; 0 lists the editions and exits with 2 |
| `-Label <text>` | name of `-Out` | build name; other characters than `A-Z a-z 0-9 . _ -` become `_` |
| `-Arch <list>` | all | passed to `collect_pes.py --arch` |
| `-Python <exe>` | `python` | interpreter for the Python tools |
| `-Resume` | off | `collect_pes.py --resume` |
| `-Force` | off | `collect_pes.py --force` |
| `-NoVerify` | off | skip verification (the corpus is then unverified) |
| `-ConvertEsd` | off | export an ESD image to a temporary WIM first |
| `-DeleteSource` | off | delete the ISO after a run that passed; `-Iso` only, never with `-NoVerify` |

Refused before anything is mounted (exit 2): `-DeleteSource` with
`-NoVerify`, `-DeleteSource` without `-Iso`, a negative `-Index`, a
report directory inside `-Out`. Refused with exit 1: missing companion
scripts, a Python that does not start, a media source without elevation.

### 2.4 Order of a run
1. Check parameters, companion scripts, Python and elevation; warn when
   `LongPathsEnabled` is off (the Python tools use `\\?\` paths anyway).
2. Hash the container (`-Iso`, `-Wim`, `-Vhd`) with SHA-256.
3. Mount the ISO or VHD read-only and locate the image.
4. `-Index 0`: list the editions, exit 2. Otherwise read the image's
   DISM description, export an ESD if needed, and mount the image
   read-only on `<Out>\..\.mnt\<Label>` (which must be empty).
5. Run `collect_pes.py <mount> <Out> --report <Report> --label <Label>`.
   Exit 0 or 3 continues; 130 stops with 130; anything else stops with 1.
6. Write `source.json` (§6.6).
7. Run `verify_corpus.py`, with `--allow-collisions` when collection
   already returned 3, so a collision is reported once.
8. With `-DeleteSource` and a passing run, dismount and delete the ISO.
9. `finally`: dismount the image, the ISO and the VHD, remove the empty
   mount directory and the temporary WIM. Each failure is a `[~]` line,
   never a lost mount.

The exit code is verification's when it failed, otherwise collection's.

### 2.5 Examples

```powershell
# list the editions
.\bin\extract-image.ps1 -Iso D:\media\Win10_22H2.iso -Out D:\corpus\10.0.19045

# collect edition 6 and verify it
.\bin\extract-image.ps1 -Iso D:\media\Win10_22H2.iso -Out D:\corpus\10.0.19045 -Index 6

# an ESD, exported to a temporary WIM first
.\bin\extract-image.ps1 -Wim D:\media\install.esd -ConvertEsd -Index 4 -Out D:\corpus\26200

# an already extracted tree, no elevation
.\bin\extract-image.ps1 -Directory D:\mnt\windows -Out D:\corpus\sample
```

On server media, pick the *Desktop Experience* index: Server Core has no
`SysWOW64`, so the x86 half of the corpus would be empty.

---

## 3. `collect_pes.py`

### 3.1 Purpose
Builds a corpus from a directory: every PE it finds, each distinct
content stored once, with reports that say what was stored, what was
not and why.

```text
python collect_pes.py <image-dir> <out-dir> [options]
```

### 3.2 Discovery
- Every file is considered; a file is a PE when its header passes
  `pelib.sniff_bytes` (§5.2). The extension is never consulted.
- Files under 64 bytes are skipped without being opened.
- Symbolic links and junctions are not followed.
- A path holding a tab or a line break is not collected (it cannot be
  written to a report) and is listed as `[~]`.
- Each PE is hashed with SHA-256. A hardlinked file is hashed once per
  run (`st_dev`, `st_ino`).

### 3.3 Exclusions
Patterns are matched case-insensitively against the path relative to
the image root, as if anchored anywhere. A pattern ending in `/**` also
prunes the directory itself, so its content is never walked.

Default patterns (off with `--no-default-excludes`):
`$Recycle.Bin`, `System Volume Information`, `Windows/WinSxS/Temp`,
`Windows/WinSxS/Backup`, `Windows/SoftwareDistribution`,
`Windows/servicing/LCU`, `Windows/Prefetch`, `Windows/Temp`,
`Windows/Logs`, `Windows/Minidump`, and the files `pagefile.sys`,
`hiberfil.sys`, `swapfile.sys`. `--exclude GLOB` adds more (repeatable).

### 3.4 Locations
Every path gets a location class. Its position in this table is its
rank, used by selection (lower is more authoritative):

| Rank | `location` | Path (case-insensitive) |
|---|---|---|
| 0 | `system32` | `Windows/System32/...` |
| 1 | `syswow64` | `Windows/SysWOW64/...` |
| 2 | `systemapps` | `Windows/SystemApps/...` |
| 3 | `programfiles` | `Program Files...` (also `(x86)`) |
| 4 | `winsxs` | `Windows/WinSxS/...` |
| 5 | `driverstore` | any `.../DriverStore/...`, checked first |
| 6 | `windows` | any other `Windows/...` |
| 7 | `other` | everything else |

One x64 image yields both architectures: `System32` holds x64 and
`SysWOW64` x86.

### 3.5 Selection
PEs are grouped by **(lowercased file name, architecture)**, where the
architecture comes from the COFF machine field (§5.2).

1. **Collisions.** One path found twice when compared without regard to
   case (`Foo.dll` and `foo.dll` in one folder) can only come from a
   case-sensitive source, and cannot be stored on NTFS. The first in
   exact path order is kept; every other is a row of `collisions.tsv`
   and the run exits 3 unless `--allow-collisions`.
2. **Duplicates.** Within a group, identical bytes are stored once, at
   the path with the lowest (rank, lowercased path, path). Every other
   path with those bytes is a row of `duplicates.tsv` and is not stored,
   so a consumer never sees the same bytes twice under one name.
3. **Variants.** Within a group, every distinct content is stored at
   its own path. The best one is `canonical=1` in `modules.tsv`, ordered
   by rank, then highest file version (`VS_FIXEDFILEINFO`, §5.4), then
   lowercased path, then path. The others are variants (`canonical=0`).

Selection is a pure function of the paths and their bytes. It never
depends on the order the walk returned them in.

Files with different names are never compared: `a.dll` and `dup.dll`
with the same bytes are two modules, stored as two hardlinks to one
copy.

A consumer that needs exactly one file per (name, architecture), such
as the AXIS noreturn tables, reads the rows with `canonical=1`.

### 3.6 Storage
- A stored file keeps its image path inside `<out-dir>`.
- New content is written under `<name>.os-corpus-tmp` and renamed over
  the destination. Nothing is ever written into an existing file, so a
  destination hardlinked into another build is replaced, and that build
  keeps its bytes.
- **Hash index.** `<out>/../.hash-index.tsv` (§6.8) maps a digest to a
  stored copy. When it knows the digest and that copy has the right
  size, the file is hardlinked instead of copied, so a second build
  costs only the bytes that changed. Hardlinks need one NTFS volume;
  failing that, the file is copied. `--no-link` always copies.
  `--index none` drops the shared index file: identical bytes are still
  linked within one run, but not across builds.
- A file already in place is kept: same size, and either the previous
  manifest lists it with this digest (`--resume`) or it is the same file
  as the index's copy.

### 3.7 Re-runs
- **Empty output.** A non-empty `<out-dir>` is refused (exit 2) unless
  `--resume`, `--force` or `--dry-run`.
- **`--resume`** reuses `scan-cache.tsv` (a file whose size and mtime
  match is not re-read) and keeps files already in place. `--rehash`
  ignores the cache.
- **`--force`** adds to a non-empty output without the cache.
- **Interruption.** The old manifest is removed before files are placed
  and the new one is written last, so a manifest exists only for a
  completed run. The index is saved even when interrupted, so
  `--resume` links what was already placed instead of copying it again.
  Exit 130.
- **Stale files.** Files in the output that the new manifest does not
  list (after a narrower `--arch`, say) are not deleted. They are counted
  (`stale_files`) and reported with `[~]`; verification fails until they
  are removed. Leftover `.os-corpus-tmp` files are removed.
- **`--dry-run`** scans, selects and prints the counts, and writes
  nothing, not even the report directory. The cheap way to check that a
  mount is the image you think it is.
- Re-running with the same input and options rewrites `manifest.sha256`,
  `modules.tsv`, `duplicates.tsv` and `collisions.tsv` byte for byte;
  only `summary.json` and `scan-cache.tsv` carry time.

### 3.8 Options

| Option | Default | Effect |
|---|---|---|
| `--report DIR` | `<out>/../manifests/<out-name>` | report directory; must be outside the corpus |
| `--index PATH` | `<out>/../.hash-index.tsv` | shared hardlink index; `none` disables it |
| `--label TEXT` | name of `<out-dir>` | recorded in `summary.json` |
| `--resume` | off | reuse the scan cache, keep files in place |
| `--rehash` | off | ignore the scan cache even with `--resume` |
| `--dry-run` | off | write nothing |
| `--no-link` | off | always copy |
| `--arch LIST` | all | comma separated, e.g. `x64,x86` |
| `--exclude GLOB` | none | extra exclusion, repeatable |
| `--no-default-excludes` | off | do not skip the §3.3 locations |
| `--allow-collisions` | off | exit 0 even with collisions |
| `--force` | off | allow a non-empty output |
| `-q`, `--quiet` | off | warnings, errors and the closing line only |

### 3.9 Order of a run
1. Check the paths: source is a directory, source and output do not
   contain each other, report and index are outside the output (exit 2).
2. With `--resume`, read `scan-cache.tsv` and the previous manifest.
   Load the hash index.
3. Scan (§3.2, §3.3), filter by `--arch`. No PE at all is an error (1).
4. Split off collisions, group, select (§3.5); read the version and
   classification of every stored file from the source.
5. Remove the old manifest, place every stored file (§3.6), save the index.
6. Report stale files.
7. Write the reports that changed, `manifest.sha256` last.
8. Print the counts, every collision (`[!]`, up to 20) and the closing line.

---

## 4. `verify_corpus.py`

### 4.1 Purpose
Re-checks a finished corpus without trusting the run that built it.
Every file is re-read from disk and every report is cross-checked
against the manifest. A corpus is trustworthy when this passes on a
machine that did not build it, which is why verification is a separate
process and not a flag of collection.

```text
python verify_corpus.py <out-dir> [--report DIR] [--fast] [--allow-collisions] [-q]
```

### 4.2 Checks
In this order. A failure is printed as `[!]` and sets the exit code
shown; every check runs, so one run lists every problem.

| Check | Fails (exit) when | Warns when |
|---|---|---|
| `manifest` | a line has no double space, a digest is not 64 lowercase hex characters, a path is absolute, holds `:` or `..` (4) | |
| `tree` | a manifest path is missing on disk, or a file on disk is not in the manifest (4) | |
| `hashes` | a file's SHA-256 differs from the manifest (4) | `--fast` |
| `sizes` | a file's size differs from `modules.tsv` (4) | |
| `modules` | unexpected columns, a path listed twice, paths or digests that differ from the manifest, a (name, arch) group without exactly one `canonical=1` row (5) | |
| `duplicates` | unexpected columns, a `kept` path that is not stored, a `duplicate` path that is stored (5) | file missing |
| `collisions` | unexpected columns (5); any row (3) | file missing; rows with `--allow-collisions` |
| `summary` | `stored_files`, `distinct_modules` or `stored_total` disagree with the manifest, `modules.tsv` or the tree (5) | file missing or unreadable |
| `identity` | `source.json` `manifestSha256` is not the SHA-256 of `manifest.sha256` (4) | no `source.json`, or no hash in it |
| `revision` | `source.json` `revision` differs from the file version of `Windows/System32/ntdll.dll` (4) | no revision, no ntdll, no version resource |
| `presence` | | no `Windows/System32/ntdll.dll` (partial tree?) |

A missing or unreadable `manifest.sha256` stops at once with exit 1:
the collection run did not complete.

### 4.3 Options

| Option | Effect |
|---|---|
| `--report DIR` | report directory, default `<out>/../manifests/<out-name>` |
| `--fast` | skip `hashes`; existence and sizes are still checked |
| `--allow-collisions` | collisions warn instead of failing |
| `-q`, `--quiet` | warnings, failures and the closing line only |

---

## 5. `pelib.py`

### 5.1 Purpose
The PE primitives the other tools share. Nothing in it writes a file.

```text
python pelib.py info <file>     everything below for one file, as JSON (exit 1: not a PE)
python pelib.py version         the os-corpus version
```

### 5.2 Sniffing
`sniff_bytes(head, file_size)` reads the first 4 KB of a file and
returns its properties, or `None`. It never raises on malformed input.
A file is a PE when:

1. it starts with `MZ` and is at least 64 bytes;
2. `e_lfanew` is at least 0x40 and the PE signature, the COFF header and
   the optional-header magic lie inside the 4 KB;
3. the signature is `PE\0\0`;
4. the magic is 0x10B (PE32) or 0x20B (PE32+);
5. it has 1 to 96 sections;
6. the optional header is at least 96 (PE32) or 112 (PE32+) bytes;
7. the section table ends inside the file, and `SizeOfHeaders` is
   neither 0 nor past the end of the file.

Architecture, from the COFF machine field: `x86` (0x14C), `x64`
(0x8664), `arm` (0x1C4), `arm64` (0xAA64), `arm64ec` (0xA641), `ia64`
(0x200), `riscv32` (0x5032), `riscv64` (0x5064), anything else `other`.

### 5.3 Classification
From header fields only; nothing is executed or resolved.

| Field | Values | Rule, first match wins |
|---|---|---|
| `kind` | `efi` | subsystem 10 to 13 (EFI application, boot driver, runtime driver, ROM) |
| | `resource` | DLL with `AddressOfEntryPoint` 0 and `SizeOfCode` 0 (MUI and other resource-only DLLs) |
| | `native` | subsystem 1: kernel drivers, kernel-mode DLLs, native programs such as `smss.exe` |
| | `dll` | any other DLL (`IMAGE_FILE_DLL`) |
| | `exe` | anything else |
| `clr` | 0 / 1 | the CLR data directory (14) has a size: a .NET assembly |
| `embedded_signature` | 0 / 1 | the certificate table (data directory 4) has a size |

`clr` and `arch` are independent: an AnyCPU assembly has machine 0x14C,
so its `arch` is `x86` and `clr` marks it. `embedded_signature` is not
validated, and most Windows binaries are catalog-signed and carry no
embedded signature, so 0 does not mean unsigned.

Subsystem names: 1 `native`, 2 `gui`, 3 `cui`, 5 `os2`, 7 `posix`,
9 `windows-ce`, 10 `efi-app`, 11 `efi-boot`, 12 `efi-runtime`,
13 `efi-rom`, 14 `xbox`, 16 `windows-boot`; other values as a number.

### 5.4 Versions
`version_of(path)` maps the file and follows the resource directory to
`RT_VERSION` (first name, first language). `file_version` and
`product_version` come from `VS_FIXEDFILEINFO` as four numbers when it
is present, otherwise from the `FileVersion` / `ProductVersion` strings.
`CompanyName`, `FileDescription` and `OriginalFilename` are read too.
Every read is bounds-checked; a malformed resource gives an empty result.

### 5.5 Other functions

| Function | Returns |
|---|---|
| `long_path(path, force)` | a `\\?\` (or `\\?\UNC\`) path on Windows when needed or forced; the path unchanged elsewhere |
| `sha256_file(path)` | lowercase hex SHA-256, streamed in 1 MB chunks |
| `read_head(path)` | the first 4 KB, or `b""` |
| `pe_info(path)` | sniffing, classification, version and size in one dict, or `None` |
| `version_tuple(text)` | a dotted version as four integers, for ordering |

---

## 6. Output formats

### 6.1 `manifest.sha256`
`<sha256>  <path>` per stored file: lowercase hex, two spaces, forward
slashes, sorted by path, no header. `sha256sum -c` reads it from the
corpus root. A corpus is identified by the SHA-256 of this file.

### 6.2 `modules.tsv` (`os-corpus/modules/1`)
One row per stored file, sorted by lowercased name, architecture,
canonical first, path. Header row, tab separated.

| Column | Meaning |
|---|---|
| `name` | file name as found |
| `arch` | architecture (§5.2) |
| `canonical` | 1 for the chosen file of its (name, arch) group, 0 for a variant (§3.5) |
| `kind` | `exe`, `dll`, `native`, `resource`, `efi` (§5.3) |
| `location` | location class (§3.4) |
| `format` | `pe32` or `pe32+` |
| `machine` | COFF machine as `0x%04x` |
| `dll` | 1 when `IMAGE_FILE_DLL` is set |
| `clr` | 1 for a .NET assembly |
| `embedded_signature` | 1 when an Authenticode blob is embedded |
| `subsystem` | subsystem name (§5.3) |
| `file_version`, `product_version` | §5.4, empty without a version resource |
| `size` | bytes |
| `sha256` | content digest |
| `path` | path in the corpus and in the image |

### 6.3 `duplicates.tsv` (`os-corpus/duplicates/1`)

| Column | Meaning |
|---|---|
| `name`, `arch` | the group |
| `sha256` | the shared content |
| `kept` | the stored path |
| `duplicate` | a path with the same name, architecture and bytes, not stored |

### 6.4 `collisions.tsv` (`os-corpus/collisions/1`)

| Column | Meaning |
|---|---|
| `path`, `sha256` | the stored file |
| `other`, `other_sha256` | the same path in another case, not stored |

### 6.5 `summary.json` (`os-corpus/summary/1`)

| Field | Meaning |
|---|---|
| `tool` | `{name, version}` |
| `source` | `{name, kind, label}`: the image folder's name, `directory`, the label |
| `counts.files_seen` | files considered after exclusions |
| `counts.pe_files` | PEs after the architecture filter |
| `counts.stored_files` | manifest rows |
| `counts.distinct_modules` | (name, arch) groups, i.e. `canonical=1` rows |
| `counts.variants` | stored files with `canonical=0` |
| `counts.duplicate_paths` | `duplicates.tsv` rows |
| `counts.collisions` | `collisions.tsv` rows |
| `counts.pruned_paths` | excluded files and directories |
| `counts.skipped_existing` | files already in place |
| `counts.stale_files` | files in the output not in the manifest |
| `bytes.stored_total` | sum of stored file sizes |
| `bytes.copied_unique` | bytes copied by this run |
| `bytes.linked_existing` | bytes hardlinked instead of copied |
| `arch` | canonical modules per architecture |
| `kinds`, `locations` | stored files per kind and per location |
| `reports` | schema ID of every TSV report |
| `excludes` | the patterns in effect |
| `options` | `{arch, link, sharedIndex}`: the filter, whether hardlinks were allowed, whether the index file was used |
| `dryRun`, `started`, `finished`, `elapsed_seconds` | run facts (UTC) |

### 6.6 `source.json` (`os-corpus/source/1`, written by the wrapper)

| Field | Meaning |
|---|---|
| `tool` | `{name, version}` |
| `kind` | `iso`, `wim`, `vhd` or `directory` |
| `image` | `{name, bytes, sha256}` of the container; bytes 0 and an empty hash for a directory |
| `container` | DISM description of the image, `null` for a directory or a VHD volume: `name` (`install.wim` / `install.esd`), `imageIndex`, `imageName`, `edition`, `installationType`, `architecture`, `build` (`major.minor.build.spbuild`), `languages` |
| `revision` | file version of `Windows/System32/ntdll.dll` in the corpus |
| `manifestSha256` | SHA-256 of `manifest.sha256`, which binds the media to the corpus |
| `collectedFiles` | manifest rows |
| `acquired` | UTC time |

`revision` is ntdll's own version and can differ from the OS build:
Windows 10 22H2 (build 19045) ships ntdll `10.0.19041.x`. `container.build`
is the OS build DISM reports.

### 6.7 `scan-cache.tsv`
`sha256, arch, size, mtime_ns, path` per PE seen, no header. Read only
with `--resume`; not evidence, safe to delete.

### 6.8 `.hash-index.tsv`
`sha256, path` per known content, no header, absolute paths. It is a
local accelerator shared by every build under one root, not a report:
never publish it. A path whose content is replaced is dropped from it.

---

## 7. Known Implementation Gaps

- **PE header past 4 KB.** A file whose PE signature starts after the
  first 4 KB is not recognised. Legal but not seen in Windows media.
- **`native` is not split.** Kernel drivers, kernel-mode DLLs and
  native programs share one kind; telling them apart needs the import
  table, which is not parsed.
- **`clr` does not read the CLR header.** AnyCPU and x86-only
  assemblies both stay `x86`.
- **Signatures are not validated**, and catalog signatures are not
  seen at all (§5.3).
- **One version per file**: the first name and language of
  `RT_VERSION`.
- **The hash index holds absolute paths.** Moving the corpus root makes
  it fall back to copying until the index is rebuilt by a run.
- **Hardlinks need one NTFS volume.** A plain copy of a corpus to
  another place duplicates the shared bytes; use a tool that keeps
  hardlinks (a backup tool such as `restic`, or `rsync -H`).
- **No parallel hashing.** A compressed WIM mount is limited by
  decompression; to be measured before adding threads.
- **Exclusion patterns are `fnmatch` patterns**, so `[` in a pattern
  starts a character class.
- **Only the `-Directory` path of `extract-image.ps1` is tested.** ISO,
  WIM, ESD and VHD need elevation and real media. The DISM fields of
  `source.json` `container` (`MajorVersion`, `Build`, `SPBuild`,
  `EditionId`, `Languages`) have not yet been checked against real media.
- **Variants make the corpus larger** than one file per name. There is
  no option to store the canonical files only.
