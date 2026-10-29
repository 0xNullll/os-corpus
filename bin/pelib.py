#!/usr/bin/env python3
"""
pelib.py: the PE primitives os-corpus is built on. Header sniffing, machine mapping, module
classification, version-resource extraction, streaming hashes and Windows long-path handling.
Standard library only; imported by collect_pes.py and verify_corpus.py.

    python pelib.py info <file>         print what the tools see in one file, as JSON
    python pelib.py version             print the os-corpus version

Sniffing
    A file is a PE only when the first 4 KB hold MZ, an in-range e_lfanew, PE\\0\\0, a PE32 or
    PE32+ optional-header magic, 1 to 96 sections and a header table that fits inside the file.
    The extension is never consulted. A file whose PE header starts past the first 4 KB is not
    recognised (USAGE.md, known gaps).

Classification (from the headers alone, nothing is executed or resolved)
    kind       efi       subsystem EFI application, boot, runtime driver or ROM
               resource  DLL with no entry point and no code (MUI and other resource-only DLLs)
               native    subsystem NATIVE: kernel drivers, kernel-mode DLLs, native programs
               dll       any other DLL
               exe       anything else
    clr        1 when the CLR (.NET) data directory is present. The COFF machine of an AnyCPU
               assembly is still x86, so arch stays what the header says and clr marks it.
    embedded_signature
               1 when the certificate table holds an Authenticode blob. It is not validated, and
               catalog-signed files (most of Windows) carry none, so 0 does not mean unsigned.

Exit code 0 on success, 1 when the file is not a PE, 2 on bad usage.
"""

from __future__ import annotations

import hashlib
import json
import mmap
import os
import struct
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

# ---- CONFIG ----

VERSION = "0.1.0"

# Version of what pe_info returns (sniffing, classification, version parsing). Bump it when a
# change here alters a result, so collect_pes.py stops trusting info cached by an older run.
INFO_VERSION = 1

# Parallel hashing default: the CPU count, at most this. Measured on an NVMe SSD: 1 thread
# 139 MB/s, 4 threads 539 MB/s, 8 threads 958 MB/s.
MAX_DEFAULT_JOBS = 8

PE32 = 0x10B
PE32_PLUS = 0x20B
_OPT_MAGIC = {PE32: "pe32", PE32_PLUS: "pe32+"}

# COFF machine field to architecture name. Anything else is "other".
MACHINES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C4: "arm",
    0xAA64: "arm64",
    0xA641: "arm64ec",
    0x0200: "ia64",
    0x5032: "riscv32",
    0x5064: "riscv64",
}

SUBSYSTEMS = {
    1: "native",
    2: "gui",
    3: "cui",
    5: "os2",
    7: "posix",
    9: "windows-ce",
    10: "efi-app",
    11: "efi-boot",
    12: "efi-runtime",
    13: "efi-rom",
    14: "xbox",
    16: "windows-boot",
}
_EFI_SUBSYSTEMS = (10, 11, 12, 13)
_NATIVE = 1

KINDS = ("efi", "resource", "native", "dll", "exe")

# Data directory indexes read by the classification.
_DIR_SECURITY = 4
_DIR_CLR = 14

SNIFF_BYTES = 0x1000
_CHUNK = 1 << 20
_MAX_SECTIONS = 96
_LONG_PATH_MIN = 240
_MAX_VERSION_BLOB = 1 << 20


def fail(message, code=1):
    sys.stdout.flush()  # keep stdout lines ahead of the error in a shared log
    print("[!] pelib: %s" % message, file=sys.stderr)
    return code


# ---- PATHS AND HASHING ----

def long_path(path, force=False):
    """Return a path usable past MAX_PATH on Windows.

    The \\\\?\\ prefix is only added when needed, unless ``force`` is set, so paths in messages
    stay readable. Other systems get the path back unchanged.
    """
    if os.name != "nt":
        return path
    p = os.path.abspath(path)
    if p.startswith("\\\\?\\"):
        return p
    if not force and len(p) < _LONG_PATH_MIN:
        return path
    if p.startswith("\\\\"):
        return "\\\\?\\UNC\\" + p[2:]
    return "\\\\?\\" + p


def sha256_file(path):
    """Stream a file through SHA-256 and return lowercase hex."""
    h = hashlib.sha256()
    with open(long_path(path, True), "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def read_head(path):
    """The first SNIFF_BYTES of a file, or b"" when it cannot be read."""
    try:
        with open(long_path(path, True), "rb") as f:
            return f.read(SNIFF_BYTES)
    except OSError:
        return b""


# ---- PE SNIFFING ----

def _u16(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def classify(subsystem, dll, entry, code_size):
    """The kind of a module, from header fields only (see the module docstring)."""
    if subsystem in _EFI_SUBSYSTEMS:
        return "efi"
    if dll and entry == 0 and code_size == 0:
        return "resource"
    if subsystem == _NATIVE:
        return "native"
    return "dll" if dll else "exe"


def _data_directory(head, opt, magic, opt_size, index):
    """(rva or offset, size) of one data directory, or (0, 0) when the header has none."""
    count_off = opt + (92 if magic == PE32 else 108)
    dirs = opt + (96 if magic == PE32 else 112)
    entry = dirs + 8 * index
    if count_off + 4 > opt + opt_size or entry + 8 > opt + opt_size:
        return 0, 0
    if entry + 8 > len(head) or _u32(head, count_off) <= index:
        return 0, 0
    return _u32(head, entry), _u32(head, entry + 4)


def sniff_bytes(head, file_size=None):
    """Validate a PE header and return its properties, or None.

    ``head`` needs the first 4 KB (or the whole file, whichever is smaller).
    ``file_size``, when given, rejects images whose header table cannot fit.
    Never raises on malformed input.
    """
    try:
        return _sniff(head, file_size)
    except (struct.error, IndexError):
        return None


def _sniff(head, file_size):
    if len(head) < 0x40 or head[:2] != b"MZ":
        return None
    e = _u32(head, 0x3C)
    # The signature, the COFF header (20 bytes) and the optional-header magic (2 bytes).
    if e < 0x40 or e + 26 > len(head):
        return None
    if head[e:e + 4] != b"PE\0\0":
        return None
    machine, nsections = struct.unpack_from("<HH", head, e + 4)
    opt_size = _u16(head, e + 20)
    characteristics = _u16(head, e + 22)
    opt = e + 24
    magic = _u16(head, opt)
    if magic not in _OPT_MAGIC:
        return None
    if not 1 <= nsections <= _MAX_SECTIONS:
        return None
    if opt_size < (96 if magic == PE32 else 112):
        return None
    table_end = opt + opt_size + 40 * nsections
    if file_size is not None and table_end > file_size:
        return None

    dll = bool(characteristics & 0x2000)
    info = {
        "arch": MACHINES.get(machine, "other"),
        "machine": machine,
        "magic": _OPT_MAGIC[magic],
        "sections": nsections,
        "dll": dll,
        "characteristics": characteristics,
        "timestamp": _u32(head, e + 8),
    }
    if table_end <= len(head):
        size_of_headers = _u32(head, opt + 60)
        if size_of_headers == 0:
            return None
        if file_size is not None and size_of_headers > file_size:
            return None
        info["size_of_headers"] = size_of_headers

    if opt + 70 <= len(head):
        subsystem = _u16(head, opt + 68)
        entry = _u32(head, opt + 16)
        code_size = _u32(head, opt + 4)
        info["subsystem"] = subsystem
        info["entry_point"] = entry
        info["kind"] = classify(subsystem, dll, entry, code_size)
        info["clr"] = _data_directory(head, opt, magic, opt_size, _DIR_CLR)[1] > 0
        info["embedded_signature"] = _data_directory(head, opt, magic, opt_size, _DIR_SECURITY)[1] > 0
    return info


def sniff_file(path, size=None):
    """Open ``path``, validate the header, and return its properties."""
    try:
        with open(long_path(path, True), "rb") as f:
            head = f.read(SNIFF_BYTES)
            if size is None:
                size = os.fstat(f.fileno()).st_size
    except OSError:
        return None
    return sniff_bytes(head, size)


# ---- VERSION RESOURCES ----

class _View:
    """Bounds-checked little-endian reader over bytes or an mmap."""

    __slots__ = ("buf", "size")

    def __init__(self, buf, size):
        self.buf = buf
        self.size = size

    def _check(self, off, n):
        if off < 0 or n < 0 or off + n > self.size:
            raise ValueError("read past end of buffer")

    def u16(self, off):
        self._check(off, 2)
        return struct.unpack_from("<H", self.buf, off)[0]

    def u32(self, off):
        self._check(off, 4)
        return struct.unpack_from("<I", self.buf, off)[0]

    def raw(self, off, n):
        self._check(off, n)
        return bytes(self.buf[off:off + n])


def _align4(n):
    return (n + 3) & ~3


def _read_utf16z(view, pos, limit):
    chars = []
    while pos + 2 <= limit:
        c = view.u16(pos)
        pos += 2
        if c == 0:
            break
        chars.append(chr(c))
    return "".join(chars), pos


def _read_utf16(view, pos, nbytes):
    raw = view.raw(pos, nbytes)
    text = raw.decode("utf-16-le", "replace")
    return text.split("\x00", 1)[0]


def _rva_to_offset(view, pe, rva):
    opt = pe + 24
    if view.u16(opt) not in _OPT_MAGIC:
        return None
    nsec = view.u16(pe + 6)
    table = opt + view.u16(pe + 20)
    for i in range(nsec):
        s = table + 40 * i
        vsize = view.u32(s + 8)
        va = view.u32(s + 12)
        raw_size = view.u32(s + 16)
        raw_ptr = view.u32(s + 20)
        if va <= rva < va + max(vsize, raw_size):
            delta = rva - va
            if delta >= raw_size:
                return None
            return raw_ptr + delta
    return None


def _resource_entries(view, base, rel):
    d = base + rel
    named = view.u16(d + 12)
    ids = view.u16(d + 14)
    for i in range(named + ids):
        o = d + 16 + i * 8
        yield view.u32(o), bool(view.u32(o + 4) & 0x80000000), view.u32(o + 4) & 0x7FFFFFFF


def _version_blob(view):
    """Locate RT_VERSION in a mapped PE and return its bytes (first name, first language)."""
    if view.u16(0) != 0x5A4D:
        return None
    pe = view.u32(0x3C)
    if view.u32(pe) != 0x00004550:
        return None
    opt = pe + 24
    magic = view.u16(opt)
    if magic not in _OPT_MAGIC:
        return None
    dirs = opt + (96 if magic == PE32 else 112)
    if view.u32(dirs - 4) < 3:
        return None
    res_rva = view.u32(dirs + 16)
    if not res_rva:
        return None
    base = _rva_to_offset(view, pe, res_rva)
    if base is None:
        return None

    type_rel = next((off for ident, is_dir, off in _resource_entries(view, base, 0)
                     if ident == 16 and is_dir), None)
    if type_rel is None:
        return None
    name_rel = next((off for _, is_dir, off in _resource_entries(view, base, type_rel)
                     if is_dir), None)
    if name_rel is None:
        return None
    data_rel = next((off for _, _, off in _resource_entries(view, base, name_rel)), None)
    if data_rel is None:
        return None

    entry = base + data_rel
    rva = view.u32(entry)
    length = view.u32(entry + 4)
    if not rva or not length or length > _MAX_VERSION_BLOB:
        return None
    offset = _rva_to_offset(view, pe, rva)
    if offset is None:
        return None
    return view.raw(offset, length)


def _walk_version(view, start, limit, fixed, strings, depth=0):
    if depth > 8 or start + 6 > limit:
        return
    length = view.u16(start)
    value_length = view.u16(start + 2)
    value_type = view.u16(start + 4)
    if length < 6:
        return
    end = min(start + length, limit)
    key, pos = _read_utf16z(view, start + 6, end)
    value_bytes = value_length * (2 if value_type else 1)
    value_start = _align4(pos)
    children_start = _align4(value_start + value_bytes)

    if key == "VS_VERSION_INFO" and value_bytes >= 52 and value_start + 52 <= end:
        if view.u32(value_start) == 0xFEEF04BD:
            fixed[:] = [
                (view.u32(value_start + 8), view.u32(value_start + 12)),
                (view.u32(value_start + 16), view.u32(value_start + 20)),
            ]
    elif value_type == 1 and value_bytes:
        strings[key] = _read_utf16(view, value_start, value_bytes)

    off = children_start
    for _ in range(64):
        if off + 6 > end:
            break
        child_length = view.u16(off)
        if child_length < 6:
            break
        _walk_version(view, off, min(off + child_length, end), fixed, strings, depth + 1)
        off = _align4(off + child_length)


def _version_string(ms, ls):
    parts = (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)
    if not any(parts):
        return ""
    return "%d.%d.%d.%d" % parts


def parse_version_blob(blob):
    """Parse a raw RT_VERSION resource into a dict.

    ``file_version`` and ``product_version`` come from VS_FIXEDFILEINFO when it is present, so
    they are numeric four-part strings; otherwise from the FileVersion / ProductVersion strings.
    """
    view = _View(blob, len(blob))
    fixed = []
    strings = {}
    try:
        _walk_version(view, 0, len(blob), fixed, strings)
    except (ValueError, struct.error):
        pass

    if fixed:
        file_version = _version_string(*fixed[0])
        product_version = _version_string(*fixed[1])
    else:
        file_version = strings.get("FileVersion", "")
        product_version = strings.get("ProductVersion", "")

    return {
        "file_version": file_version,
        "product_version": product_version,
        "company": strings.get("CompanyName", ""),
        "description": strings.get("FileDescription", ""),
        "original_filename": strings.get("OriginalFilename", ""),
        "strings": strings,
        "fixed": bool(fixed),
    }


def version_of(path):
    """Return version metadata for a PE, or an empty dict."""
    try:
        with open(long_path(path, True), "rb") as f:
            size = os.fstat(f.fileno()).st_size
            if size <= 0:
                return {}
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as view:
                blob = _version_blob(_View(view, size))
                if blob is None:
                    return {}
                return parse_version_blob(blob)
    except (OSError, ValueError, struct.error, IndexError):
        return {}


def version_tuple(text):
    """A dotted version as four integers for ordering; missing or non-numeric parts are 0."""
    parts = []
    for piece in (text or "").split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            parts.append(0)
    parts += [0] * (4 - len(parts))
    return tuple(parts[:4])


def pe_info(path, size=None):
    """Sniff, classification and version metadata. Returns None for non-PE files."""
    info = sniff_file(path, size)
    if info is None:
        return None
    info.update(version_of(path))
    try:
        info["size"] = os.path.getsize(long_path(path, True)) if size is None else size
    except OSError:
        info["size"] = 0
    return info


# ---- PARALLEL ----

def default_jobs():
    return max(1, min(MAX_DEFAULT_JOBS, os.cpu_count() or 1))


def ordered_map(func, items, jobs, window=None):
    """Yield (item, func(item)) in input order, running up to ``jobs`` calls in threads.

    hashlib and file reads release the GIL, so threads overlap I/O and hashing. At most
    ``window`` calls are in flight (default 8 per job), so ``items`` can be a lazy walk. With
    jobs 1 everything runs inline. ``func`` handles its own errors.
    """
    if jobs <= 1:
        for item in items:
            yield item, func(item)
        return
    window = window or jobs * 8
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        pending = deque()
        for item in items:
            pending.append((item, pool.submit(func, item)))
            if len(pending) >= window:
                done, future = pending.popleft()
                yield done, future.result()
        while pending:
            done, future = pending.popleft()
            yield done, future.result()


# ---- PROGRESS ----

def byte_string(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%d B" % n if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0
    return "%d B" % n


def duration(seconds):
    """12.3s, 4m05s, 1h02m."""
    if seconds < 60:
        return "%.1fs" % seconds
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return "%dm%02ds" % (minutes, secs)
    hours, minutes = divmod(minutes, 60)
    return "%dh%02dm" % (hours, minutes)


def eta(elapsed, done, total):
    """', ETA 1m40s' from the share done so far, or '' before there is anything to go on."""
    if done <= 0 or total <= done:
        return ""
    return ", ETA " + duration(elapsed * (total - done) / done)


class Progress:
    """Progress of one long phase, so a quiet stretch never looks like a hang.

    On a console, one [i] line is redrawn in place every LIVE_SECONDS. Anywhere else (a pipe,
    a log file, extract-image.ps1) a plain [i] line is printed every LOG_SECONDS. ``tick``
    takes a function, so the line is only formatted when it is printed.
    """

    LIVE_SECONDS = 0.5
    LOG_SECONDS = 10.0

    def __init__(self, enabled=True, stream=None):
        self.stream = stream or sys.stdout
        self.enabled = enabled
        try:
            self.live = enabled and self.stream.isatty()
        except (AttributeError, ValueError):
            self.live = False
        self.started = time.monotonic()
        self.last = self.started
        self.width = 0

    def elapsed(self):
        return time.monotonic() - self.started

    def tick(self, render):
        if not self.enabled:
            return
        now = time.monotonic()
        if now - self.last < (self.LIVE_SECONDS if self.live else self.LOG_SECONDS):
            return
        self.last = now
        line = "[i] %s, %s" % (render(), duration(now - self.started))
        if self.live:
            self.stream.write("\r" + line.ljust(self.width))
            self.width = len(line)
        else:
            self.stream.write(line + "\n")
        self.stream.flush()

    def clear(self):
        """Remove the live line, before the next regular line is printed."""
        if self.live and self.width:
            self.stream.write("\r" + " " * self.width + "\r")
            self.stream.flush()
            self.width = 0


# ---- COMMAND LINE ----

_USAGE = """usage: pelib.py info <file>
       pelib.py version
"""


def _cli(argv):
    if not argv or argv[0] in ("-h", "--help"):
        sys.stderr.write(_USAGE)
        return 2
    if argv[0] == "version" and len(argv) == 1:
        print(VERSION)
        return 0
    if argv[0] == "info" and len(argv) == 2:
        info = pe_info(argv[1])
        if info is None:
            return fail("not a PE: %s" % argv[1])
        print(json.dumps(info, indent=2, sort_keys=True))
        return 0
    sys.stderr.write(_USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
