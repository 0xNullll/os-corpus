"""Shared fixtures for the os-corpus tests: synthetic PE images, version resources, a fake
Windows image tree, and helpers that run the real command line tools as subprocesses.

Not a test module itself (no test_ prefix); the test modules import it.
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"
sys.path.insert(0, str(BIN))

COLLECT = str(BIN / "collect_pes.py")
VERIFY = str(BIN / "verify_corpus.py")
PELIB = str(BIN / "pelib.py")
DIFF = str(BIN / "diff_corpus.py")
WRAPPER = str(BIN / "extract-image.ps1")

PE32, PE32_PLUS = 0x10B, 0x20B
X86, X64 = 0x014C, 0x8664
CUI, NATIVE, EFI_APP = 3, 1, 10


# ---- SYNTHETIC PEs ----

def _resource_section(blob, rva):
    """A .rsrc section holding one RT_VERSION resource (type 16, id 1, language 0x409)."""
    def directory(entry_id, target):
        return struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", entry_id, target)

    data = directory(16, 0x80000000 | 0x18)
    data += directory(1, 0x80000000 | 0x30)
    data += directory(0x409, 0x48)
    data += struct.pack("<IIII", rva + 0x58, len(blob), 0, 0)
    return data + blob


def pe_bytes(marker=b"A", machine=X64, magic=None, dll=True, size=0x400, subsystem=CUI,
             entry=0x1000, code_size=0x200, clr=False, cert=False, version=None):
    """A minimal but structurally valid PE image.

    ``version`` (four integers) adds a .rsrc section with a VS_VERSIONINFO resource.
    """
    if magic is None:
        magic = PE32 if machine == X86 else PE32_PLUS
    opt_size = 224 if magic == PE32 else 240
    rsrc = _resource_section(version_blob(version), 0x2000) if version else b""
    rsrc_raw = (len(rsrc) + 0x1FF) & ~0x1FF
    data = bytearray(max(size, 0x400 + rsrc_raw))

    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    struct.pack_into("<I", data, 0x80, 0x00004550)
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 2 if rsrc else 1, 0, 0, 0, opt_size,
                     0x2102 if dll else 0x0102)
    opt = 0x98
    struct.pack_into("<H", data, opt, magic)
    struct.pack_into("<I", data, opt + 4, code_size)
    struct.pack_into("<I", data, opt + 16, entry)
    struct.pack_into("<I", data, opt + 56, 0x3000)
    struct.pack_into("<I", data, opt + 60, 0x200)
    struct.pack_into("<H", data, opt + 68, subsystem)
    dirs = opt + (96 if magic == PE32 else 112)
    struct.pack_into("<I", data, dirs - 4, 16)
    if rsrc:
        struct.pack_into("<II", data, dirs + 8 * 2, 0x2000, len(rsrc))
    if cert:
        struct.pack_into("<II", data, dirs + 8 * 4, 0x300, 0x10)
    if clr:
        struct.pack_into("<II", data, dirs + 8 * 14, 0x1100, 0x48)

    sec = opt + opt_size
    data[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, sec + 8, 0x200, 0x1000, 0x200, 0x200)
    if rsrc:
        data[sec + 40:sec + 48] = b".rsrc\x00\x00\x00"
        struct.pack_into("<IIII", data, sec + 48, len(rsrc), 0x2000, rsrc_raw, 0x400)
        data[0x400:0x400 + len(rsrc)] = rsrc
    data[0x200:0x200 + len(marker)] = marker
    return bytes(data)


def write_pe(path, **kwargs):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pe_bytes(**kwargs))
    return path


# ---- VERSION RESOURCES ----

def vblock(key, value=b"", vtype=0, vlen=None, children=b""):
    key_raw = key.encode("utf-16-le") + b"\x00\x00"
    if vlen is None:
        vlen = len(value) // (2 if vtype else 1)
    head = struct.pack("<HHH", 0, vlen, vtype) + key_raw
    head += b"\x00" * ((-len(head)) % 4)
    body = head + value + children
    body += b"\x00" * ((-len(body)) % 4)
    return struct.pack("<H", len(body)) + body[2:]


def vstring(key, text):
    value = text.encode("utf-16-le") + b"\x00\x00"
    return vblock(key, value, vtype=1, vlen=len(value) // 2)


def version_blob(file_version=(10, 0, 19045, 3803), product_version=None, strings=None):
    product_version = product_version or file_version
    fixed = struct.pack(
        "<13I", 0xFEEF04BD, 0x00010000,
        (file_version[0] << 16) | file_version[1],
        (file_version[2] << 16) | file_version[3],
        (product_version[0] << 16) | product_version[1],
        (product_version[2] << 16) | product_version[3],
        0x3F, 0, 0x40004, 1, 0, 0, 0)
    table = vblock("040904B0", b"", vtype=1, vlen=0,
                   children=b"".join(vstring(k, v) for k, v in (strings or {}).items()))
    return vblock("VS_VERSION_INFO", fixed, vtype=0, vlen=52,
                  children=vblock("StringFileInfo", b"", vtype=1, vlen=0, children=table))


def edge_lfanew_bytes():
    """MZ whose PE signature ends exactly at the 4 KB sniff boundary (once crashed the scan)."""
    data = bytearray(0x1000)
    data[0:2] = b"MZ"
    e = 0x1000 - 24
    struct.pack_into("<I", data, 0x3C, e)
    data[e:e + 4] = b"PE\0\0"
    return bytes(data)


# ---- FAKE IMAGE ----

# Path -> pe_bytes arguments of the standard fake image. Comments give the expected outcome.
IMAGE = {
    "Windows/System32/a.dll": dict(marker=b"A"),                                # canonical
    "Windows/SysWOW64/a.dll": dict(marker=b"A32", machine=X86),                 # canonical x86
    "Windows/WinSxS/amd64_comp/a.dll": dict(marker=b"A"),                       # duplicate
    "Windows/System32/dup.dll": dict(marker=b"A"),                              # same bytes, other name
    "Windows/System32/b.dll": dict(marker=b"B1"),                               # canonical
    "Windows/WinSxS/amd64_comp/b.dll": dict(marker=b"B2"),                      # variant
    "Program Files/App/tool.exe": dict(marker=b"T", dll=False),                 # exe
    "Windows/System32/en-US/a.dll.mui": dict(marker=b"M", entry=0, code_size=0),  # resource
    "Windows/System32/drivers/x.sys": dict(marker=b"S", dll=False, subsystem=NATIVE),
    "Windows/Microsoft.NET/Framework/v4.0.30319/System.dll": dict(marker=b"N", machine=X86, clr=True),
    "$Recycle.Bin/gone.dll": dict(marker=b"R"),                                 # excluded
    "Windows/SoftwareDistribution/Download/patch.dll": dict(marker=b"P"),       # excluded
}

# Paths the standard image stores, sorted.
STORED = sorted([
    "Program Files/App/tool.exe",
    "Windows/Microsoft.NET/Framework/v4.0.30319/System.dll",
    "Windows/SysWOW64/a.dll",
    "Windows/System32/a.dll",
    "Windows/System32/b.dll",
    "Windows/System32/drivers/x.sys",
    "Windows/System32/dup.dll",
    "Windows/System32/en-US/a.dll.mui",
    "Windows/WinSxS/amd64_comp/b.dll",
])


def build_image(root):
    root = Path(root)
    for rel, kwargs in IMAGE.items():
        write_pe(root / rel, **kwargs)
    (root / "Windows/System32/notpe.dll").write_text("this is not a PE", encoding="ascii")
    (root / "Windows/System32/edge.bin").write_bytes(edge_lfanew_bytes())
    return root


# ---- RUNNING THE TOOLS ----

def run(*args):
    return subprocess.run([sys.executable, *[str(a) for a in args]],
                          capture_output=True, text=True)


def output(result):
    return result.stdout + result.stderr


def read_manifest(report):
    lines = (Path(report) / "manifest.sha256").read_text(encoding="ascii").splitlines()
    return dict((rel, digest) for digest, rel in (line.split("  ", 1) for line in lines))


def read_tsv(path):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    return header, [dict(zip(header, line.split("\t"))) for line in lines[1:]]


def same_file(a, b):
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False
