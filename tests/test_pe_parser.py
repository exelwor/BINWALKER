import struct

import pytest

from binwalker.models import BinaryFormat
from binwalker.parsers import BinaryParseError, parse_binary
from binwalker.samples import build_sample_pe64


def test_sample_pe64_parses_headers_iat_exports_and_mitigations():
    parsed = parse_binary(build_sample_pe64(), "agent.exe")
    assert parsed.header.format is BinaryFormat.PE
    assert parsed.header.architecture == "x86_64"
    assert parsed.header.bits == 64
    assert parsed.header.subsystem == "windows_cui"
    assert parsed.header.entry_point == 0x1000
    assert parsed.libraries == ("KERNEL32.dll", "WS2_32.dll")
    assert {imp.symbol for imp in parsed.imports} == {"VirtualAllocEx", "CreateRemoteThread", "WSAStartup"}
    assert [exp.symbol for exp in parsed.exports] == ["RunDiagnostics"]
    assert parsed.security.nx is True
    assert parsed.security.pie is True
    assert parsed.security.high_entropy_va is True
    assert parsed.security.cfg is False
    assert parsed.security.signed is False


def test_pe32_ordinal_import_and_cfg_signed_flags():
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    rdata = bytearray(0x200)
    rdata_rva = 0x2000
    rdata[0x80 : 0x80 + 11] = b"USER32.dll\x00"
    struct.pack_into("<II", rdata, 0x40, 0x8000002A, 0)  # Ordinal #42 import
    struct.pack_into("<IIIII", rdata, 0x00, rdata_rva + 0x40, 0, 0, rdata_rva + 0x80, rdata_rva + 0x40)

    coff = struct.pack("<HHIIIHH", 0x014C, 2, 0, 0, 0, 224, 0x2102)  # x86 DLL
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)  # PE32
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<I", opt, 28, 0x10000000)
    struct.pack_into("<HH", opt, 68, 2, 0x4140)  # GUI, CFG + NX + DynamicBase
    struct.pack_into("<I", opt, 92, 16)
    struct.pack_into("<II", opt, 96 + 8, rdata_rva, 40)  # Import Dir
    struct.pack_into("<II", opt, 96 + 32, 0x300, 16)  # Certificate table present

    sec_text = struct.pack("<8sIIIIIIHHI", b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    sec_rdata = struct.pack("<8sIIIIIIHHI", b".rdata", 0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0x40000040)

    hdr = (bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sec_text + sec_rdata).ljust(0x200, b"\x00")
    parsed = parse_binary(hdr + b"\xc3".ljust(0x200, b"\x00") + bytes(rdata), "gui.dll")
    assert parsed.header.bits == 32
    assert parsed.header.file_type == "dll"
    assert parsed.security.cfg is True
    assert parsed.security.signed is True
    assert parsed.imports[0].symbol == "Ordinal#42"
    assert parsed.imports[0].ordinal == 42


def test_invalid_pe_signature_raises():
    bad = bytearray(128)
    bad[0:2] = b"MZ"
    struct.pack_into("<I", bad, 0x3C, 0x40)
    with pytest.raises(BinaryParseError):
        parse_binary(bytes(bad))
