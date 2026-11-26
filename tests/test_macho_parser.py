import struct

import pytest

from binwalker.models import BinaryFormat
from binwalker.parsers import BinaryParseError, parse_binary
from binwalker.samples import build_sample_macho64


def test_sample_macho64_parses_segments_dylibs_and_symtab():
    parsed = parse_binary(build_sample_macho64(), "cli.macho")
    assert parsed.header.format is BinaryFormat.MACHO
    assert parsed.header.architecture == "aarch64"
    assert parsed.header.bits == 64
    assert parsed.header.entry_point == 0x400
    assert parsed.libraries == ("/usr/lib/libSystem.B.dylib",)
    assert {i.symbol for i in parsed.imports} == {"_printf", "_dlopen"}
    assert [e.symbol for e in parsed.exports] == ["_main"]
    assert parsed.security.pie is True
    assert parsed.security.nx is True
    assert parsed.security.signed is False


def test_macho_universal_fat_binary_selects_slice_and_records_arches():
    slice_bytes = build_sample_macho64()
    slice_offset = 0x1000
    fat_header = struct.pack(">II", 0xCAFEBABE, 1)
    fat_arch = struct.pack(">IIIII", 0x0100000C, 0, slice_offset, len(slice_bytes), 14)
    blob = (fat_header + fat_arch).ljust(slice_offset, b"\x00") + slice_bytes

    parsed = parse_binary(blob, "universal.macho")
    assert parsed.header.format is BinaryFormat.MACHO_FAT
    assert parsed.header.architecture == "aarch64"
    assert dict(parsed.metadata)["universal_architectures"] == "aarch64"


def test_java_class_cafebabe_is_rejected():
    # Java .class has major version 61 (0x003d) -> nfat_arch = 61 -> rejected as non-MachO fat
    java_class = struct.pack(">IHH", 0xCAFEBABE, 0, 61) + b"\x00" * 32
    with pytest.raises(BinaryParseError):
        parse_binary(java_class)
