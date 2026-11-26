import struct

import pytest

from binwalker.models import BinaryFormat, Endianness
from binwalker.parsers import BinaryParseError, parse_binary
from binwalker.samples import build_sample_elf64


def test_sample_elf64_parses_headers_sections_imports_and_flags():
    parsed = parse_binary(build_sample_elf64(), "beacon.elf")
    assert parsed.header.format is BinaryFormat.ELF
    assert parsed.header.architecture == "x86_64"
    assert parsed.header.bits == 64
    assert parsed.header.endianness is Endianness.LITTLE
    assert parsed.header.entry_point == 0x401000
    assert parsed.libraries == ("libc.so.6", "libcurl.so.4")
    assert {imp.symbol for imp in parsed.imports} == {"execve", "mprotect", "connect"}
    assert [exp.symbol for exp in parsed.exports] == ["sample_entry"]
    assert parsed.security.nx is False
    assert parsed.security.pie is False
    assert parsed.security.relro == "none"
    text_sec = next(s for s in parsed.sections if s.name == ".text")
    assert text_sec.is_writable and text_sec.is_executable


def test_elf32_big_endian_with_relro_nx_pie_and_canary():
    shstr = b"\x00.text\x00.dynsym\x00.dynstr\x00.dynamic\x00.shstrtab\x00"
    dynstr = b"\x00libc.so.6\x00__stack_chk_fail\x00"
    dynsym = b"".join(
        [
            struct.pack(">IIIBBH", 0, 0, 0, 0, 0, 0),
            struct.pack(">IIIBBH", 11, 0, 0, 0x12, 0, 0),  # __stack_chk_fail
        ]
    )
    dynamic = b"".join(
        [
            struct.pack(">iI", 1, 1),  # DT_NEEDED libc.so.6
            struct.pack(">iI", 24, 0),  # DT_BIND_NOW
            struct.pack(">iI", 0, 0),
        ]
    )
    ehdr_sz, phdr_sz, phnum = 52, 32, 3
    off = ehdr_sz + phdr_sz * phnum
    text_off = off
    text_blob = b"/lib/ld.so.1\x00".ljust(32, b"\x00")
    dynsym_off = text_off + len(text_blob)
    dynstr_off = dynsym_off + len(dynsym)
    dynamic_off = dynstr_off + len(dynstr)
    shstr_off = dynamic_off + len(dynamic)
    shoff = shstr_off + len(shstr)

    ehdr = struct.pack(
        ">16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x02\x01\x00" + b"\x00" * 8,
        3,  # ET_DYN
        0x14,  # PowerPC
        1,
        0x1000,
        ehdr_sz,
        shoff,
        0,
        ehdr_sz,
        phdr_sz,
        phnum,
        40,
        6,
        5,
    )
    phdrs = b"".join(
        [
            struct.pack(">IIIIIIII", 3, text_off, 0, 0, 13, 13, 4, 1),  # PT_INTERP
            struct.pack(">IIIIIIII", 0x6474E551, 0, 0, 0, 0, 0, 6, 4),  # PT_GNU_STACK RW (NX enabled)
            struct.pack(">IIIIIIII", 0x6474E552, 0, 0, 0, 0, 0, 4, 1),  # PT_GNU_RELRO
        ]
    )
    shdrs = b"".join(
        [
            struct.pack(">IIIIIIIIII", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            struct.pack(">IIIIIIIIII", 1, 1, 6, 0x1000, text_off, len(text_blob), 0, 0, 4, 0),
            struct.pack(">IIIIIIIIII", 7, 11, 2, 0, dynsym_off, len(dynsym), 3, 1, 4, 16),
            struct.pack(">IIIIIIIIII", 15, 3, 2, 0, dynstr_off, len(dynstr), 0, 0, 1, 0),
            struct.pack(">IIIIIIIIII", 23, 6, 3, 0, dynamic_off, len(dynamic), 3, 0, 4, 8),
            struct.pack(">IIIIIIIIII", 32, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0),
        ]
    )

    parsed = parse_binary(ehdr + phdrs + text_blob + dynsym + dynstr + dynamic + shstr + shdrs, "ppc.elf")
    assert parsed.header.bits == 32
    assert parsed.header.endianness is Endianness.BIG
    assert parsed.header.architecture == "powerpc"
    assert parsed.security.nx is True
    assert parsed.security.pie is True
    assert parsed.security.relro == "full"
    assert parsed.security.canary is True


def test_truncated_elf_raises_binary_parse_error():
    with pytest.raises(BinaryParseError):
        parse_binary(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 10)
