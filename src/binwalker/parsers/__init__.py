"""Static binary format detection, safe reader primitives, and parser dispatch."""

from __future__ import annotations

import hashlib
import struct

from binwalker.models import BinaryFormat, Endianness, ParsedBinary

MAX_BINARY_SIZE = 64 * 1024 * 1024  # 64 MiB safety limit for static analysis

_MACHO_MAGICS = frozenset(
    {
        b"\xfe\xed\xfa\xce",  # MH_MAGIC (32-bit BE)
        b"\xce\xfa\xed\xfe",  # MH_CIGAM (32-bit LE)
        b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 (64-bit BE)
        b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 (64-bit LE)
    }
)
_FAT_MAGICS = frozenset(
    {
        b"\xca\xfe\xba\xbe",  # FAT_MAGIC (note: also Java class file; checked via nfat_arch)
        b"\xbe\xba\xfe\xca",  # FAT_CIGAM
        b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64
        b"\xbf\xba\xfe\xca",  # FAT_CIGAM_64
    }
)


class BinaryParseError(ValueError):
    """Raised when the input bytes cannot be parsed as a supported executable."""


class BinaryReader:
    """Bounds-checked reader over an immutable byte buffer."""

    def __init__(self, data: bytes, endianness: Endianness = Endianness.LITTLE):
        self.data = data
        self.size = len(data)
        self.endianness = endianness

    @property
    def prefix(self) -> str:
        return "<" if self.endianness is Endianness.LITTLE else ">"

    def with_endianness(self, endianness: Endianness) -> BinaryReader:
        return BinaryReader(self.data, endianness)

    def read_bytes(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > self.size:
            raise BinaryParseError(
                f"out-of-bounds read at offset 0x{max(offset, 0):x} (length {length}, file size {self.size})"
            )
        return self.data[offset : offset + length]

    def unpack(self, fmt: str, offset: int) -> tuple:
        full_fmt = fmt if fmt[0] in ("<", ">", "!", "=", "@") else self.prefix + fmt
        needed = struct.calcsize(full_fmt)
        if offset < 0 or offset + needed > self.size:
            raise BinaryParseError(
                f"truncated structure at offset 0x{max(offset, 0):x} (needed {needed} bytes, file size {self.size})"
            )
        return struct.unpack_from(full_fmt, self.data, offset)

    def u8(self, offset: int) -> int:
        return self.unpack("B", offset)[0]

    def u16(self, offset: int) -> int:
        return self.unpack("H", offset)[0]

    def u32(self, offset: int) -> int:
        return self.unpack("I", offset)[0]

    def u64(self, offset: int) -> int:
        return self.unpack("Q", offset)[0]

    def read_cstring(self, offset: int, max_len: int = 512) -> str:
        if offset < 0 or offset >= self.size:
            return ""
        end = self.data.find(b"\x00", offset, min(self.size, offset + max_len))
        if end == -1:
            end = min(self.size, offset + max_len)
        return self.data[offset:end].decode("utf-8", errors="replace")


def compute_hashes(data: bytes) -> tuple[str, str, str]:
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha1(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
    )


def detect_format(data: bytes) -> BinaryFormat:
    if len(data) < 4:
        raise BinaryParseError("file is too small to be an executable (< 4 bytes)")
    magic = data[:4]
    if magic == b"\x7fELF":
        return BinaryFormat.ELF
    if data[:2] == b"MZ":
        return BinaryFormat.PE
    if magic in _MACHO_MAGICS:
        return BinaryFormat.MACHO
    if magic in _FAT_MAGICS:
        # Distinguish Mach-O Fat header from Java .class files (CAFEBABE + major/minor >= 45)
        if len(data) >= 8:
            count = struct.unpack(">I" if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") else "<I", data[4:8])[0]
            if 1 <= count <= 16 and len(data) >= 8 + count * 20:
                return BinaryFormat.MACHO_FAT
        raise BinaryParseError("unrecognized 0xCAFEBABE file (not a valid Mach-O universal binary)")
    raise BinaryParseError(
        f"unsupported binary format (magic bytes: {magic.hex()}); supported formats are ELF, PE, and Mach-O"
    )


def parse_binary(data: bytes, filename: str = "sample.bin") -> ParsedBinary:
    if not data:
        raise BinaryParseError("input file is empty")
    if len(data) > MAX_BINARY_SIZE:
        raise BinaryParseError(f"file exceeds static analysis limit ({len(data)} > {MAX_BINARY_SIZE} bytes)")

    fmt = detect_format(data)
    if fmt is BinaryFormat.ELF:
        from binwalker.parsers.elf import parse_elf

        return parse_elf(data, filename)
    if fmt is BinaryFormat.PE:
        from binwalker.parsers.pe import parse_pe

        return parse_pe(data, filename)
    from binwalker.parsers.macho import parse_macho

    return parse_macho(data, filename)
