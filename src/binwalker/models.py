"""Immutable domain model for static executable inspection.

All parsers (ELF, PE, Mach-O) normalize into these types so downstream
analysis (entropy, heuristics, reports, API, Web UI) is format-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class BinaryFormat(str, Enum):
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    MACHO_FAT = "macho_fat"


class Endianness(str, Enum):
    LITTLE = "little"
    BIG = "big"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> float:
        return {
            "info": 0.2,
            "low": 0.8,
            "medium": 1.6,
            "high": 2.6,
            "critical": 3.8,
        }[self.value]


@dataclass(frozen=True)
class HeaderSummary:
    format: BinaryFormat
    architecture: str
    bits: int
    endianness: Endianness
    file_type: str
    entry_point: int | None = None
    image_base: int | None = None
    subsystem: str | None = None
    machine_raw: str = ""
    compile_timestamp: str | None = None
    interpreter: str | None = None
    os_abi: str | None = None


@dataclass(frozen=True)
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    flags: tuple[str, ...] = ()
    section_type: str = ""
    entropy: float = 0.0
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = True


@dataclass(frozen=True)
class SegmentInfo:
    type: str
    virtual_address: int
    virtual_size: int
    file_offset: int
    file_size: int
    flags: tuple[str, ...] = ()


@dataclass(frozen=True)
class ImportInfo:
    library: str
    symbol: str
    ordinal: int | None = None
    address: int | None = None
    category: str = "general"


@dataclass(frozen=True)
class ExportInfo:
    symbol: str
    address: int
    ordinal: int | None = None


@dataclass(frozen=True)
class SecurityFlags:
    nx: bool | None = None
    pie: bool | None = None
    relro: str | None = None  # "none" | "partial" | "full"
    canary: bool | None = None
    cfg: bool | None = None
    signed: bool | None = None
    stripped: bool | None = None
    high_entropy_va: bool | None = None


@dataclass(frozen=True)
class StringMatch:
    value: str
    offset: int
    encoding: str = "ascii"
    category: str = "general"


@dataclass(frozen=True)
class EntropyWindow:
    offset: int
    size: int
    entropy: float


@dataclass(frozen=True)
class AnomalyFinding:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParsedBinary:
    filename: str
    size: int
    md5: str
    sha1: str
    sha256: str
    header: HeaderSummary
    sections: tuple[SectionInfo, ...] = ()
    segments: tuple[SegmentInfo, ...] = ()
    imports: tuple[ImportInfo, ...] = ()
    exports: tuple[ExportInfo, ...] = ()
    libraries: tuple[str, ...] = ()
    security: SecurityFlags = field(default_factory=SecurityFlags)
    metadata: tuple[tuple[str, str], ...] = ()
    warnings: tuple[str, ...] = ()
