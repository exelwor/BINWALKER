"""Static ELF32 / ELF64 parser (headers, segments, sections, symbols, mitigations)."""

from __future__ import annotations

from binwalker.analysis.entropy import classify_import, shannon_entropy
from binwalker.models import (
    BinaryFormat,
    Endianness,
    ExportInfo,
    HeaderSummary,
    ImportInfo,
    ParsedBinary,
    SectionInfo,
    SecurityFlags,
    SegmentInfo,
)
from binwalker.parsers import BinaryParseError, BinaryReader, compute_hashes

_ET_TYPES = {
    0: "none",
    1: "relocatable",
    2: "executable",
    3: "shared_or_pie",
    4: "core",
}

_EM_ARCH = {
    0x03: ("x86", 32),
    0x08: ("mips", 32),
    0x14: ("powerpc", 32),
    0x15: ("powerpc64", 64),
    0x28: ("arm", 32),
    0x3E: ("x86_64", 64),
    0xB7: ("aarch64", 64),
    0xF3: ("riscv", 64),
}

_OS_ABI = {
    0: "System V",
    1: "HP-UX",
    2: "NetBSD",
    3: "Linux",
    6: "Solaris",
    9: "FreeBSD",
    12: "OpenBSD",
}

_PT_TYPES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    5: "PT_SHLIB",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO",
    0x6474E553: "PT_GNU_PROPERTY",
}

_SHT_TYPES = {
    0: "NULL",
    1: "PROGBITS",
    2: "SYMTAB",
    3: "STRTAB",
    4: "RELA",
    5: "HASH",
    6: "DYNAMIC",
    7: "NOTE",
    8: "NOBITS",
    9: "REL",
    11: "DYNSYM",
    14: "INIT_ARRAY",
    15: "FINI_ARRAY",
    0x6FFFFFF6: "GNU_HASH",
    0x6FFFFFFE: "VERNEED",
    0x6FFFFFFF: "VERSYM",
}

_MAX_HEADERS = 4096
_MAX_SYMBOLS = 20000


def _p_flags(val: int) -> tuple[str, ...]:
    flags = []
    if val & 0x4:
        flags.append("R")
    if val & 0x2:
        flags.append("W")
    if val & 0x1:
        flags.append("X")
    return tuple(flags)


def _section_flags(val: int) -> tuple[str, ...]:
    flags = ["R"] if (val & 0x2) else []
    if val & 0x1:
        flags.append("W")
    if val & 0x4:
        flags.append("X")
    if val & 0x2:
        flags.append("ALLOC")
    return tuple(flags)


def parse_elf(data: bytes, filename: str = "sample.elf") -> ParsedBinary:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise BinaryParseError("invalid ELF header")

    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise BinaryParseError(f"unsupported ELF class {ei_class}")
    if ei_data not in (1, 2):
        raise BinaryParseError(f"unsupported ELF data encoding {ei_data}")

    bits = 32 if ei_class == 1 else 64
    endianness = Endianness.LITTLE if ei_data == 1 else Endianness.BIG
    reader = BinaryReader(data, endianness)
    os_abi = _OS_ABI.get(data[7], f"ABI-{data[7]}")
    warnings: list[str] = []

    if bits == 32:
        e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _eflags, _ehsz, phentsz, phnum, shentsz, shnum, shstrndx = (
            reader.unpack("HHIIIIIHHHHHH", 16)
        )
    else:
        if len(data) < 64:
            raise BinaryParseError("truncated ELF64 header")
        e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _eflags, _ehsz, phentsz, phnum, shentsz, shnum, shstrndx = (
            reader.unpack("HHIQQQIHHHHHH", 16)
        )

    arch, arch_bits = _EM_ARCH.get(e_machine, (f"machine-0x{e_machine:x}", bits))
    file_type_raw = _ET_TYPES.get(e_type, f"type-{e_type}")

    segments: list[SegmentInfo] = []
    gnu_stack_flags: int | None = None
    has_relro = False
    has_interp = False
    interpreter: str | None = None
    dynamic_ranges: list[tuple[int, int]] = []

    if e_phoff and phnum:
        if phnum > _MAX_HEADERS:
            warnings.append(f"clamped program headers from {phnum} to {_MAX_HEADERS}")
            phnum = _MAX_HEADERS
        min_ph = 32 if bits == 32 else 56
        step = max(phentsz, min_ph)
        for i in range(phnum):
            off = e_phoff + i * step
            if off + min_ph > reader.size:
                warnings.append(f"truncated program header table at index {i}")
                break
            if bits == 32:
                p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, _align = reader.unpack("IIIIIIII", off)
            else:
                p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = reader.unpack("IIQQQQQQ", off)
            tname = _PT_TYPES.get(p_type, f"0x{p_type:x}")
            segments.append(
                SegmentInfo(
                    type=tname,
                    virtual_address=p_vaddr,
                    virtual_size=p_memsz,
                    file_offset=p_offset,
                    file_size=p_filesz,
                    flags=_p_flags(p_flags),
                )
            )
            if p_type == 0x6474E551:  # PT_GNU_STACK
                gnu_stack_flags = p_flags
            elif p_type == 0x6474E552:  # PT_GNU_RELRO
                has_relro = True
            elif p_type == 3 and p_offset < reader.size:  # PT_INTERP
                has_interp = True
                interpreter = reader.read_cstring(p_offset, min(256, max(1, p_filesz))) or None
            elif p_type == 2 and p_filesz > 0:  # PT_DYNAMIC
                dynamic_ranges.append((p_offset, p_filesz))

    raw_sections: list[tuple[int, int, int, int, int, int, int, int, int]] = []
    if e_shoff and shnum:
        if shnum > _MAX_HEADERS:
            warnings.append(f"clamped section headers from {shnum} to {_MAX_HEADERS}")
            shnum = _MAX_HEADERS
        min_sh = 40 if bits == 32 else 64
        step = max(shentsz, min_sh)
        for i in range(shnum):
            off = e_shoff + i * step
            if off + min_sh > reader.size:
                warnings.append(f"truncated section header table at index {i}")
                break
            if bits == 32:
                vals = reader.unpack("IIIIIIIIII", off)
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, _align, sh_entsize = vals
            else:
                vals = reader.unpack("IIQQQQIIQQ", off)
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, _align, sh_entsize = vals
            raw_sections.append(
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_entsize)
            )

    shstr_off, shstr_size = 0, 0
    if 0 <= shstrndx < len(raw_sections):
        shstr_off = raw_sections[shstrndx][4]
        shstr_size = raw_sections[shstrndx][5]

    sections: list[SectionInfo] = []
    has_symtab = False
    for sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, _link, _info, _entsz in raw_sections:
        name = ""
        if shstr_size and shstr_off + sh_name < reader.size:
            name = reader.read_cstring(shstr_off + sh_name, 128)
        if not name:
            name = "<unnamed>" if sh_type != 0 else "<null>"
        if sh_type == 2:
            has_symtab = True

        entropy = 0.0
        if sh_type != 8 and sh_size > 0 and sh_offset < reader.size:  # skip SHT_NOBITS (.bss)
            end = min(reader.size, sh_offset + sh_size)
            entropy = shannon_entropy(data[sh_offset:end])

        sections.append(
            SectionInfo(
                name=name,
                virtual_address=sh_addr,
                virtual_size=sh_size,
                raw_offset=sh_offset,
                raw_size=0 if sh_type == 8 else sh_size,
                flags=_section_flags(sh_flags),
                section_type=_SHT_TYPES.get(sh_type, f"0x{sh_type:x}"),
                entropy=entropy,
                is_executable=bool(sh_flags & 0x4),
                is_writable=bool(sh_flags & 0x1),
                is_readable=bool(sh_flags & 0x2) or sh_type != 0,
            )
        )

    # Parse dynamic tags (DT_NEEDED, BIND_NOW, PIE, RPATH/RUNPATH)
    needed_offsets: list[int] = []
    bind_now = False
    df_1_pie = False
    rpaths: list[int] = []
    dynstr_off, dynstr_size = 0, 0

    for idx, (_sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, sh_link, _info, _entsz) in enumerate(
        raw_sections
    ):
        if sh_type == 6:  # SHT_DYNAMIC
            if not dynamic_ranges:
                dynamic_ranges.append((sh_offset, sh_size))
            if 0 <= sh_link < len(raw_sections):
                dynstr_off = raw_sections[sh_link][4]
                dynstr_size = raw_sections[sh_link][5]
        elif sh_type == 11 and dynstr_size == 0 and 0 <= sh_link < len(raw_sections):  # SHT_DYNSYM -> .dynstr
            dynstr_off = raw_sections[sh_link][4]
            dynstr_size = raw_sections[sh_link][5]

    if dynstr_size == 0:
        for sec in sections:
            if sec.name == ".dynstr" and sec.raw_size > 0:
                dynstr_off = sec.raw_offset
                dynstr_size = sec.raw_size
                break

    for dyn_off, dyn_sz in dynamic_ranges:
        entry_sz = 8 if bits == 32 else 16
        fmt = "iI" if bits == 32 else "qQ"
        for off in range(dyn_off, min(reader.size - entry_sz + 1, dyn_off + dyn_sz), entry_sz):
            d_tag, d_val = reader.unpack(fmt, off)
            if d_tag == 0:  # DT_NULL
                break
            if d_tag == 1:  # DT_NEEDED
                needed_offsets.append(d_val)
            elif d_tag == 24:  # DT_BIND_NOW
                bind_now = True
            elif d_tag == 30 and (d_val & 0x8):  # DT_FLAGS DF_BIND_NOW
                bind_now = True
            elif d_tag == 0x6FFFFFFB:  # DT_FLAGS_1
                if d_val & 0x1:
                    bind_now = True
                if d_val & 0x08000000:
                    df_1_pie = True
            elif d_tag in (15, 29):  # DT_RPATH / DT_RUNPATH
                rpaths.append(d_val)

    libraries: list[str] = []
    if dynstr_size:
        for str_off in needed_offsets:
            if str_off < dynstr_size and dynstr_off + str_off < reader.size:
                lib = reader.read_cstring(dynstr_off + str_off, 256)
                if lib:
                    libraries.append(lib)

    rpath_values: list[str] = []
    if dynstr_size:
        for str_off in rpaths:
            if str_off < dynstr_size and dynstr_off + str_off < reader.size:
                val = reader.read_cstring(dynstr_off + str_off, 256)
                if val:
                    rpath_values.append(val)

    # Parse .dynsym (imports & exports) and check .symtab for stack canary
    imports: list[ImportInfo] = []
    exports: list[ExportInfo] = []
    seen_imports: set[str] = set()
    all_symbol_names: set[str] = set()

    for _sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, sh_link, _info, sh_entsize in raw_sections:
        if sh_type not in (2, 11):  # SYMTAB or DYNSYM
            continue
        if not (0 <= sh_link < len(raw_sections)):
            continue
        str_off = raw_sections[sh_link][4]
        str_sz = raw_sections[sh_link][5]
        sym_sz = sh_entsize or (16 if bits == 32 else 24)
        min_sym = 16 if bits == 32 else 24
        if sym_sz < min_sym:
            continue
        count = min(_MAX_SYMBOLS, sh_size // sym_sz)
        for idx in range(count):
            off = sh_offset + idx * sym_sz
            if off + min_sym > reader.size:
                break
            if bits == 32:
                st_name, st_value, _st_size, st_info, _other, st_shndx = reader.unpack("IIIBBH", off)
            else:
                st_name, st_info, _other, st_shndx, st_value, _st_size = reader.unpack("IBBHQQ", off)
            if not st_name or st_name >= str_sz or str_off + st_name >= reader.size:
                continue
            sym_name = reader.read_cstring(str_off + st_name, 256)
            if not sym_name:
                continue
            all_symbol_names.add(sym_name)
            if sh_type == 11:  # DYNSYM
                bind = st_info >> 4
                stype = st_info & 0xF
                if st_shndx == 0 and bind in (1, 2):  # undefined global/weak -> import
                    if sym_name not in seen_imports:
                        seen_imports.add(sym_name)
                        imports.append(
                            ImportInfo(
                                library=libraries[0] if len(libraries) == 1 else "dynamic",
                                symbol=sym_name,
                                address=st_value or None,
                                category=classify_import(sym_name),
                            )
                        )
                elif st_shndx != 0 and bind in (1, 2) and stype in (1, 2):  # defined FUNC/OBJECT -> export
                    exports.append(ExportInfo(symbol=sym_name, address=st_value))

    # Determine PIE and file_type
    if e_type == 3:
        is_pie = bool(has_interp or df_1_pie)
        file_type = "executable (PIE)" if is_pie else "shared_library"
    else:
        is_pie = False
        file_type = file_type_raw

    nx_flag: bool | None = None
    if gnu_stack_flags is not None:
        nx_flag = not bool(gnu_stack_flags & 0x1)

    relro_mode = "none"
    if has_relro:
        relro_mode = "full" if bind_now else "partial"

    has_canary = any(s in all_symbol_names for s in ("__stack_chk_fail", "__stack_chk_guard"))
    md5, sha1, sha256 = compute_hashes(data)

    metadata: list[tuple[str, str]] = [
        ("elf_class", f"ELF{bits}"),
        ("section_count", str(len(sections))),
        ("segment_count", str(len(segments))),
    ]
    if rpath_values:
        metadata.append(("rpath", ":".join(rpath_values)))

    return ParsedBinary(
        filename=filename,
        size=len(data),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        header=HeaderSummary(
            format=BinaryFormat.ELF,
            architecture=arch,
            bits=arch_bits,
            endianness=endianness,
            file_type=file_type,
            entry_point=e_entry,
            machine_raw=f"0x{e_machine:x}",
            interpreter=interpreter,
            os_abi=os_abi,
        ),
        sections=tuple(sections),
        segments=tuple(segments),
        imports=tuple(imports),
        exports=tuple(exports),
        libraries=tuple(libraries),
        security=SecurityFlags(
            nx=nx_flag,
            pie=is_pie,
            relro=relro_mode,
            canary=has_canary if (imports or has_symtab) else None,
            stripped=not has_symtab,
        ),
        metadata=tuple(metadata),
        warnings=tuple(warnings),
    )
