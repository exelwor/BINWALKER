"""Static Mach-O (32/64-bit & Universal/Fat) parser."""

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

_CPU_ARCH = {
    7: ("x86", 32),
    0x01000007: ("x86_64", 64),
    12: ("arm", 32),
    0x0100000C: ("aarch64", 64),
    18: ("powerpc", 32),
    0x01000012: ("powerpc64", 64),
}

_FILE_TYPES = {
    1: "object",
    2: "executable",
    3: "fvmlib",
    4: "core",
    5: "preload",
    6: "dylib",
    7: "dylinker",
    8: "bundle",
    11: "kext_bundle",
}

_MAX_CMDS = 4096
_MAX_SYMS = 30000


def _vm_flags(prot: int) -> tuple[str, ...]:
    flags = []
    if prot & 0x1:
        flags.append("R")
    if prot & 0x2:
        flags.append("W")
    if prot & 0x4:
        flags.append("X")
    return tuple(flags)


def _decode_name(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")


def parse_macho(data: bytes, filename: str = "sample.macho") -> ParsedBinary:
    if len(data) < 28:
        raise BinaryParseError("truncated Mach-O file")

    magic = data[:4]
    slice_offset = 0
    slice_size = len(data)
    fat_arches: list[str] = []
    is_fat = False

    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        is_fat = True
        fat_be = magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf")
        is_fat64 = magic in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
        fat_reader = BinaryReader(data, Endianness.BIG if fat_be else Endianness.LITTLE)
        nfat = fat_reader.u32(4)
        if nfat == 0 or nfat > 16:
            raise BinaryParseError(f"invalid Mach-O fat archive slice count: {nfat}")
        entry_sz = 32 if is_fat64 else 20
        chosen: tuple[int, int, int] | None = None
        for i in range(nfat):
            off = 8 + i * entry_sz
            if off + entry_sz > fat_reader.size:
                break
            if is_fat64:
                cputype, _sub, f_off, f_sz, _align, _res = fat_reader.unpack("IIQQII", off)
            else:
                cputype, _sub, f_off, f_sz, _align = fat_reader.unpack("IIIII", off)
            arch_name, _ = _CPU_ARCH.get(cputype, (f"cpu-0x{cputype:x}", 64))
            fat_arches.append(arch_name)
            if chosen is None or arch_name in ("aarch64", "x86_64"):
                if f_off + f_sz <= len(data) and f_sz >= 28:
                    chosen = (f_off, f_sz, cputype)
                    if arch_name == "aarch64":
                        break
        if chosen is None:
            raise BinaryParseError("universal Mach-O contains no valid slice within file bounds")
        slice_offset, slice_size, _ = chosen

    slice_data = data[slice_offset : slice_offset + slice_size]
    if len(slice_data) < 28:
        raise BinaryParseError("truncated Mach-O slice")

    smagic = slice_data[:4]
    if smagic == b"\xfe\xed\xfa\xce":
        bits, endianness = 32, Endianness.BIG
    elif smagic == b"\xce\xfa\xed\xfe":
        bits, endianness = 32, Endianness.LITTLE
    elif smagic == b"\xfe\xed\xfa\xcf":
        bits, endianness = 64, Endianness.BIG
    elif smagic == b"\xcf\xfa\xed\xfe":
        bits, endianness = 64, Endianness.LITTLE
    else:
        raise BinaryParseError(f"unsupported Mach-O magic {smagic.hex()}")

    reader = BinaryReader(slice_data, endianness)
    if bits == 64:
        if len(slice_data) < 32:
            raise BinaryParseError("truncated Mach-O 64 header")
        _m, cputype, _cpusub, filetype, ncmds, sizeofcmds, flags, _res = reader.unpack("IIIIIIII", 0)
        cursor = 32
    else:
        _m, cputype, _cpusub, filetype, ncmds, sizeofcmds, flags = reader.unpack("IIIIIII", 0)
        cursor = 28

    warnings: list[str] = []
    if ncmds > _MAX_CMDS:
        warnings.append(f"clamped load commands from {ncmds} to {_MAX_CMDS}")
        ncmds = _MAX_CMDS

    segments: list[SegmentInfo] = []
    sections: list[SectionInfo] = []
    libraries: list[str] = []
    interpreter: str | None = None
    entry_point: int | None = None
    image_base: int | None = None
    has_code_sig = False
    encrypted = False
    symtab_info: tuple[int, int, int, int] | None = None
    has_local_syms = False

    cmd_limit = min(reader.size, cursor + sizeofcmds)
    for idx in range(ncmds):
        if cursor + 8 > cmd_limit:
            warnings.append(f"truncated load command table at index {idx}")
            break
        cmd, cmdsize = reader.unpack("II", cursor)
        if cmdsize < 8 or cursor + cmdsize > reader.size:
            warnings.append(f"invalid load command size ({cmdsize}) at offset 0x{cursor:x}")
            break

        if cmd == 0x1 and cmdsize >= 56:  # LC_SEGMENT
            segname_raw, vmaddr, vmsize, fileoff, filesize, _maxp, initprot, nsects, _sflags = reader.unpack(
                "16sIIIIIIII", cursor + 8
            )
            segname = _decode_name(segname_raw)
            if segname == "__TEXT" and image_base is None:
                image_base = vmaddr
            segments.append(
                SegmentInfo(
                    type=segname,
                    virtual_address=vmaddr,
                    virtual_size=vmsize,
                    file_offset=fileoff,
                    file_size=filesize,
                    flags=_vm_flags(initprot),
                )
            )
            sec_cursor = cursor + 56
            for _ in range(nsects):
                if sec_cursor + 68 > cursor + cmdsize:
                    break
                sectname_r, _segn_r, addr, size, offset, _al, _rel, _nrel, sflags, _r1, _r2 = reader.unpack(
                    "16s16sIIIIIIIII", sec_cursor
                )
                sname = f"{segname}.{_decode_name(sectname_r)}"
                ent = 0.0
                if size > 0 and offset > 0 and offset < reader.size:
                    ent = shannon_entropy(slice_data[offset : min(reader.size, offset + size)])
                is_exec = bool(initprot & 0x4) or bool(sflags & 0x80000400)
                sections.append(
                    SectionInfo(
                        name=sname,
                        virtual_address=addr,
                        virtual_size=size,
                        raw_offset=offset,
                        raw_size=0 if (sflags & 0xFF) == 1 else size,  # S_ZEROFILL = 1
                        flags=_vm_flags(initprot),
                        section_type=f"0x{sflags & 0xff:02x}",
                        entropy=ent,
                        is_executable=is_exec,
                        is_writable=bool(initprot & 0x2),
                        is_readable=bool(initprot & 0x1),
                    )
                )
                sec_cursor += 68

        elif cmd == 0x19 and cmdsize >= 72:  # LC_SEGMENT_64
            segname_raw, vmaddr, vmsize, fileoff, filesize, _maxp, initprot, nsects, _sflags = reader.unpack(
                "16sQQQQIIII", cursor + 8
            )
            segname = _decode_name(segname_raw)
            if segname == "__TEXT" and image_base is None:
                image_base = vmaddr
            segments.append(
                SegmentInfo(
                    type=segname,
                    virtual_address=vmaddr,
                    virtual_size=vmsize,
                    file_offset=fileoff,
                    file_size=filesize,
                    flags=_vm_flags(initprot),
                )
            )
            sec_cursor = cursor + 72
            for _ in range(nsects):
                if sec_cursor + 80 > cursor + cmdsize:
                    break
                sectname_r, _segn_r, addr, size, offset, _al, _rel, _nrel, sflags, _r1, _r2, _r3 = reader.unpack(
                    "16s16sQQIIIIIIII", sec_cursor
                )
                sname = f"{segname}.{_decode_name(sectname_r)}"
                ent = 0.0
                if size > 0 and offset > 0 and offset < reader.size:
                    ent = shannon_entropy(slice_data[offset : min(reader.size, offset + size)])
                is_exec = bool(initprot & 0x4) or bool(sflags & 0x80000400)
                sections.append(
                    SectionInfo(
                        name=sname,
                        virtual_address=addr,
                        virtual_size=size,
                        raw_offset=offset,
                        raw_size=0 if (sflags & 0xFF) == 1 else size,
                        flags=_vm_flags(initprot),
                        section_type=f"0x{sflags & 0xff:02x}",
                        entropy=ent,
                        is_executable=is_exec,
                        is_writable=bool(initprot & 0x2),
                        is_readable=bool(initprot & 0x1),
                    )
                )
                sec_cursor += 80

        elif cmd in (0xC, 0x18, 0x80000018, 0x8000001F, 0x20) and cmdsize >= 24:
            str_off = reader.u32(cursor + 8)
            if 8 <= str_off < cmdsize:
                lib = reader.read_cstring(cursor + str_off, cmdsize - str_off)
                if lib and lib not in libraries:
                    libraries.append(lib)

        elif cmd == 0xE and cmdsize >= 12:  # LC_LOAD_DYLINKER
            str_off = reader.u32(cursor + 8)
            if 8 <= str_off < cmdsize:
                interpreter = reader.read_cstring(cursor + str_off, cmdsize - str_off)

        elif cmd == 0x80000028 and cmdsize >= 24:  # LC_MAIN
            entryoff, _stacksize = reader.unpack("QQ", cursor + 8)
            entry_point = entryoff

        elif cmd == 0x2 and cmdsize >= 24:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = reader.unpack("IIII", cursor + 8)
            symtab_info = (symoff, nsyms, stroff, strsize)

        elif cmd == 0x1D:  # LC_CODE_SIGNATURE
            has_code_sig = True

        elif cmd in (0x21, 0x2C) and cmdsize >= 20:  # LC_ENCRYPTION_INFO(_64)
            _coff, _csize, cryptid = reader.unpack("III", cursor + 8)
            if cryptid != 0:
                encrypted = True

        cursor += cmdsize

    imports: list[ImportInfo] = []
    exports: list[ExportInfo] = []
    seen_imports: set[str] = set()
    all_syms: set[str] = set()
    if symtab_info is not None:
        symoff, nsyms, stroff, strsize = symtab_info
        entry_sz = 12 if bits == 32 else 16
        fmt = "IBBHI" if bits == 32 else "IBBHQ"
        for i in range(min(nsyms, _MAX_SYMS)):
            off = symoff + i * entry_sz
            if off + entry_sz > reader.size:
                break
            n_strx, n_type, _n_sect, _n_desc, n_value = reader.unpack(fmt, off)
            if n_strx == 0 or n_strx >= strsize or stroff + n_strx >= reader.size:
                continue
            sym = reader.read_cstring(stroff + n_strx, 256)
            if not sym:
                continue
            all_syms.add(sym)
            if not (n_type & 0x01):  # local non-external symbol
                has_local_syms = True
            if (n_type & 0x01) and (n_type & 0x0E) == 0:  # N_EXT | N_UNDF
                if sym not in seen_imports:
                    seen_imports.add(sym)
                    imports.append(
                        ImportInfo(
                            library=libraries[0] if len(libraries) == 1 else "dyld",
                            symbol=sym,
                            address=n_value or None,
                            category=classify_import(sym),
                        )
                    )
            elif (n_type & 0x01) and (n_type & 0x0E) == 0x0E and n_value:  # N_EXT | N_SECT
                exports.append(ExportInfo(symbol=sym, address=n_value))

    arch, arch_bits = _CPU_ARCH.get(cputype, (f"cpu-0x{cputype:x}", bits))
    md5, sha1, sha256 = compute_hashes(data)
    metadata: list[tuple[str, str]] = [
        ("macho_flags", f"0x{flags:08x}"),
        ("section_count", str(len(sections))),
        ("segment_count", str(len(segments))),
        ("encrypted", "yes" if encrypted else "no"),
    ]
    if fat_arches:
        metadata.append(("universal_architectures", ", ".join(fat_arches)))

    has_canary = any(s in all_syms for s in ("___stack_chk_fail", "___stack_chk_guard", "__stack_chk_fail"))
    nx_flag = not bool(flags & 0x20000)  # MH_ALLOW_STACK_EXECUTION absent

    return ParsedBinary(
        filename=filename,
        size=len(data),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        header=HeaderSummary(
            format=BinaryFormat.MACHO_FAT if is_fat else BinaryFormat.MACHO,
            architecture=arch,
            bits=arch_bits,
            endianness=endianness,
            file_type=_FILE_TYPES.get(filetype, f"type-{filetype}"),
            entry_point=entry_point,
            image_base=image_base,
            machine_raw=f"0x{cputype:x}",
            interpreter=interpreter,
        ),
        sections=tuple(sections),
        segments=tuple(segments),
        imports=tuple(imports),
        exports=tuple(exports),
        libraries=tuple(libraries),
        security=SecurityFlags(
            nx=nx_flag,
            pie=bool(flags & 0x200000),  # MH_PIE
            canary=has_canary if symtab_info is not None else None,
            signed=has_code_sig,
            stripped=not has_local_syms,
        ),
        metadata=tuple(metadata),
        warnings=tuple(warnings),
    )
