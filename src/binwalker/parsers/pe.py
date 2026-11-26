"""Static PE32 / PE32+ parser (DOS/COFF/Optional headers, sections, IAT, exports, mitigations)."""

from __future__ import annotations

from datetime import datetime, timezone

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
)
from binwalker.parsers import BinaryParseError, BinaryReader, compute_hashes

_MACHINE_MAP = {
    0x014C: ("x86", 32),
    0x8664: ("x86_64", 64),
    0x01C0: ("arm", 32),
    0x01C4: ("arm_thumb2", 32),
    0xAA64: ("aarch64", 64),
}

_SUBSYSTEM_MAP = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    7: "posix_cui",
    9: "windows_ce_gui",
    10: "efi_application",
    11: "efi_boot_service_driver",
    12: "efi_runtime_driver",
}

_MAX_SECTIONS = 128
_MAX_IMPORTS = 10000
_MAX_EXPORTS = 10000


def _sec_flags(chars: int) -> tuple[str, ...]:
    flags = []
    if chars & 0x40000000:
        flags.append("R")
    if chars & 0x80000000:
        flags.append("W")
    if chars & 0x20000000:
        flags.append("X")
    if chars & 0x00000020:
        flags.append("CODE")
    if chars & 0x00000040:
        flags.append("IDATA")
    if chars & 0x00000080:
        flags.append("UDATA")
    return tuple(flags)


def _rva_to_offset(rva: int, sections: list[SectionInfo]) -> int | None:
    if rva == 0:
        return None
    for sec in sections:
        span = max(sec.virtual_size, sec.raw_size)
        if sec.virtual_address <= rva < sec.virtual_address + span:
            delta = rva - sec.virtual_address
            if delta < sec.raw_size:
                return sec.raw_offset + delta
            return None
    return None


def parse_pe(data: bytes, filename: str = "sample.exe") -> ParsedBinary:
    if len(data) < 64 or data[:2] != b"MZ":
        raise BinaryParseError("invalid PE DOS header (missing MZ signature)")

    reader = BinaryReader(data, Endianness.LITTLE)
    e_lfanew = reader.u32(0x3C)
    if e_lfanew + 24 > reader.size or reader.read_bytes(e_lfanew, 4) != b"PE\x00\x00":
        raise BinaryParseError("invalid PE signature (missing PE\\0\\0)")

    coff_off = e_lfanew + 4
    machine, num_sections, timestamp, _sym_off, num_syms, opt_size, characteristics = reader.unpack(
        "HHIIIHH", coff_off
    )
    opt_off = coff_off + 20
    if opt_size < 96 or opt_off + opt_size > reader.size:
        raise BinaryParseError("truncated PE optional header")

    magic = reader.u16(opt_off)
    if magic == 0x10B:
        bits = 32
        entry_rva = reader.u32(opt_off + 16)
        image_base = reader.u32(opt_off + 28)
        subsystem_id = reader.u16(opt_off + 68)
        dll_chars = reader.u16(opt_off + 70)
        num_rva = reader.u32(opt_off + 92)
        dd_off = opt_off + 96
    elif magic == 0x20B:
        bits = 64
        if opt_size < 112:
            raise BinaryParseError("truncated PE32+ optional header")
        entry_rva = reader.u32(opt_off + 16)
        image_base = reader.u64(opt_off + 24)
        subsystem_id = reader.u16(opt_off + 68)
        dll_chars = reader.u16(opt_off + 70)
        num_rva = reader.u32(opt_off + 108)
        dd_off = opt_off + 112
    else:
        raise BinaryParseError(f"unsupported PE optional magic 0x{magic:x}")

    data_dirs: list[tuple[int, int]] = []
    for idx in range(min(16, num_rva)):
        off = dd_off + idx * 8
        if off + 8 > opt_off + opt_size or off + 8 > reader.size:
            break
        data_dirs.append(reader.unpack("II", off))

    warnings: list[str] = []
    if num_sections > _MAX_SECTIONS:
        warnings.append(f"clamped section count from {num_sections} to {_MAX_SECTIONS}")
        num_sections = _MAX_SECTIONS

    sec_table_off = opt_off + opt_size
    sections: list[SectionInfo] = []
    for idx in range(num_sections):
        off = sec_table_off + idx * 40
        if off + 40 > reader.size:
            warnings.append(f"truncated PE section table at index {idx}")
            break
        raw_name, vsize, vaddr, raw_sz, raw_off, _reloc, _lnum, _nreloc, _nline, chars = reader.unpack(
            "8sIIIIIIHHI", off
        )
        name = raw_name.split(b"\x00", 1)[0].decode("utf-8", errors="replace") or f"<sec{idx}>"
        entropy = 0.0
        if raw_sz > 0 and raw_off < reader.size:
            end = min(reader.size, raw_off + raw_sz)
            entropy = shannon_entropy(data[raw_off:end])
        sections.append(
            SectionInfo(
                name=name,
                virtual_address=vaddr,
                virtual_size=vsize,
                raw_offset=raw_off,
                raw_size=raw_sz,
                flags=_sec_flags(chars),
                section_type="CODE" if (chars & 0x20) else ("UDATA" if (chars & 0x80) else "DATA"),
                entropy=entropy,
                is_executable=bool(chars & 0x20000000),
                is_writable=bool(chars & 0x80000000),
                is_readable=bool(chars & 0x40000000),
            )
        )

    # Parse Import Directory (DataDirectory[1])
    imports: list[ImportInfo] = []
    libraries: list[str] = []
    if len(data_dirs) > 1 and data_dirs[1][0] != 0:
        imp_off = _rva_to_offset(data_dirs[1][0], sections)
        if imp_off is not None:
            while imp_off + 20 <= reader.size and len(imports) < _MAX_IMPORTS:
                oft, _ts, _fwd, name_rva, ft = reader.unpack("IIIII", imp_off)
                if oft == 0 and name_rva == 0 and ft == 0:
                    break
                name_off = _rva_to_offset(name_rva, sections)
                dll_name = reader.read_cstring(name_off, 256) if name_off is not None else "<unknown>"
                if dll_name and dll_name not in libraries:
                    libraries.append(dll_name)
                thunk_rva = oft or ft
                thunk_off = _rva_to_offset(thunk_rva, sections)
                if thunk_off is not None:
                    entry_sz = 4 if bits == 32 else 8
                    ord_flag = 0x80000000 if bits == 32 else 0x8000000000000000
                    while thunk_off + entry_sz <= reader.size and len(imports) < _MAX_IMPORTS:
                        val = reader.u32(thunk_off) if bits == 32 else reader.u64(thunk_off)
                        if val == 0:
                            break
                        if val & ord_flag:
                            ordinal = val & 0xFFFF
                            imports.append(
                                ImportInfo(
                                    library=dll_name,
                                    symbol=f"Ordinal#{ordinal}",
                                    ordinal=ordinal,
                                    category="general",
                                )
                            )
                        else:
                            hint_off = _rva_to_offset(val & 0x7FFFFFFF, sections)
                            if hint_off is not None and hint_off + 2 < reader.size:
                                hint = reader.u16(hint_off)
                                sym = reader.read_cstring(hint_off + 2, 256)
                                if sym:
                                    imports.append(
                                        ImportInfo(
                                            library=dll_name,
                                            symbol=sym,
                                            ordinal=hint,
                                            category=classify_import(sym),
                                        )
                                    )
                        thunk_off += entry_sz
                imp_off += 20

    # Parse Export Directory (DataDirectory[0])
    exports: list[ExportInfo] = []
    if len(data_dirs) > 0 and data_dirs[0][0] != 0:
        exp_off = _rva_to_offset(data_dirs[0][0], sections)
        if exp_off is not None and exp_off + 40 <= reader.size:
            (
                _chars,
                _ts,
                _maj,
                _min,
                _name_rva,
                ord_base,
                num_funcs,
                num_names,
                addr_funcs_rva,
                addr_names_rva,
                addr_ords_rva,
            ) = reader.unpack("IIHHIIIIIII", exp_off)
            funcs_off = _rva_to_offset(addr_funcs_rva, sections)
            names_off = _rva_to_offset(addr_names_rva, sections)
            ords_off = _rva_to_offset(addr_ords_rva, sections)
            if funcs_off is not None and names_off is not None and ords_off is not None:
                for idx in range(min(num_names, _MAX_EXPORTS)):
                    if names_off + idx * 4 + 4 > reader.size or ords_off + idx * 2 + 2 > reader.size:
                        break
                    sym_rva = reader.u32(names_off + idx * 4)
                    ord_idx = reader.u16(ords_off + idx * 2)
                    sym_off = _rva_to_offset(sym_rva, sections)
                    if sym_off is None or ord_idx >= num_funcs:
                        continue
                    if funcs_off + ord_idx * 4 + 4 > reader.size:
                        continue
                    func_rva = reader.u32(funcs_off + ord_idx * 4)
                    sym = reader.read_cstring(sym_off, 256)
                    if sym:
                        exports.append(ExportInfo(symbol=sym, address=func_rva, ordinal=ord_base + ord_idx))

    arch, arch_bits = _MACHINE_MAP.get(machine, (f"machine-0x{machine:x}", bits))
    if characteristics & 0x2000:
        file_type = "dll"
    elif characteristics & 0x1000:
        file_type = "system_driver"
    else:
        file_type = "executable"

    compile_ts = None
    if timestamp > 0:
        try:
            compile_ts = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="seconds")
        except (OSError, OverflowError, ValueError):
            compile_ts = None

    has_cert = len(data_dirs) > 4 and data_dirs[4][0] != 0 and data_dirs[4][1] > 0
    has_canary = any("__security_cookie" in imp.symbol or "__security_check_cookie" in imp.symbol for imp in imports)
    if not has_canary and len(data_dirs) > 10 and data_dirs[10][0] != 0:
        lc_off = _rva_to_offset(data_dirs[10][0], sections)
        cookie_offset = 60 if bits == 32 else 88
        if lc_off is not None and lc_off + cookie_offset + (bits // 8) <= reader.size:
            cookie_val = reader.u32(lc_off + cookie_offset) if bits == 32 else reader.u64(lc_off + cookie_offset)
            if cookie_val != 0:
                has_canary = True

    md5, sha1, sha256 = compute_hashes(data)
    metadata = (
        ("pe_format", "PE32+" if bits == 64 else "PE32"),
        ("section_count", str(len(sections))),
        ("dll_characteristics", f"0x{dll_chars:04x}"),
        ("coff_characteristics", f"0x{characteristics:04x}"),
    )

    return ParsedBinary(
        filename=filename,
        size=len(data),
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        header=HeaderSummary(
            format=BinaryFormat.PE,
            architecture=arch,
            bits=arch_bits,
            endianness=Endianness.LITTLE,
            file_type=file_type,
            entry_point=entry_rva,
            image_base=image_base,
            subsystem=_SUBSYSTEM_MAP.get(subsystem_id, f"subsystem-{subsystem_id}"),
            machine_raw=f"0x{machine:04x}",
            compile_timestamp=compile_ts,
        ),
        sections=tuple(sections),
        segments=(),
        imports=tuple(imports),
        exports=tuple(exports),
        libraries=tuple(libraries),
        security=SecurityFlags(
            nx=bool(dll_chars & 0x0100),
            pie=bool(dll_chars & 0x0040),
            cfg=bool(dll_chars & 0x4000),
            high_entropy_va=bool(dll_chars & 0x0020) if bits == 64 else None,
            canary=has_canary,
            signed=has_cert,
            stripped=num_syms == 0,
        ),
        metadata=metadata,
        warnings=tuple(warnings),
    )
