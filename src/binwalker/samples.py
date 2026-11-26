"""Deterministic pure-Python sample executable builders (ELF64, PE32+, Mach-O 64).

Used by ``binwalker sample``, the ``/api/samples`` endpoint, and automated tests
so demonstrations run anywhere without shipping opaque binary blobs.
"""

from __future__ import annotations

import struct


def _pad(buf: bytes, size: int) -> bytes:
    if len(buf) >= size:
        return buf[:size]
    return buf + b"\x00" * (size - len(buf))


def _pseudo_random_bytes(length: int) -> bytes:
    """Deterministic high-entropy bytes (LCG-based) simulating packed/encrypted data."""
    state = 0x9E3779B97F4A7C15
    out = bytearray(length)
    for i in range(length):
        state = (state * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out[i] = (state >> 56) & 0xFF
    return bytes(out)


def build_sample_elf64() -> bytes:
    """Build a valid ELF64 x86_64 sample binary with headers, sections, imports, and W^X anomaly."""
    # Sections: 0=null, 1=.text, 2=.rodata, 3=.dynsym, 4=.dynstr, 5=.dynamic, 6=.shstrtab
    shstr_items = [b"", b".text", b".rodata", b".dynsym", b".dynstr", b".dynamic", b".shstrtab"]
    shstr_blob = b"\x00".join(shstr_items) + b"\x00"
    shstr_offs = []
    pos = 0
    for item in shstr_items:
        shstr_offs.append(pos)
        pos += len(item) + 1

    dynstr_items = [b"", b"libc.so.6", b"libcurl.so.4", b"execve", b"mprotect", b"connect", b"sample_entry"]
    dynstr_blob = b"\x00".join(dynstr_items) + b"\x00"
    dynstr_offs = []
    pos = 0
    for item in dynstr_items:
        dynstr_offs.append(pos)
        pos += len(item) + 1

    text_blob = b"\x55\x48\x89\xe5\x48\x83\xec\x10\xb8\x00\x00\x00\x00\xc9\xc3" * 8
    rodata_blob = b"https://telemetry.blackboxlab.local/beacon\x00/bin/sh -c id\x00" + _pseudo_random_bytes(320)

    # .dynsym: null + 3 imports + 1 export
    dynsym_blob = b"".join(
        [
            struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0),
            struct.pack("<IBBHQQ", dynstr_offs[3], 0x12, 0, 0, 0, 0),  # execve (STB_GLOBAL|STT_FUNC, SHN_UNDEF)
            struct.pack("<IBBHQQ", dynstr_offs[4], 0x12, 0, 0, 0, 0),  # mprotect
            struct.pack("<IBBHQQ", dynstr_offs[5], 0x12, 0, 0, 0, 0),  # connect
            struct.pack("<IBBHQQ", dynstr_offs[6], 0x12, 0, 1, 0x401000, 32),  # sample_entry export
        ]
    )

    # .dynamic: DT_NEEDED x2 + DT_NULL
    dynamic_blob = b"".join(
        [
            struct.pack("<qQ", 1, dynstr_offs[1]),
            struct.pack("<qQ", 1, dynstr_offs[2]),
            struct.pack("<qQ", 0, 0),
        ]
    )

    ehdr_size = 64
    phdr_size = 56
    phnum = 3  # PT_LOAD, PT_DYNAMIC, PT_GNU_STACK (RWX!)
    phoff = ehdr_size
    sec_start = ehdr_size + phnum * phdr_size

    text_off = sec_start
    rodata_off = text_off + len(text_blob)
    dynsym_off = rodata_off + len(rodata_blob)
    dynstr_off = dynsym_off + len(dynsym_blob)
    dynamic_off = dynstr_off + len(dynstr_blob)
    shstr_off = dynamic_off + len(dynamic_blob)
    shoff = shstr_off + len(shstr_blob)

    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x03" + b"\x00" * 8,  # ELF64, LE, Linux ABI
        2,  # ET_EXEC (no PIE)
        0x3E,  # x86_64
        1,
        0x401000,
        phoff,
        shoff,
        0,
        ehdr_size,
        phdr_size,
        phnum,
        64,
        7,
        6,  # .shstrtab index
    )

    phdrs = b"".join(
        [
            struct.pack("<IIQQQQQQ", 1, 7, 0, 0x400000, 0x400000, shoff, shoff, 0x1000),  # PT_LOAD RWX
            struct.pack("<IIQQQQQQ", 2, 6, dynamic_off, 0x402000, 0x402000, len(dynamic_blob), len(dynamic_blob), 8),
            struct.pack("<IIQQQQQQ", 0x6474E551, 7, 0, 0, 0, 0, 0, 16),  # PT_GNU_STACK RWX (NX disabled)
        ]
    )

    shdrs = b"".join(
        [
            struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            # .text marked W+X+A (triggers W^X anomaly)
            struct.pack("<IIQQQQIIQQ", shstr_offs[1], 1, 0x7, 0x401000, text_off, len(text_blob), 0, 0, 16, 0),
            struct.pack("<IIQQQQIIQQ", shstr_offs[2], 1, 0x2, 0x401200, rodata_off, len(rodata_blob), 0, 0, 8, 0),
            struct.pack("<IIQQQQIIQQ", shstr_offs[3], 11, 0x2, 0x401600, dynsym_off, len(dynsym_blob), 4, 1, 8, 24),
            struct.pack("<IIQQQQIIQQ", shstr_offs[4], 3, 0x2, 0x401800, dynstr_off, len(dynstr_blob), 0, 0, 1, 0),
            struct.pack("<IIQQQQIIQQ", shstr_offs[5], 6, 0x3, 0x402000, dynamic_off, len(dynamic_blob), 4, 0, 8, 16),
            struct.pack("<IIQQQQIIQQ", shstr_offs[6], 3, 0x0, 0, shstr_off, len(shstr_blob), 0, 0, 1, 0),
        ]
    )

    return ehdr + phdrs + text_blob + rodata_blob + dynsym_blob + dynstr_blob + dynamic_blob + shstr_blob + shdrs


def build_sample_pe64() -> bytes:
    """Build a valid PE32+ x86_64 sample executable with IAT, exports, and security flags."""
    e_lfanew = 0x80
    dos = bytearray(e_lfanew)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    # Layout: headers end at 0x200, .text at 0x200 (RVA 0x1000), .rdata at 0x400 (RVA 0x2000)
    # Build .rdata containing Import Directory, Export Directory, DLL/function strings
    rdata = bytearray(0x400)
    rdata_rva = 0x2000

    # Strings inside .rdata starting at 0x180
    def put_str(off: int, text: str) -> int:
        raw = text.encode("ascii") + b"\x00"
        rdata[off : off + len(raw)] = raw
        return rdata_rva + off

    k32_rva = put_str(0x180, "KERNEL32.dll")
    ws2_rva = put_str(0x190, "WS2_32.dll")
    # Import by name structs: 2-byte Hint + ASCII
    imp1_rva = rdata_rva + 0x1A0
    struct.pack_into("<H", rdata, 0x1A0, 1)
    put_str(0x1A2, "VirtualAllocEx")
    imp2_rva = rdata_rva + 0x1C0
    struct.pack_into("<H", rdata, 0x1C0, 2)
    put_str(0x1C2, "CreateRemoteThread")
    imp3_rva = rdata_rva + 0x1E0
    struct.pack_into("<H", rdata, 0x1E0, 3)
    put_str(0x1E2, "WSAStartup")

    # ILTs at 0x80 (k32) and 0xA0 (ws2)
    struct.pack_into("<QQQ", rdata, 0x80, imp1_rva, imp2_rva, 0)
    struct.pack_into("<QQ", rdata, 0xA0, imp3_rva, 0)

    # Import descriptors at 0x00
    struct.pack_into("<IIIII", rdata, 0x00, rdata_rva + 0x80, 0, 0, k32_rva, rdata_rva + 0x80)
    struct.pack_into("<IIIII", rdata, 0x14, rdata_rva + 0xA0, 0, 0, ws2_rva, rdata_rva + 0xA0)
    # terminator at 0x28 is already zeros

    # Export directory at 0x100
    exp_dll_rva = put_str(0x210, "agent.exe")
    exp_sym_rva = put_str(0x220, "RunDiagnostics")
    struct.pack_into("<I", rdata, 0x140, 0x1000)  # AddressOfFunctions
    struct.pack_into("<I", rdata, 0x148, exp_sym_rva)  # AddressOfNames
    struct.pack_into("<H", rdata, 0x150, 0)  # AddressOfNameOrdinals
    struct.pack_into(
        "<IIHHIIIIIII",
        rdata,
        0x100,
        0,
        1700000000,
        1,
        0,
        exp_dll_rva,
        1,
        1,
        1,
        rdata_rva + 0x140,
        rdata_rva + 0x148,
        rdata_rva + 0x150,
    )
    put_str(0x240, "https://c2.lab.internal/checkin")

    text = _pad(b"\x48\x83\xec\x28\x33\xc0\x48\x83\xc4\x28\xc3" * 10, 0x200)

    # PE header + OptionalHeader64 (240 bytes) + 2 sections (80 bytes)
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 1700000000, 0, 0, 240, 0x0022)
    opt = bytearray(240)
    struct.pack_into("<HBB", opt, 0, 0x20B, 14, 0)
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)  # SectionAlignment, FileAlignment
    struct.pack_into("<II", opt, 56, 0x3000, 0x200)  # SizeOfImage, SizeOfHeaders
    struct.pack_into("<HH", opt, 68, 3, 0x8160)  # CUI, NX+DynamicBase+HighEntropyVA+TSAware
    struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 112, rdata_rva + 0x100, 40)  # Export Dir
    struct.pack_into("<II", opt, 120, rdata_rva, 60)  # Import Dir

    sec_text = struct.pack(
        "<8sIIIIIIHHI", b".text", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020
    )
    sec_rdata = struct.pack(
        "<8sIIIIIIHHI", b".rdata", 0x400, 0x2000, 0x400, 0x400, 0, 0, 0, 0, 0x40000040
    )

    headers = _pad(bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sec_text + sec_rdata, 0x200)
    return headers + text + bytes(rdata)


def build_sample_macho64() -> bytes:
    """Build a valid 64-bit ARM64 Mach-O sample binary with segments, dylibs, symtab, and LC_MAIN."""
    # Load commands: LC_SEGMENT_64(__TEXT + __text), LC_LOAD_DYLIB, LC_MAIN, LC_SYMTAB
    strtab = b"\x00_printf\x00_dlopen\x00_main\x00https://updates.blackboxlab.local/pkg\x00"
    # offsets in strtab: _printf=1, _dlopen=9, _main=17
    symtab = b"".join(
        [
            struct.pack("<IBBHQ", 1, 0x01, 0, 0, 0),  # _printf (N_EXT|N_UNDF)
            struct.pack("<IBBHQ", 9, 0x01, 0, 0, 0),  # _dlopen (N_EXT|N_UNDF)
            struct.pack("<IBBHQ", 17, 0x0F, 1, 0, 0x100000400),  # _main (N_EXT|N_SECT)
        ]
    )

    dylib_path = b"/usr/lib/libSystem.B.dylib\x00"
    dylib_cmdsize = (24 + len(dylib_path) + 7) & ~7
    lc_dylib = struct.pack("<IIIIII", 0xC, dylib_cmdsize, 24, 2, 0x05260000, 0x00010000) + _pad(
        dylib_path, dylib_cmdsize - 24
    )

    lc_main = struct.pack("<IIQQ", 0x80000028, 24, 0x400, 0)
    lc_symtab_placeholder_size = 24
    lc_seg_size = 72 + 80

    sizeofcmds = lc_seg_size + len(lc_dylib) + len(lc_main) + lc_symtab_placeholder_size
    code_offset = 0x400
    code_blob = b"\xfd\x7b\xbf\xa9\xfd\x03\x00\x91\x00\x00\x80\x52\xfd\x7b\xc1\xa8\xc0\x03\x5f\xd6" * 6
    symoff = code_offset + len(code_blob)
    stroff = symoff + len(symtab)
    total_size = stroff + len(strtab)

    lc_seg = struct.pack(
        "<II16sQQQQIIII",
        0x19,
        lc_seg_size,
        b"__TEXT",
        0x100000000,
        0x1000,
        0,
        total_size,
        7,
        5,
        1,
        0,
    )
    lc_sec = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text",
        b"__TEXT",
        0x100000400,
        len(code_blob),
        code_offset,
        4,
        0,
        0,
        0x80000400,
        0,
        0,
        0,
    )
    lc_symtab = struct.pack("<IIIIII", 0x2, 24, symoff, 3, stroff, len(strtab))

    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,  # MH_MAGIC_64
        0x0100000C,  # ARM64
        0,
        2,  # MH_EXECUTE
        4,
        sizeofcmds,
        0x00200085,  # MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE
        0,
    )
    cmds = lc_seg + lc_sec + lc_dylib + lc_main + lc_symtab
    return _pad(header + cmds, code_offset) + code_blob + symtab + strtab


BUILTIN_SAMPLES = {
    "elf64-beacon": ("sample-beacon.elf", build_sample_elf64),
    "pe64-agent": ("sample-agent.exe", build_sample_pe64),
    "macho64-cli": ("sample-cli.macho", build_sample_macho64),
}
