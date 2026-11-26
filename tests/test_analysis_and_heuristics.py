import os

from binwalker.analysis.entropy import entropy_profile, shannon_entropy
from binwalker.analysis.strings import extract_strings
from binwalker.pipeline import analyze_bytes
from binwalker.samples import build_sample_elf64, build_sample_macho64, build_sample_pe64


def test_entropy_bounds_and_profile():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 1024) == 0.0
    high = shannon_entropy(os.urandom(4096))
    assert high > 7.5
    profile = entropy_profile(b"\x00" * 512 + os.urandom(512), min_window=256)
    assert len(profile) >= 2
    assert profile[0].entropy == 0.0
    assert profile[-1].entropy > 6.5


def test_strings_extracts_ascii_utf16_and_tags_indicators():
    blob = (
        b"\x00\x00https://evil.example/payload\x00"
        + b"/bin/sh -c whoami\x00"
        + "HKEY_LOCAL_MACHINE\\Software\\Test".encode("utf-16-le")
        + b"\x00\x00"
    )
    matches = extract_strings(blob, min_len=5)
    cats = {m.value: m.category for m in matches}
    assert cats["https://evil.example/payload"] == "url"
    assert cats["/bin/sh -c whoami"] == "command"
    assert any(m.encoding == "utf-16le" and m.category == "registry" for m in matches)


def test_elf_sample_triggers_wx_nx_entropy_and_capability_findings():
    res = analyze_bytes(build_sample_elf64(), "sample.elf")
    ids = {f["id"] for f in res["findings"]}
    assert {"SEC-NX", "SEC-PIE", "ANOM-WX", "ANOM-ENTROPY", "CAP-INJECTION", "STR-INDICATORS"} <= ids
    assert 0.0 < res["summary"]["score"] <= 10.0


def test_pe_and_macho_samples_produce_coherent_summaries():
    pe_res = analyze_bytes(build_sample_pe64(), "agent.exe")
    assert pe_res["summary"]["imports"] == 3
    assert any(f["id"] == "CAP-INJECTION" for f in pe_res["findings"])

    macho_res = analyze_bytes(build_sample_macho64(), "cli.macho")
    assert macho_res["header"]["format"] == "macho"
    assert macho_res["summary"]["exports"] == 1
