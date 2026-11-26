"""Analysis pipeline: raw executable bytes -> JSON-serializable report dict."""

from __future__ import annotations

import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from binwalker import __version__
from binwalker.analysis.entropy import entropy_profile, shannon_entropy
from binwalker.analysis.heuristics import compute_risk_score, evaluate_findings
from binwalker.analysis.strings import extract_strings
from binwalker.parsers import BinaryParseError, parse_binary

RATINGS = ((8.5, "critical"), (6.0, "high"), (3.5, "medium"), (0.5, "low"))


def rating(score: float) -> str:
    for threshold, label in RATINGS:
        if score >= threshold:
            return label
    return "clean"


def _hex(value: int | None) -> str | None:
    return f"0x{value:x}" if value is not None else None


def analyze_bytes(data: bytes, filename: str = "sample.bin") -> dict:
    parsed = parse_binary(data, filename)
    overall_entropy = shannon_entropy(data)
    windows = entropy_profile(data)
    strings = extract_strings(data)
    findings = evaluate_findings(parsed, overall_entropy, strings)
    score = compute_risk_score(findings)

    import_categories = Counter(imp.category for imp in parsed.imports)
    finding_severities = Counter(f.severity.value for f in findings)

    return {
        "schema": 1,
        "tool_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "file": {
            "name": parsed.filename,
            "size": parsed.size,
            "md5": parsed.md5,
            "sha1": parsed.sha1,
            "sha256": parsed.sha256,
            "entropy": overall_entropy,
        },
        "header": {
            "format": parsed.header.format.value,
            "architecture": parsed.header.architecture,
            "bits": parsed.header.bits,
            "endianness": parsed.header.endianness.value,
            "file_type": parsed.header.file_type,
            "entry_point": _hex(parsed.header.entry_point),
            "image_base": _hex(parsed.header.image_base),
            "subsystem": parsed.header.subsystem,
            "machine_raw": parsed.header.machine_raw,
            "compile_timestamp": parsed.header.compile_timestamp,
            "interpreter": parsed.header.interpreter,
            "os_abi": parsed.header.os_abi,
        },
        "summary": {
            "score": score,
            "rating": rating(score),
            "overall_entropy": overall_entropy,
            "sections": len(parsed.sections),
            "segments": len(parsed.segments),
            "libraries": len(parsed.libraries),
            "imports": len(parsed.imports),
            "exports": len(parsed.exports),
            "strings": len(strings),
            "findings": len(findings),
            "by_severity": {
                sev: finding_severities.get(sev, 0)
                for sev in ("critical", "high", "medium", "low", "info")
            },
            "import_categories": dict(sorted(import_categories.items())),
        },
        "security": {
            "nx": parsed.security.nx,
            "pie": parsed.security.pie,
            "relro": parsed.security.relro,
            "canary": parsed.security.canary,
            "cfg": parsed.security.cfg,
            "signed": parsed.security.signed,
            "stripped": parsed.security.stripped,
            "high_entropy_va": parsed.security.high_entropy_va,
        },
        "sections": [
            {
                "name": s.name,
                "virtual_address": _hex(s.virtual_address),
                "virtual_size": s.virtual_size,
                "raw_offset": _hex(s.raw_offset),
                "raw_size": s.raw_size,
                "flags": list(s.flags),
                "type": s.section_type,
                "entropy": s.entropy,
                "is_executable": s.is_executable,
                "is_writable": s.is_writable,
                "is_readable": s.is_readable,
            }
            for s in parsed.sections
        ],
        "segments": [
            {
                "type": seg.type,
                "virtual_address": _hex(seg.virtual_address),
                "virtual_size": seg.virtual_size,
                "file_offset": _hex(seg.file_offset),
                "file_size": seg.file_size,
                "flags": list(seg.flags),
            }
            for seg in parsed.segments
        ],
        "libraries": list(parsed.libraries),
        "imports": [
            {
                "library": imp.library,
                "symbol": imp.symbol,
                "ordinal": imp.ordinal,
                "address": _hex(imp.address),
                "category": imp.category,
            }
            for imp in parsed.imports
        ],
        "exports": [
            {
                "symbol": exp.symbol,
                "address": _hex(exp.address),
                "ordinal": exp.ordinal,
            }
            for exp in parsed.exports
        ],
        "entropy_profile": [
            {"offset": w.offset, "size": w.size, "entropy": w.entropy} for w in windows
        ],
        "strings": [
            {
                "value": st.value,
                "offset": _hex(st.offset),
                "encoding": st.encoding,
                "category": st.category,
            }
            for st in strings
        ],
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": list(f.evidence),
            }
            for f in findings
        ],
        "metadata": {k: v for k, v in parsed.metadata},
        "warnings": list(parsed.warnings),
    }


def analyze_file(path: str | os.PathLike) -> dict:
    file_path = Path(path)
    try:
        data = file_path.read_bytes()
    except OSError as exc:
        raise BinaryParseError(f"cannot read {file_path}: {exc.strerror}") from exc
    return analyze_bytes(data, filename=file_path.name)
