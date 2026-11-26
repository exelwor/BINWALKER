"""Security posture and structural anomaly heuristics.

Produces explainable findings and a transparent 0-10 static risk score.
"""

from __future__ import annotations

from collections import defaultdict

from binwalker.analysis.entropy import HIGH_ENTROPY_THRESHOLD, PACKED_THRESHOLD
from binwalker.models import (
    AnomalyFinding,
    BinaryFormat,
    ParsedBinary,
    Severity,
    StringMatch,
)


def evaluate_findings(
    parsed: ParsedBinary,
    overall_entropy: float,
    strings: list[StringMatch],
) -> list[AnomalyFinding]:
    findings: list[AnomalyFinding] = []
    sec = parsed.security
    fmt = parsed.header.format

    if sec.nx is False:
        findings.append(
            AnomalyFinding(
                id="SEC-NX",
                title="Executable stack / missing NX (DEP)",
                severity=Severity.HIGH,
                category="mitigation",
                description=(
                    "The binary does not enforce non-executable stack/memory protections (NX/DEP), "
                    "making stack-based code injection easier if memory corruption occurs."
                ),
                remediation="Compile with NX/DEP enabled (-z noexecstack on ELF, /NXCOMPAT on PE).",
                evidence=(f"format={fmt.value}", "nx=false"),
            )
        )

    if sec.pie is False and parsed.header.file_type not in ("object", "relocatable"):
        findings.append(
            AnomalyFinding(
                id="SEC-PIE",
                title="Position-independent code / ASLR disabled",
                severity=Severity.MEDIUM,
                category="mitigation",
                description=(
                    "The image lacks PIE/DYNAMIC_BASE support, fixing code addresses across runs and "
                    "weakening address space layout randomization."
                ),
                remediation="Build with -fPIE -pie (ELF/Mach-O) or /DYNAMICBASE (PE).",
                evidence=(f"file_type={parsed.header.file_type}", "pie=false"),
            )
        )

    if fmt is BinaryFormat.ELF and sec.relro in ("none", "partial"):
        sev = Severity.MEDIUM if sec.relro == "none" else Severity.LOW
        findings.append(
            AnomalyFinding(
                id="SEC-RELRO",
                title=f"ELF RELRO is {sec.relro}",
                severity=sev,
                category="mitigation",
                description=(
                    "Without Full RELRO, the Global Offset Table (GOT) remains writable at runtime "
                    "and can be targeted by GOT-overwrite primitives."
                ),
                remediation="Link with -Wl,-z,relro,-z,now for Full RELRO.",
                evidence=(f"relro={sec.relro}",),
            )
        )

    if fmt is BinaryFormat.PE and sec.cfg is False:
        findings.append(
            AnomalyFinding(
                id="SEC-CFG",
                title="Control Flow Guard (CFG) disabled",
                severity=Severity.LOW,
                category="mitigation",
                description="Indirect call target validation (CFG) is not enabled in DllCharacteristics.",
                remediation="Compile and link with /guard:cf.",
                evidence=("cfg=false",),
            )
        )

    if fmt in (BinaryFormat.PE, BinaryFormat.MACHO, BinaryFormat.MACHO_FAT) and sec.signed is False:
        findings.append(
            AnomalyFinding(
                id="SEC-UNSIGNED",
                title="Binary has no embedded code signature",
                severity=Severity.LOW,
                category="integrity",
                description="No Authenticode directory or Mach-O LC_CODE_SIGNATURE command was found.",
                remediation="Sign release artifacts with a trusted code-signing identity.",
                evidence=(f"format={fmt.value}", "signed=false"),
            )
        )

    # W^X sections & segments
    wx_sections = [s for s in parsed.sections if s.is_writable and s.is_executable]
    if wx_sections:
        findings.append(
            AnomalyFinding(
                id="ANOM-WX",
                title="Writable and executable (W^X) section detected",
                severity=Severity.HIGH,
                category="structure",
                description=(
                    "One or more sections have both write and execute permissions, a classic trait of "
                    "self-modifying code, JIT stubs, or unpacker stubs."
                ),
                remediation="Separate writable data (.data) from executable code (.text).",
                evidence=tuple(f"{s.name} ({','.join(s.flags)})" for s in wx_sections[:6]),
            )
        )

    # High entropy sections or overall file entropy
    high_ent = [s for s in parsed.sections if s.raw_size >= 128 and s.entropy >= HIGH_ENTROPY_THRESHOLD]
    if high_ent or overall_entropy >= PACKED_THRESHOLD:
        max_ent = max([overall_entropy] + [s.entropy for s in high_ent])
        sev = Severity.HIGH if max_ent >= PACKED_THRESHOLD else Severity.MEDIUM
        ev = [f"overall={overall_entropy:.2f}"] + [f"{s.name}={s.entropy:.2f}" for s in high_ent[:5]]
        findings.append(
            AnomalyFinding(
                id="ANOM-ENTROPY",
                title="High-entropy / potentially packed or encrypted regions",
                severity=sev,
                category="entropy",
                description=(
                    "High Shannon entropy (>= 7.2 bits/byte) indicates compressed, encrypted, or packed "
                    "payloads, or embedded cryptographic material."
                ),
                remediation="Inspect high-entropy sections for packers (e.g. UPX) or embedded blobs.",
                evidence=tuple(ev),
            )
        )

    # Suspicious / high-risk import capabilities
    by_cat: dict[str, list[str]] = defaultdict(list)
    for imp in parsed.imports:
        if imp.category != "general":
            by_cat[imp.category].append(f"{imp.library}:{imp.symbol}")

    if by_cat.get("memory") and by_cat.get("process"):
        findings.append(
            AnomalyFinding(
                id="CAP-INJECTION",
                title="Memory manipulation + process control imports",
                severity=Severity.HIGH,
                category="capabilities",
                description=(
                    "The binary imports APIs capable of allocating/modifying memory and spawning or "
                    "manipulating processes."
                ),
                remediation="Verify whether process/memory APIs match the binary's documented purpose.",
                evidence=tuple((by_cat["memory"] + by_cat["process"])[:8]),
            )
        )
    elif by_cat.get("process") or by_cat.get("memory"):
        combined = by_cat.get("process", []) + by_cat.get("memory", [])
        findings.append(
            AnomalyFinding(
                id="CAP-EXEC",
                title="Process execution or raw memory control imports",
                severity=Severity.MEDIUM,
                category="capabilities",
                description="Imports include process creation or low-level memory permission APIs.",
                remediation="Audit call sites for command injection or unsafe memory permissions.",
                evidence=tuple(combined[:8]),
            )
        )

    if by_cat.get("anti_debug"):
        findings.append(
            AnomalyFinding(
                id="CAP-ANTIDEBUG",
                title="Anti-debugging API imports detected",
                severity=Severity.MEDIUM,
                category="capabilities",
                description="The binary references debugger-detection or process-inspection APIs.",
                remediation="Review whether anti-analysis checks are expected DRM or evasion logic.",
                evidence=tuple(by_cat["anti_debug"][:6]),
            )
        )

    if by_cat.get("network"):
        findings.append(
            AnomalyFinding(
                id="CAP-NETWORK",
                title="Network communication imports",
                severity=Severity.INFO,
                category="capabilities",
                description="The binary imports socket or HTTP networking symbols.",
                remediation="Confirm outbound/inbound network activity aligns with expected behavior.",
                evidence=tuple(by_cat["network"][:6]),
            )
        )

    cmd_or_url = [s for s in strings if s.category in ("command", "url")]
    if cmd_or_url:
        findings.append(
            AnomalyFinding(
                id="STR-INDICATORS",
                title="Embedded command or URL string indicators",
                severity=Severity.LOW,
                category="strings",
                description="Static string scan uncovered embedded shell commands or network URLs.",
                remediation="Inspect referenced URLs/commands to verify they are benign configuration.",
                evidence=tuple(f"[{s.category}] {s.value[:80]}" for s in cmd_or_url[:6]),
            )
        )

    if parsed.warnings:
        findings.append(
            AnomalyFinding(
                id="PARSE-WARN",
                title="Structural parser warnings encountered",
                severity=Severity.MEDIUM,
                category="structure",
                description="Parts of the binary header or tables appeared truncated or non-standard.",
                remediation="Inspect raw headers for intentional tampering or compiler quirks.",
                evidence=parsed.warnings[:5],
            )
        )

    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    findings.sort(key=lambda f: (order[f.severity], f.id))
    return findings


def compute_risk_score(findings: list[AnomalyFinding]) -> float:
    """Transparent additive score capped at 10.0."""
    total = sum(f.severity.weight for f in findings)
    return round(min(10.0, total), 2)
