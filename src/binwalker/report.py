"""Report generator: Markdown for terminals/CI and standalone interactive HTML."""

from __future__ import annotations

import json
from importlib import resources

_TOKEN = "/*BINWALKER_DATA*/null"


def _cell(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _flag(val: bool | str | None) -> str:
    if val is True:
        return "enabled"
    if val is False:
        return "disabled"
    if val is None:
        return "n/a"
    return str(val)


def render_markdown(result: dict) -> str:
    f = result["file"]
    h = result["header"]
    s = result["summary"]
    sec = result["security"]

    out = [
        f"# BINWALKER static report: {f['name']}",
        "",
        f"Generated {result['generated_at']} by BINWALKER {result['tool_version']}.",
        "",
        f"**Risk score: {s['score']:.1f} / 10 ({s['rating']})** | "
        f"**Format:** `{h['format'].upper()}` ({h['architecture']}, {h['bits']}-bit, {h['endianness']}-endian) | "
        f"**Entropy:** {f['entropy']:.2f} bits/byte",
        "",
        f"- **Size:** {f['size']} bytes",
        f"- **SHA-256:** `{f['sha256']}`",
        f"- **MD5:** `{f['md5']}`",
        f"- **File type:** {h['file_type']} | **Entry point:** `{h['entry_point'] or 'n/a'}`",
        "",
        "## Security mitigations",
        "",
        "| Mitigation | Status |",
        "|------------|--------|",
        f"| NX / DEP | {_flag(sec['nx'])} |",
        f"| PIE / ASLR | {_flag(sec['pie'])} |",
        f"| RELRO | {_flag(sec['relro'])} |",
        f"| Stack Canary | {_flag(sec['canary'])} |",
        f"| Control Flow Guard | {_flag(sec['cfg'])} |",
        f"| Code Signature | {_flag(sec['signed'])} |",
        f"| Stripped Symbols | {_flag(sec['stripped'])} |",
        "",
        "## Findings",
        "",
    ]

    if not result["findings"]:
        out += ["No structural anomalies or missing mitigations detected.", ""]
    else:
        out += [
            "| ID | Severity | Title | Evidence | Remediation |",
            "|----|----------|-------|----------|-------------|",
        ]
        for item in result["findings"]:
            ev = ", ".join(item["evidence"]) or "-"
            out.append(
                f"| `{item['id']}` | {item['severity']} | {_cell(item['title'])} "
                f"| {_cell(ev)} | {_cell(item['remediation'])} |"
            )
        out.append("")

    out += ["## Sections", ""]
    if not result["sections"]:
        out += ["No section headers present.", ""]
    else:
        out += [
            "| Name | VirtAddr | RawOffset | RawSize | Flags | Entropy |",
            "|------|----------|-----------|---------|-------|---------|",
        ]
        for section in result["sections"]:
            out.append(
                f"| `{_cell(section['name'])}` | `{section['virtual_address']}` | `{section['raw_offset']}` "
                f"| {section['raw_size']} | `{','.join(section['flags']) or '-'}` | {section['entropy']:.2f} |"
            )
        out.append("")

    out += ["## Linked libraries & top imports", ""]
    if result["libraries"]:
        out += [f"- **Libraries:** {', '.join(f'`{lib}`' for lib in result['libraries'])}", ""]
    if result["imports"]:
        out += [
            "| Library | Symbol | Category |",
            "|---------|--------|----------|",
        ]
        for imp in result["imports"][:40]:
            out.append(f"| `{_cell(imp['library'])}` | `{_cell(imp['symbol'])}` | {imp['category']} |")
        if len(result["imports"]) > 40:
            out += ["", f"_{len(result['imports']) - 40} additional import(s) omitted._"]
    else:
        out += ["No dynamic imports found."]

    return "\n".join(out) + "\n"


def viewer_template() -> str:
    return resources.files("binwalker").joinpath("web/viewer.html").read_text(encoding="utf-8")


def render_html(result: dict | None) -> str:
    """Self-contained interactive HTML report, or empty web app shell when ``result`` is None."""
    template = viewer_template()
    if result is None:
        return template
    payload = (
        json.dumps(result)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    return template.replace(_TOKEN, payload)
