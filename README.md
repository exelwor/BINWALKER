# BINWALKER

> **Part of BLACKBOX LAB** — static executable structure analyzer.
> Inspects binary headers, segments, sections, imports, exports, strings, Shannon entropy, and security mitigations **without ever executing the file**.

```
binary ──> format detection ──> ELF / PE / Mach-O parser ──> entropy / strings / heuristics ──> Web UI / HTML / MD / API
```

## Features

* **Multi-format static parsing** (pure Python with bounds-checked binary readers):
  * **ELF32 / ELF64** (little & big endian): headers, program segments, sections, `.dynsym` imports/exports, `DT_NEEDED` libraries, `NX` (`PT_GNU_STACK`), `PIE`, `RELRO` (`none`/`partial`/`full`), stack canary, stripped status.
  * **PE32 / PE32+** (`.exe`, `.dll`, `.sys`): DOS/COFF/Optional headers, sections, Import Address Table (by name & ordinal), Export Directory, `ASLR`/`DynamicBase`, `DEP/NX`, `HighEntropyVA`, `CFG`, Authenticode signature presence.
  * **Mach-O (32/64-bit) & Universal/Fat archives**: `LC_SEGMENT(_64)`, `LC_LOAD_DYLIB`, `LC_MAIN`, `LC_SYMTAB`, `LC_CODE_SIGNATURE`, `LC_ENCRYPTION_INFO`, `MH_PIE`, stack execution flags.
* **Entropy & indicator analysis**:
  * Per-section and sliding-window Shannon entropy profile (`0.0`–`8.0` bits/byte) to spot packed or encrypted regions (`>= 7.2`).
  * ASCII & UTF-16LE string extraction categorized into URLs, IPs, shell commands, registry keys, and filesystem paths.
* **Security posture & anomaly scoring**:
  * Detects missing exploit mitigations, `W^X` (writable + executable) sections, high-entropy blobs, and categorized API capabilities (process, memory, anti-debug, network).
  * Produces an explainable `0–10` risk score and actionable remediation hints.
* **Interactive Web UI & self-contained reports**:
  * Drag-and-drop web workbench (`binwalker serve`) with interactive SVG section layout map, SVG entropy chart, filterable tables, analysis history, and built-in lab samples.
  * Export standalone offline HTML (`-o report.html`), Markdown (`--md`), or JSON (`--json`), plus a `--fail-on SCORE` CI gate.

## Quick start

```bash
pip install -e ".[dev]"

binwalker sample --name elf64-beacon -o sample.elf
binwalker inspect sample.elf
binwalker analyze sample.elf -o report.html --md report.md
```

Start the Web UI and HTTP API:

```bash
binwalker serve            # http://127.0.0.1:8000
# or
docker compose up --build
```

> **Security notice:** BINWALKER performs static parsing only and never executes uploaded files, but the web server has no built-in authentication and binds to `127.0.0.1` by default. Do not expose it directly to untrusted networks without a reverse proxy and auth.

## Architecture

| Module | Responsibility |
|--------|----------------|
| `models.py` | Immutable dataclasses (`ParsedBinary`, `HeaderSummary`, `SectionInfo`, `SecurityFlags`, `AnomalyFinding`, etc.) |
| `parsers/__init__.py` | Magic-byte format detection, `BinaryReader` bounds-checked primitives, parser dispatch |
| `parsers/elf.py` | ELF32/64 static parser |
| `parsers/pe.py` | PE32/PE32+ static parser |
| `parsers/macho.py` | Mach-O 32/64 and Universal/Fat static parser |
| `analysis/entropy.py` | Shannon entropy, sliding-window profile, API capability classification |
| `analysis/strings.py` | ASCII & UTF-16LE printable string extractor and indicator classifier |
| `analysis/heuristics.py` | Mitigation checks, structural anomaly rules, and risk scoring |
| `pipeline.py` | Single JSON contract (`analyze_bytes`, `analyze_file`) consumed by all front ends |
| `report.py` | Markdown and standalone interactive HTML report renderer |
| `web/viewer.html` | Interactive workbench UI (plain JS + SVG, zero build step, works offline) |
| `api.py`, `storage.py` | FastAPI HTTP service and SQLite storage (PostgreSQL-ready interface) |
| `samples.py` | Pure-Python deterministic ELF64, PE32+, and Mach-O 64 sample builders |

## API endpoints

* `GET /api/health` — liveness check
* `GET /api/samples` — list built-in synthetic samples
* `POST /api/samples/{sample_id}/analyze` — analyze and store a built-in sample
* `POST /api/analyze` — multipart binary upload (`file`)
* `GET /api/analyses`, `GET /api/analyses/{id}`, `DELETE /api/analyses/{id}` — history CRUD
* `GET /api/analyses/{id}/report.html`, `GET /api/analyses/{id}/report.md` — downloadable reports

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

## Roadmap

* Native Rust parsing/entropy module via PyO3 for multi-megabyte firmware and batch scanning.
* Signature matching (YARA / packer database) and DWARF / PDB metadata extraction.
* PostgreSQL backend implementing the `Storage` interface.
* React workspace front end if the UI grows beyond a single self-contained bundle.

## License

MIT. See [LICENSE](LICENSE).
