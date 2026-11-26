"""HTTP API (FastAPI). Thin transport layer over the static analysis pipeline."""

from __future__ import annotations

import os

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse

from binwalker import __version__
from binwalker.parsers import MAX_BINARY_SIZE, BinaryParseError
from binwalker.pipeline import analyze_bytes
from binwalker.report import render_html, render_markdown
from binwalker.samples import BUILTIN_SAMPLES
from binwalker.storage import Storage

_SAMPLE_DESCRIPTIONS = {
    "elf64-beacon": (
        "ELF64 x86_64 executable with RWX stack, W^X .text, high-entropy .rodata, and process/network imports"
    ),
    "pe64-agent": "PE32+ x86_64 Windows executable with IAT injection/network imports, exports, and ASLR/NX flags",
    "macho64-cli": "Mach-O ARM64 macOS executable with PIE, __TEXT.__text, dylib load command, and symtab",
}


def create_app(db_path: str | None = None) -> FastAPI:
    app = FastAPI(title="BINWALKER", version=__version__)
    storage = Storage(db_path or os.environ.get("BINWALKER_DB", "binwalker.db"))

    def not_found() -> HTTPException:
        return HTTPException(status_code=404, detail="analysis not found")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return render_html(None)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/api/samples")
    def list_samples() -> list[dict]:
        return [
            {
                "id": sid,
                "filename": fname,
                "description": _SAMPLE_DESCRIPTIONS.get(sid, ""),
            }
            for sid, (fname, _) in BUILTIN_SAMPLES.items()
        ]

    @app.post("/api/samples/{sample_id}/analyze")
    def analyze_sample(sample_id: str) -> dict:
        entry = BUILTIN_SAMPLES.get(sample_id)
        if entry is None:
            raise HTTPException(status_code=404, detail=f"unknown sample {sample_id!r}")
        filename, builder = entry
        result = analyze_bytes(builder(), filename=filename)
        result["id"] = storage.save(result)
        return result

    @app.post("/api/analyze")
    async def analyze_upload(file: UploadFile = File(...)) -> dict:
        data = await file.read(MAX_BINARY_SIZE + 1)
        if len(data) > MAX_BINARY_SIZE:
            raise HTTPException(status_code=413, detail="uploaded file exceeds maximum analysis size")
        try:
            result = analyze_bytes(data, filename=file.filename or "upload.bin")
        except BinaryParseError as exc:
            raise HTTPException(status_code=422, detail={"error": str(exc)}) from exc
        result["id"] = storage.save(result)
        return result

    @app.get("/api/analyses")
    def list_analyses() -> list[dict]:
        return storage.list()

    @app.get("/api/analyses/{analysis_id}")
    def get_analysis(analysis_id: str) -> dict:
        result = storage.get(analysis_id)
        if result is None:
            raise not_found()
        result["id"] = analysis_id
        return result

    @app.get("/api/analyses/{analysis_id}/report.html", response_class=HTMLResponse)
    def report_html(analysis_id: str) -> str:
        result = storage.get(analysis_id)
        if result is None:
            raise not_found()
        return render_html(result)

    @app.get("/api/analyses/{analysis_id}/report.md")
    def report_md(analysis_id: str) -> PlainTextResponse:
        result = storage.get(analysis_id)
        if result is None:
            raise not_found()
        return PlainTextResponse(render_markdown(result), media_type="text/markdown")

    @app.delete("/api/analyses/{analysis_id}", status_code=204)
    def delete_analysis(analysis_id: str) -> None:
        if not storage.delete(analysis_id):
            raise not_found()

    return app


# Run with: uvicorn binwalker.api:create_app --factory
