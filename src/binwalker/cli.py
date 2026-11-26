"""Command-line interface for BINWALKER.

  binwalker analyze binary.elf -o report.html --md report.md --fail-on 7
  binwalker inspect binary.exe
  binwalker sample --name elf64-beacon -o sample.elf
  binwalker serve --port 8000
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from binwalker import __version__
from binwalker.parsers import BinaryParseError
from binwalker.pipeline import analyze_file
from binwalker.report import render_html, render_markdown
from binwalker.samples import BUILTIN_SAMPLES


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="binwalker", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=f"binwalker {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("analyze", help="analyze an executable and emit reports")
    run.add_argument("binary", help="path to ELF, PE, or Mach-O file")
    run.add_argument("-o", "--html", help="write an interactive HTML report")
    run.add_argument("--md", help="write a Markdown report")
    run.add_argument("--json", dest="json_out", help="write full JSON analysis")
    run.add_argument(
        "--fail-on", type=float, metavar="SCORE", help="exit with code 1 if risk score >= SCORE"
    )

    inspect_cmd = sub.add_parser("inspect", help="print structural summary without writing files")
    inspect_cmd.add_argument("binary", help="path to ELF, PE, or Mach-O file")

    sample = sub.add_parser("sample", help="generate a synthetic sample binary")
    sample.add_argument(
        "--name",
        choices=sorted(BUILTIN_SAMPLES),
        default="elf64-beacon",
        help="which built-in sample binary to write",
    )
    sample.add_argument("-o", "--out", help="output file path (defaults to sample filename)")

    serve = sub.add_parser("serve", help="start the BINWALKER web server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--db", default="binwalker.db", help="SQLite file for saved analyses")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "sample":
        default_name, builder = BUILTIN_SAMPLES[args.name]
        out_path = Path(args.out or default_name)
        out_path.write_bytes(builder())
        print(f"wrote {out_path} ({out_path.stat().st_size} bytes)")
        return 0

    if args.command == "serve":
        try:
            import uvicorn

            from binwalker.api import create_app
        except ImportError:
            print('Web server dependencies missing: pip install "binwalker[server]"', file=sys.stderr)
            return 2
        uvicorn.run(create_app(args.db), host=args.host, port=args.port)
        return 0

    try:
        result = analyze_file(args.binary)
    except BinaryParseError as exc:
        print(f"Parse error: {exc}", file=sys.stderr)
        return 2

    f = result["file"]
    h = result["header"]
    s = result["summary"]
    print(
        f"{f['name']}: {h['format'].upper()} {h['architecture']} ({h['bits']}-bit, {h['file_type']}), "
        f"risk {s['score']:.1f}/10 ({s['rating']}), entropy {f['entropy']:.2f}, "
        f"{s['sections']} section(s), {s['imports']} import(s), {s['findings']} finding(s)."
    )

    if args.command == "inspect":
        for item in result["findings"]:
            print(f"  [{item['severity'].upper()}] {item['id']}: {item['title']}")
        return 0

    if args.html:
        Path(args.html).write_text(render_html(result), encoding="utf-8")
        print(f"wrote {args.html}")
    if args.md:
        Path(args.md).write_text(render_markdown(result), encoding="utf-8")
        print(f"wrote {args.md}")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"wrote {args.json_out}")

    if args.fail_on is not None and s["score"] >= args.fail_on:
        print(f"FAIL: risk score {s['score']:.1f} >= threshold {args.fail_on}", file=sys.stderr)
        return 1
    return 0
