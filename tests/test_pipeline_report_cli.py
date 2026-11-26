import json

from binwalker.cli import main
from binwalker.pipeline import analyze_bytes
from binwalker.report import render_html, render_markdown
from binwalker.samples import build_sample_elf64
from binwalker.storage import Storage


def test_markdown_and_html_reports_escape_xss():
    res = analyze_bytes(build_sample_elf64(), filename="</script><script>alert(1)</script>.elf")
    md = render_markdown(res)
    assert md.startswith("# BINWALKER static report:")
    assert "## Security mitigations" in md
    assert "execve" in md

    html = render_html(res)
    assert "/*BINWALKER_DATA*/null" not in html
    assert "</script><script>alert(1)" not in html
    assert render_html(None).count("/*BINWALKER_DATA*/null") == 1


def test_cli_sample_inspect_analyze_and_fail_on(tmp_path):
    bin_path = tmp_path / "sample.elf"
    assert main(["sample", "--name", "elf64-beacon", "-o", str(bin_path)]) == 0
    assert bin_path.exists()

    assert main(["inspect", str(bin_path)]) == 0

    html_out = tmp_path / "r.html"
    md_out = tmp_path / "r.md"
    json_out = tmp_path / "r.json"
    code = main(
        ["analyze", str(bin_path), "-o", str(html_out), "--md", str(md_out), "--json", str(json_out)]
    )
    assert code == 0
    assert html_out.stat().st_size > 0 and md_out.stat().st_size > 0
    parsed = json.loads(json_out.read_text())
    assert parsed["header"]["format"] == "elf"

    assert main(["analyze", str(bin_path), "--fail-on", "1.0"]) == 1
    assert main(["analyze", str(bin_path), "--fail-on", "10.0"]) in (0, 1)

    bad_file = tmp_path / "not_a_bin.txt"
    bad_file.write_text("hello world")
    assert main(["analyze", str(bad_file)]) == 2


def test_storage_roundtrip(tmp_path):
    store = Storage(tmp_path / "bw.db")
    res = analyze_bytes(build_sample_elf64(), "beacon.elf")
    aid1 = store.save(res)
    aid2 = store.save(res)
    assert store.get(aid1)["file"]["sha256"] == res["file"]["sha256"]
    assert [row["id"] for row in store.list()] == [aid2, aid1]
    assert store.delete(aid1) is True and store.delete(aid1) is False
    assert store.get(aid1) is None
