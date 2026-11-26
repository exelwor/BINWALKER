import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from binwalker.api import create_app  # noqa: E402
from binwalker.samples import build_sample_pe64  # noqa: E402


def client(tmp_path):
    return TestClient(create_app(str(tmp_path / "api.db")))


def test_health_index_and_samples(tmp_path):
    c = client(tmp_path)
    assert c.get("/api/health").json()["status"] == "ok"
    assert "BINWALKER" in c.get("/").text
    samples = c.get("/api/samples").json()
    assert len(samples) == 3
    res = c.post(f"/api/samples/{samples[0]['id']}/analyze")
    assert res.status_code == 200
    assert res.json()["id"]


def test_upload_analyze_reports_and_delete(tmp_path):
    c = client(tmp_path)
    resp = c.post(
        "/api/analyze",
        files={"file": ("agent.exe", build_sample_pe64(), "application/octet-stream")},
    )
    assert resp.status_code == 200
    body = resp.json()
    aid = body["id"]
    assert body["header"]["format"] == "pe"
    assert c.get(f"/api/analyses/{aid}").json()["file"]["name"] == "agent.exe"
    assert c.get("/api/analyses").json()[0]["id"] == aid
    assert "BINWALKER" in c.get(f"/api/analyses/{aid}/report.html").text
    assert c.get(f"/api/analyses/{aid}/report.md").text.startswith("# BINWALKER static report")
    assert c.delete(f"/api/analyses/{aid}").status_code == 204
    assert c.get(f"/api/analyses/{aid}").status_code == 404


def test_invalid_binary_upload_returns_422(tmp_path):
    c = client(tmp_path)
    resp = c.post(
        "/api/analyze",
        files={"file": ("bad.bin", b"not-an-executable", "application/octet-stream")},
    )
    assert resp.status_code == 422
    assert "error" in resp.json()["detail"]
