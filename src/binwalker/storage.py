"""SQLite persistence for binary analyses (stdlib only, PostgreSQL-ready interface)."""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    format TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    score REAL NOT NULL,
    result TEXT NOT NULL
)
"""


class Storage:
    def __init__(self, path: str | Path = "binwalker.db"):
        self.path = str(path)
        with self._connect() as conn:
            conn.execute(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    def save(self, result: dict) -> str:
        analysis_id = uuid.uuid4().hex[:12]
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT INTO analyses (id, filename, format, sha256, created_at, score, result) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    analysis_id,
                    result["file"]["name"],
                    result["header"]["format"],
                    result["file"]["sha256"],
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    result["summary"]["score"],
                    json.dumps(result),
                ),
            )
        return analysis_id

    def get(self, analysis_id: str) -> dict | None:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT result FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, limit: int = 50) -> list[dict]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT id, filename, format, sha256, created_at, score "
                "FROM analyses ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r[0],
                "filename": r[1],
                "format": r[2],
                "sha256": r[3],
                "created_at": r[4],
                "score": r[5],
            }
            for r in rows
        ]

    def delete(self, analysis_id: str) -> bool:
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
        return cursor.rowcount > 0
