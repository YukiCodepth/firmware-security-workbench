from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path("reports/generated/fwb_scans.sqlite3")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL,
    updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at_utc TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_extension TEXT,
    file_size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    type_guess TEXT NOT NULL,
    architecture_hint TEXT,
    entropy REAL NOT NULL,
    strings_count INTEGER NOT NULL,
    suspicious_count INTEGER NOT NULL,
    result_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_runs_sha256 ON scan_runs(sha256);
CREATE INDEX IF NOT EXISTS idx_scan_runs_scanned_at ON scan_runs(scanned_at_utc DESC);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    offset INTEGER,
    offset_hex TEXT,
    keywords_json TEXT NOT NULL,
    snippet TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scan_runs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
"""


def _connect(db_path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> Path:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    now_utc = datetime.now(timezone.utc).isoformat()

    with _connect(path) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            """
            INSERT INTO schema_version (id, version, updated_at_utc)
            VALUES (1, 1, ?)
            ON CONFLICT(id) DO UPDATE SET
                version = excluded.version,
                updated_at_utc = excluded.updated_at_utc
            """,
            (now_utc,),
        )
    return path


def save_scan_result(result: dict[str, Any], db_path: str | Path = DEFAULT_DB_PATH) -> int:
    path = init_db(db_path)

    file_info = result.get("file", {})
    analysis = result.get("analysis", {})
    scanner_info = result.get("scanner", {})
    findings = analysis.get("suspicious_findings", [])

    if not isinstance(file_info, dict) or not isinstance(analysis, dict):
        raise ValueError("Invalid scan result shape: missing file or analysis object.")

    scanned_at_utc = scanner_info.get("scanned_at_utc")
    if not isinstance(scanned_at_utc, str):
        scanned_at_utc = datetime.now(timezone.utc).isoformat()

    with _connect(path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO scan_runs (
                scanned_at_utc,
                file_path,
                file_name,
                file_extension,
                file_size_bytes,
                sha256,
                type_guess,
                architecture_hint,
                entropy,
                strings_count,
                suspicious_count,
                result_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scanned_at_utc,
                str(file_info.get("path", "")),
                str(file_info.get("name", "")),
                file_info.get("extension"),
                int(file_info.get("size_bytes", 0)),
                str(file_info.get("sha256", "")),
                str(file_info.get("type_guess", "Unknown")),
                file_info.get("architecture_hint"),
                float(analysis.get("entropy", 0.0)),
                int(analysis.get("strings_count", 0)),
                int(analysis.get("suspicious_count", 0)),
                json.dumps(result),
            ),
        )
        scan_id = int(cursor.lastrowid)

        if isinstance(findings, list):
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                keywords = finding.get("keywords", [])
                if not isinstance(keywords, list):
                    keywords = []

                conn.execute(
                    """
                    INSERT INTO findings (
                        scan_id,
                        severity,
                        confidence,
                        offset,
                        offset_hex,
                        keywords_json,
                        snippet
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        str(finding.get("severity", "info")),
                        str(finding.get("confidence", "low")),
                        finding.get("offset"),
                        finding.get("offset_hex"),
                        json.dumps(keywords),
                        str(finding.get("string", "")),
                    ),
                )

    return scan_id


def list_scans(db_path: str | Path = DEFAULT_DB_PATH, limit: int = 20) -> list[dict[str, Any]]:
    path = init_db(db_path)
    safe_limit = max(1, min(limit, 1000))

    with _connect(path) as conn:
        rows = conn.execute(
            """
            SELECT
                id,
                scanned_at_utc,
                file_name,
                file_extension,
                file_size_bytes,
                sha256,
                type_guess,
                architecture_hint,
                entropy,
                strings_count,
                suspicious_count
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_scan_record(scan_id: int, db_path: str | Path = DEFAULT_DB_PATH) -> dict[str, Any]:
    path = init_db(db_path)
    with _connect(path) as conn:
        row = conn.execute(
            """
            SELECT id, scanned_at_utc, result_json
            FROM scan_runs
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()

    if row is None:
        raise KeyError(f"Scan id {scan_id} was not found.")

    result = json.loads(row["result_json"])
    return {
        "scan_id": row["id"],
        "scanned_at_utc": row["scanned_at_utc"],
        "result": result,
    }
