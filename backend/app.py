from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from cli.scanner import ScanError, scan_firmware
from cli.storage import DEFAULT_DB_PATH, get_scan_record, list_scans, save_scan_result


def _db_path_from_param(db_path: str | None) -> Path:
    if db_path is None or not db_path.strip():
        return DEFAULT_DB_PATH
    return Path(db_path)


def _scan_uploaded_file(
    uploaded_file: UploadFile,
    *,
    min_string_length: int,
    max_strings: int,
) -> dict[str, object]:
    suffix = Path(uploaded_file.filename or "upload.bin").suffix or ".bin"
    temp_path = None

    try:
        payload = uploaded_file.file.read()
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_file:
            temp_file.write(payload)
            temp_path = Path(temp_file.name)
        result = scan_firmware(
            temp_path,
            min_string_length=min_string_length,
            max_strings=max_strings,
        )
    except ScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)
        uploaded_file.file.close()

    if isinstance(result.get("file"), dict):
        result["file"]["name"] = uploaded_file.filename or result["file"].get("name")
    return result


app = FastAPI(
    title="Firmware Security Workbench API",
    version="0.3.0-dev",
    description="Local API for firmware scanning and scan history",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "fwb-api", "version": "0.3.0-dev"}


@app.post("/api/v1/scans")
def create_scan(
    file: UploadFile = File(...),
    min_string_length: int = Form(4),
    max_strings: int = Form(2000),
    save: bool = Form(True),
    db_path: str | None = Form(None),
) -> dict[str, object]:
    if min_string_length < 2:
        raise HTTPException(status_code=400, detail="min_string_length must be >= 2")
    if max_strings < 1:
        raise HTTPException(status_code=400, detail="max_strings must be >= 1")

    result = _scan_uploaded_file(
        file,
        min_string_length=min_string_length,
        max_strings=max_strings,
    )
    target_db = _db_path_from_param(db_path)

    if save:
        scan_id = save_scan_result(result, db_path=target_db)
        result["storage"] = {
            "saved": True,
            "scan_id": scan_id,
            "database_path": str(target_db.resolve()),
        }
    else:
        result["storage"] = {
            "saved": False,
            "scan_id": None,
            "database_path": str(target_db.resolve()),
        }

    return result


@app.get("/api/v1/scans")
def get_scans(limit: int = 20, db_path: str | None = None) -> dict[str, object]:
    target_db = _db_path_from_param(db_path)
    scans = list_scans(db_path=target_db, limit=limit)
    return {
        "count": len(scans),
        "database_path": str(target_db.resolve()),
        "scans": scans,
    }


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: int, db_path: str | None = None) -> dict[str, object]:
    target_db = _db_path_from_param(db_path)
    try:
        record = get_scan_record(scan_id=scan_id, db_path=target_db)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    record["database_path"] = str(target_db.resolve())
    return record
