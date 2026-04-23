# Phase 5: FastAPI Backend

## Goal

Expose scanner and history features through a local API.

## What You Learn In Phase 5

- how to wrap existing CLI logic into HTTP endpoints
- how to handle uploaded firmware files safely
- how to reuse SQLite storage from API code
- how to test API behavior without a running server process

## API Endpoints

Health:

```http
GET /health
```

Create scan from file upload:

```http
POST /api/v1/scans
```

Form fields:

- `file` (required)
- `min_string_length` (optional, default `4`)
- `max_strings` (optional, default `2000`)
- `save` (optional, default `true`)
- `db_path` (optional)

List scans:

```http
GET /api/v1/scans?limit=20&db_path=...
```

Show one scan:

```http
GET /api/v1/scans/{scan_id}?db_path=...
```

## Run Backend

```bash
uvicorn backend.app:app --reload --port 8000
```

Open API docs:

```text
http://127.0.0.1:8000/docs
```

## Verification

```bash
python3 -m unittest discover -s tests -v
```

Phase 5 is complete when API scan creation, history listing, and scan fetch-by-id all work with tests passing.
