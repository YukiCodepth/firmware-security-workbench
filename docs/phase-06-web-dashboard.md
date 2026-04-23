# Phase 6: Web Dashboard Alpha

## Goal

Provide a usable browser dashboard on top of the existing API and storage layers.

## What You Learn In Phase 6

- how to bind a frontend directly to scan and history APIs
- how to design scan workflows for fast inspection
- how to serve static frontend files from FastAPI
- how to keep UI and API behavior aligned via tests

## Dashboard Route

Open:

```text
http://127.0.0.1:8000/dashboard
```

The dashboard is served by FastAPI and uses same-origin API calls.

## Dashboard Features

- firmware file upload and scan submission
- scan options:
  - minimum string length
  - max strings
  - save toggle
  - database path
- scan history table with selectable rows
- detail panel:
  - key metrics
  - top suspicious findings
  - strings preview
- controls for refreshing history and clearing detail

## API Integration Used

- `GET /health`
- `POST /api/v1/scans`
- `GET /api/v1/scans`
- `GET /api/v1/scans/{scan_id}`
- `GET /dashboard`

## Verification

```bash
python3 -m unittest discover -s tests -v
```

Phase 6 is complete when dashboard route renders, upload-to-scan works, history loads, and scan detail can be opened from the table.
