# Phase 4: Local Storage Layer

## Goal

Persist scan results in a local SQLite database so history survives terminal sessions.

## What You Learn In Phase 4

- why local persistence matters before API and dashboard layers
- how to design a minimal, migration-friendly SQLite schema
- how to store both summary fields and full scan JSON
- how to expose history via CLI commands for later reuse

## New Storage Features

- SQLite database initialization and schema management
- `scan_runs` table for top-level scan metadata
- `findings` table for suspicious finding rows
- indexed history fields for listing and filtering later
- schema version tracking

## New CLI Behavior

### Scan command persistence

`scan` now saves to SQLite by default.

Use custom DB path:

```bash
./scripts/fwb scan samples/demo-firmware.bin --db reports/generated/my_scans.sqlite3
```

Disable saving for one run:

```bash
./scripts/fwb scan samples/demo-firmware.bin --no-save
```

### History commands

List recent scans:

```bash
./scripts/fwb history list --db reports/generated/fwb_scans.sqlite3
```

Show one saved scan:

```bash
./scripts/fwb history show 1 --db reports/generated/fwb_scans.sqlite3
```

JSON output:

```bash
./scripts/fwb history list --json
./scripts/fwb history show 1 --json
```

## Verification

```bash
python3 -m unittest discover -s tests -v
```

Phase 4 is complete when scan persistence works, history listing works, scan fetch-by-id works, and tests cover the new storage layer.
