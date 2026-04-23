# Firmware Security Workbench

Firmware Security Workbench is an open-source firmware analysis platform for developers, security learners, and embedded engineers.

The goal is to upload or scan firmware images such as `.bin`, `.elf`, `.hex`, and `.uf2`, extract useful security evidence, detect risky artifacts, compare versions, and generate clear reports.

## Why This Exists

Firmware security tools are often either very advanced research tools or small command-line utilities. This project aims to sit in the middle:

- beginner-friendly enough to learn from
- practical enough for real firmware review
- modular enough for open-source contributors
- polished enough to showcase as a serious portfolio project

## Planned Capabilities

- CLI firmware scanner
- Local web dashboard
- Firmware metadata extraction
- Hashing and entropy analysis
- Strings and suspicious keyword detection
- Secret and credential detection
- YARA rule scanning
- SBOM-style component discovery
- Possible CVE matching with confidence levels
- Firmware version diffing
- Firmware Risk DNA profile
- HTML, Markdown, and JSON reports
- Sample vulnerable firmware corpus for demos

## Signature Feature: Firmware Risk DNA

Firmware Risk DNA will create a behavior-style risk fingerprint for a firmware image. Instead of only listing raw strings, it will summarize evidence into categories such as:

- networking behavior
- debug leftovers
- OTA update logic
- credential exposure
- cryptography usage
- risky service endpoints
- risk added or removed between versions

This feature is designed to make reports more useful to developers than a long unstructured list of findings.

## Repository Workflow

This project is built phase by phase.

- `main` is the stable branch.
- Each phase uses a branch named `phase/XX-short-name`.
- Work is committed to the phase branch first.
- At the end of the phase, the phase branch is merged back into `main`.

Example:

```bash
git checkout main
git checkout -b phase/02-cli-scanner-mvp
```

## Current Status

Current status: `Phase 6 - Web Dashboard Alpha`

The repo structure, product requirements, MVP boundaries, prior-art research, ethical scope, and release-driven roadmap are ready. The scanner now supports format-aware metadata, SQLite scan history, FastAPI endpoints, and a browser dashboard as part of `v0.4.0-dev`.

## Quick Start

Run the scanner:

```bash
./scripts/fwb scan samples/demo-firmware.bin
```

Run scanner without saving:

```bash
./scripts/fwb scan samples/demo-firmware.bin --no-save
```

Scan Intel HEX:

```bash
./scripts/fwb scan samples/demo-firmware.hex --json
```

Print full JSON output:

```bash
./scripts/fwb scan samples/demo-firmware.bin --json
```

Write JSON report to disk:

```bash
./scripts/fwb scan samples/demo-firmware.bin --out reports/generated/demo-scan.json
```

List saved scan history:

```bash
./scripts/fwb history list
```

Show one saved scan:

```bash
./scripts/fwb history show 1 --json
```

Run tests:

```bash
python3 -m unittest discover -s tests -v
```

Run API server:

```bash
uvicorn backend.app:app --reload --port 8000
```

API docs:

```text
http://127.0.0.1:8000/docs
```

Dashboard:

```text
http://127.0.0.1:8000/dashboard
```

## Safety Scope

This project is for defensive firmware analysis, developer education, and security auditing. It does not include exploit generation, unauthorized device access, credential abuse, or malware deployment.

## Repo Layout

```text
backend/          FastAPI backend
cli/              Command-line scanner
docs/             Project docs, architecture, learning notes
frontend/         Dashboard UI (Phase 6 alpha)
reports/          Report templates and generated report output
rules/            Detection rules, including YARA rules
samples/          Safe sample firmware and test fixtures
scripts/          Utility scripts
tests/            Automated tests
```
