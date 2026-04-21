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

Current status: `Phase 1 - Product Requirements + Prior-Art Research`

The repo structure is ready. Product requirements, MVP boundaries, prior-art research, and ethical scope are being defined before scanner code begins.

## Safety Scope

This project is for defensive firmware analysis, developer education, and security auditing. It does not include exploit generation, unauthorized device access, credential abuse, or malware deployment.

## Repo Layout

```text
backend/          Future FastAPI backend
cli/              Future command-line scanner
docs/             Project docs, architecture, learning notes
frontend/         Future web dashboard
reports/          Report templates and generated report output
rules/            Detection rules, including YARA rules
samples/          Safe sample firmware and test fixtures
scripts/          Utility scripts
tests/            Automated tests
```
