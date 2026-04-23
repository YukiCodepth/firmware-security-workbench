# Final Project Roadmap

This document describes the full end-to-end project path for Firmware Security Workbench.

The roadmap is intentionally ambitious but staged. The project should become useful early, then grow into deeper security intelligence and open-source polish.

## Phase 0: Project Foundation

Branch: `phase/00-project-foundation`

Goal: create a professional repository foundation.

Completed outputs:

- Git repository
- `main` branch
- phase branch workflow
- README
- roadmap
- license
- contribution guide
- security policy
- project folders

Why it matters:

- creates a clean base for every future phase
- makes the project look professional from the beginning
- teaches disciplined Git workflow

## Phase 1: Requirements + Prior-Art Research

Branch: `phase/01-requirements-prior-art`

Goal: define what the tool should do and how it differs from existing tools.

Completed outputs:

- product requirements
- MVP scope
- threat model
- prior-art research
- safe innovation claims

Why it matters:

- prevents random feature building
- avoids weak claims like "nothing like this exists"
- defines the defensive security boundary

## Phase 1b: Release-Driven Roadmap

Branch: `phase/01b-release-roadmap`

Goal: add a product-style release strategy before implementation begins.

Outputs:

- milestone release plan
- final roadmap
- package policy
- GitHub release guidance

Why it matters:

- makes GitHub releases understandable
- helps the project look like a real open-source product
- keeps Phase 2 focused on implementation

## Phase 2: CLI Scanner MVP

Branch: `phase/02-cli-scanner-mvp`

Release: `v0.1.0`

Goal: build the first usable scanner from the terminal.

Features:

- `fwb scan <firmware-file>`
- file size
- SHA256 hash
- basic MIME/type guess
- entropy calculation
- printable strings extraction
- suspicious keyword matching
- JSON output
- terminal summary

Learning topics:

- Python CLI tools
- binary file reading
- hashing
- entropy
- JSON output
- simple tests

## Phase 3: Firmware Metadata + Format Detection

Branch: `phase/03-format-detection`

Release: `v0.2.0`

Goal: understand common firmware file formats.

Features:

- raw `.bin` support
- ELF metadata support
- Intel HEX parser
- UF2 parser if feasible
- section and symbol summaries for ELF files
- architecture and address hints when evidence exists

Learning topics:

- firmware formats
- ELF sections
- memory addresses
- embedded binary layout

## Phase 4: Local Storage Layer

Branch: `phase/04-storage-layer`

Goal: save scan history locally.

Features:

- SQLite database
- scan records
- finding records
- file metadata records
- local report references
- migration-friendly schema

Learning topics:

- SQL
- database design
- scan result modeling
- local-first product design

## Phase 5: FastAPI Backend

Branch: `phase/05-fastapi-backend`

Release: `v0.3.0`

Goal: expose the scanner through a local API.

Features:

- firmware upload endpoint
- scan endpoint
- scan history endpoint
- scan detail endpoint
- JSON error responses
- local file handling rules

Learning topics:

- HTTP
- REST APIs
- FastAPI
- file upload security
- backend structure

## Phase 6: Web Dashboard Alpha

Branch: `phase/06-web-dashboard`

Release: `v0.4.0`

Goal: make the project usable from a browser.

Features:

- firmware upload page
- scan history page
- scan result summary
- severity cards
- finding table
- metadata view
- clean local dashboard UI

Learning topics:

- frontend basics
- dashboard UX
- API integration
- security report presentation

## Phase 7: Security Detection MVP

Branch: `phase/07-secrets-scanner`

Release: `v0.5.0`

Goal: complete the first product-quality security milestone.

Features:

- likely password detection
- private key marker detection
- certificate detection
- token-looking string detection
- URL, IP, email, MQTT, and OTA endpoint detection
- debug string detection
- severity and confidence scoring
- false-positive-aware finding model

Learning topics:

- regex
- secret scanning
- confidence scoring
- evidence vs interpretation
- safe security reporting

## Phase 8: YARA + Rules Engine

Branch: `phase/08-yara-engine`

Release: `v0.6.0`

Goal: make detection extensible.

Features:

- YARA rule loading
- built-in firmware rule pack
- custom user rules under `rules/yara/`
- rule metadata in findings
- safe rule failure handling

Learning topics:

- YARA syntax
- pattern matching
- malware-analysis-style rules
- detection engineering

## Phase 9: SBOM Generator

Branch: `phase/09-sbom-generator`

Goal: create a component inventory from firmware evidence.

Features:

- component candidates from strings and symbols
- version pattern detection
- confidence levels for component matches
- CycloneDX-style JSON export
- clear "candidate, not confirmed" language

Learning topics:

- SBOM
- CycloneDX
- component fingerprinting
- supply-chain security

## Phase 10: CVE Candidate Engine

Branch: `phase/10-cve-risk-engine`

Release: `v0.7.0`

Goal: map component candidates to possible vulnerabilities.

Features:

- local vulnerability data abstraction
- possible CVE candidates
- CVSS display when available
- confidence-aware matching
- manual review warnings
- no unsupported "confirmed vulnerable" claims

Learning topics:

- CVE
- CVSS
- CPE
- OSV
- vulnerability triage

## Phase 11: Firmware Diff Intelligence

Branch: `phase/11-firmware-diff`

Goal: compare two firmware versions.

Features:

- `fwb diff old.bin new.bin`
- added and removed strings
- added and removed secrets
- changed metadata
- changed components
- newly introduced risk summary
- removed risk summary

Learning topics:

- diff algorithms
- regression analysis
- release security review

## Phase 12: Firmware Risk DNA

Branch: `phase/12-risk-dna`

Release: `v0.8.0`

Goal: build the signature project feature.

Features:

- behavior-style firmware fingerprint
- networking behavior score
- OTA behavior score
- credential exposure score
- debug leftover score
- crypto usage score
- component risk score
- risk delta summary across versions

Learning topics:

- evidence aggregation
- behavior profiling
- scoring systems
- product differentiation

## Phase 13: Report Exporter

Branch: `phase/13-report-exporter`

Goal: generate professional reports.

Features:

- JSON report
- Markdown report
- HTML report
- executive summary
- technical finding details
- evidence offsets
- remediation guidance

Learning topics:

- security reporting
- template rendering
- developer communication

## Phase 14: Sample Firmware Corpus

Branch: `phase/14-sample-corpus`

Goal: make the project demo-friendly and testable.

Features:

- safe sample firmware-like binaries
- fake secrets for detection demos
- firmware version pairs for diff demos
- optional ESP32, STM32, Arduino, and Pico-style sample builds
- documentation for safe samples

Learning topics:

- test fixtures
- embedded demo firmware
- reproducible security demos

## Phase 15: Packaging + CI

Branch: `phase/15-packaging-ci`

Release: `v0.9.0`

Goal: prepare the project for real users.

Features:

- Dockerfile
- Docker Compose setup
- GitHub Actions tests
- linting/check workflow
- install documentation
- release candidate checklist

Learning topics:

- Docker
- CI
- reproducible setup
- open-source release engineering

## Phase 16: Final Showcase

Branch: `phase/16-final-showcase`

Release: `v1.0.0`

Goal: make the project polished and public-ready.

Features:

- polished README
- screenshots
- architecture diagram
- demo video script
- contribution guide improvements
- issue templates
- first stable GitHub Release
- final project presentation

Learning topics:

- project storytelling
- open-source maintenance
- release notes
- portfolio presentation

## Post-1.0 Ideas

These are optional future directions, not required for the first stable release:

- Binwalk integration for extraction
- Ghidra headless integration for deeper analysis
- Linux firmware package profile support
- embedded device profile templates
- plugin system for custom analyzers
- SARIF export for security tooling
- documentation website
- Docker image publishing
- Python package publishing
- standalone binary builds
- limited Edge AI-assisted finding triage if it can be done locally and safely

## Final Success Definition

The project is complete for `v1.0.0` when a user can:

- clone the repo
- run the CLI scanner
- upload firmware in the dashboard
- view understandable findings
- compare firmware versions
- export a report
- understand the evidence behind each risk
- extend detection rules
- follow docs without needing private help
