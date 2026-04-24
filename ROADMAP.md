# Firmware Security Workbench Roadmap

This roadmap tracks Firmware Security Workbench from project foundation to a stable `v1.0.0` open-source release.

The roadmap is product-first: build a useful CLI, then a local API, then a dashboard, then deeper security intelligence. The project should stay practical, teachable, and defensively focused while still becoming strong enough for a serious portfolio or open-source showcase.

## Release Strategy

We will not create a GitHub Release after every phase. Releases happen only at meaningful milestones where users can try a clear capability.

| Release | Name | Main Capability | Release Moment |
| --- | --- | --- | --- |
| `v0.1.0` | CLI Scanner Preview | First useful command-line scanner | After Phase 2 |
| `v0.2.0` | Firmware Metadata + Format Detection | Better metadata and firmware type support | After Phase 3 |
| `v0.3.0` | Local Scan History + API | SQLite storage and FastAPI upload/scan API | After Phase 5 |
| `v0.4.0` | Web Dashboard Alpha | Local dashboard for upload and scan summaries | After Phase 6 |
| `v0.5.0` | Security Detection MVP | Secrets, suspicious strings, and MVP workflow | After Phase 7 |
| `v0.6.0` | YARA + Rules Engine | Custom rules and built-in firmware checks | After Phase 8 |
| `v0.7.0` | SBOM + CVE Candidate Engine | Component inventory and vulnerability candidates | After Phase 10 |
| `v0.8.0` | Firmware Diff + Risk DNA Beta | Version risk diffing and behavior fingerprinting | After Phase 12 |
| `v0.9.0` | Reports + Packaging RC | Reports, Docker, CI, and release candidate polish | After Phase 15 |
| `v1.0.0` | Stable Open-Source Release | Complete polished release | After Phase 16 |
| `v1.1.0` | Hardening Simulator Innovation | What-if remediation planning with projected risk reduction | After Phase 17 |
| `v1.2.0` | Desktop App Alpha | Native shell foundation for macOS, Windows, and Linux | After Phase 18 |
| `v1.3.0` | Next-Gen Desktop Package Preview | Redesigned UI and first desktop package workflow | After Phase 19 |

Packages are not needed yet. Later we may publish a Docker image, a Python CLI package, and standalone binaries if the project is stable enough.

## Phase Overview

| Phase | Branch | Main Goal | Output | Release Impact |
| --- | --- | --- | --- | --- |
| 0 | `phase/00-project-foundation` | Create repo foundation | Docs, structure, workflow | No release |
| 1 | `phase/01-requirements-prior-art` | Define MVP and research existing tools | Requirements and prior-art notes | No release |
| 1b | `phase/01b-release-roadmap` | Add release-driven roadmap | Release plan and final roadmap docs | No release |
| 2 | `phase/02-cli-scanner-mvp` | Build first scanner | CLI scans one file and outputs JSON | `v0.1.0` |
| 3 | `phase/03-format-detection` | Detect firmware formats | `.bin`, `.elf`, `.hex`, `.uf2` metadata | `v0.2.0` |
| 4 | `phase/04-storage-layer` | Save scan history | SQLite database and schema | Included in `v0.3.0` |
| 5 | `phase/05-fastapi-backend` | Add API | Upload and scan endpoints | `v0.3.0` |
| 6 | `phase/06-web-dashboard` | Add web UI | Upload page and scan result dashboard | `v0.4.0` |
| 7 | `phase/07-secrets-scanner` | Detect embedded secrets | Credentials, keys, URLs, tokens | `v0.5.0` |
| 8 | `phase/08-yara-engine` | Add rule engine | YARA matching and custom rules | `v0.6.0` |
| 9 | `phase/09-sbom-generator` | Generate component inventory | Basic CycloneDX-style SBOM | Included in `v0.7.0` |
| 10 | `phase/10-cve-risk-engine` | Match possible vulnerabilities | CVE candidates with confidence | `v0.7.0` |
| 11 | `phase/11-firmware-diff` | Compare firmware versions | Risk delta between old and new firmware | Included in `v0.8.0` |
| 12 | `phase/12-risk-dna` | Add behavior fingerprint | Firmware Risk DNA profile | `v0.8.0` |
| 13 | `phase/13-report-exporter` | Export reports | HTML, Markdown, JSON reports | Included in `v0.9.0` |
| 14 | `phase/14-sample-corpus` | Add demo firmware corpus | Safe test firmware samples | Included in `v0.9.0` |
| 15 | `phase/15-packaging-ci` | Package and automate | Docker and GitHub Actions | `v0.9.0` |
| 16 | `phase/16-final-showcase` | Polish release | Screenshots, demo, docs, `v1.0.0` tag | `v1.0.0` |
| 17 | `phase/17-hardening-simulator` | Add unique hardening simulation | Prioritized mitigation actions + what-if scenarios | `v1.1.0` |
| 18 | `phase/18-desktop-app-shell` | Start desktop app | Tauri-ready shell and polished desktop UI | `v1.2.0` alpha |
| 19 | `phase/19-nextgen-ui-packaging` | Upgrade UI and package workflow | Next-gen dashboard, desktop shell polish, cross-OS GitHub packaging | `v1.3.0` preview |

## Build Philosophy

- Build a working CLI before building a UI.
- Build local-first features before cloud or SaaS ideas.
- Keep evidence separate from interpretation.
- Use confidence levels for uncertain findings.
- Prefer useful developer reports over noisy raw output.
- Keep offensive features out of scope.
- Add advanced integrations only after the MVP works.

## MVP Definition

The minimum useful product is complete after Phase 7 and release `v0.5.0`.

The MVP includes:

- scan firmware from CLI
- upload firmware from API or web UI
- extract metadata, hashes, strings, entropy
- detect suspicious strings and likely secrets
- save scan history locally
- produce structured JSON output
- show scan summaries in the dashboard

Everything after Phase 7 makes the project more powerful, more open-source ready, and more innovative.

## Advanced Feature Direction

After the MVP, the project moves into deeper firmware security intelligence:

- YARA rules for firmware artifacts
- CycloneDX SBOM export
- possible CVE matching with confidence levels
- firmware version diffing
- Firmware Risk DNA behavior profiling
- optional Binwalk integration for extraction
- optional Ghidra headless integration for deeper binary metadata
- optional Linux and embedded device profile templates
- optional sample vulnerable firmware for ESP32, STM32, Arduino, and Pico-style demos

## Phase Completion Rule

A phase is complete only when:

- the feature or document goal is finished
- tests or manual verification have been run
- the phase branch has a clean commit history
- the phase branch has been pushed when a GitHub remote exists
- the phase branch is merged into `main`
- `main` remains runnable or at least clean

## Recommended Startup/Product Timeline

- Weeks 1-2: project foundation, requirements, roadmap, CLI scanner
- Weeks 3-4: format detection, storage, API
- Weeks 5-6: web dashboard alpha
- Weeks 7-8: secrets scanner and security detection MVP
- Weeks 9-10: YARA, SBOM, possible CVE matching
- Weeks 11-12: firmware diffing and Firmware Risk DNA
- Weeks 13-14: reports, sample corpus, packaging, CI
- Week 15: final showcase and `v1.0.0`
- Week 16: buffer, bug fixes, demo video, final presentation

## Current Build Focus

Current roadmap phase: `Phase 19 - Next-Gen UI + Desktop Packaging`

Next implementation phase: `Phase 20 - Native Desktop Workflows`
