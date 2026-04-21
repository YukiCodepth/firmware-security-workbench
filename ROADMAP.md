# Firmware Security Workbench Roadmap

This roadmap tracks the complete project from empty repository to a polished `v1.0` open-source release.

## Phase Overview

| Phase | Branch | Main Goal | Output |
| --- | --- | --- | --- |
| 0 | `phase/00-project-foundation` | Create repo foundation | Docs, structure, workflow |
| 1 | `phase/01-requirements-prior-art` | Define MVP and research existing tools | Product requirements and prior-art notes |
| 2 | `phase/02-cli-scanner-mvp` | Build first scanner | CLI scans one file and outputs JSON |
| 3 | `phase/03-format-detection` | Detect firmware formats | `.bin`, `.elf`, `.hex`, `.uf2` metadata |
| 4 | `phase/04-storage-layer` | Save scan history | SQLite database and schema |
| 5 | `phase/05-fastapi-backend` | Add API | Upload and scan endpoints |
| 6 | `phase/06-web-dashboard` | Add web UI | Upload page and scan result dashboard |
| 7 | `phase/07-secrets-scanner` | Detect embedded secrets | Credentials, keys, URLs, tokens |
| 8 | `phase/08-yara-engine` | Add rule engine | YARA matching and custom rules |
| 9 | `phase/09-sbom-generator` | Generate component inventory | Basic CycloneDX-style SBOM |
| 10 | `phase/10-cve-risk-engine` | Match possible vulnerabilities | CVE candidates with confidence |
| 11 | `phase/11-firmware-diff` | Compare firmware versions | Risk delta between old and new firmware |
| 12 | `phase/12-risk-dna` | Add behavior fingerprint | Firmware Risk DNA profile |
| 13 | `phase/13-report-exporter` | Export reports | HTML, Markdown, JSON reports |
| 14 | `phase/14-sample-corpus` | Add demo firmware corpus | Safe test firmware samples |
| 15 | `phase/15-packaging-ci` | Package and automate | Docker and GitHub Actions |
| 16 | `phase/16-final-showcase` | Polish release | Screenshots, demo, `v1.0` tag |

## Phase Completion Rule

A phase is complete only when:

- the feature or document goal is finished
- tests or manual verification have been run
- the phase branch has a clean commit history
- the phase branch has been pushed when a GitHub remote exists
- the phase branch is merged into `main`
- `main` remains runnable or at least clean

## Recommended Semester Timeline

- Weeks 1-2: Phases 0-2
- Weeks 3-4: Phases 3-5
- Weeks 5-6: Phase 6
- Weeks 7-8: Phases 7-8
- Weeks 9-10: Phases 9-10
- Weeks 11-12: Phases 11-12
- Weeks 13-14: Phases 13-15
- Week 15: Phase 16
- Week 16: buffer, bug fixes, presentation, final report

## MVP Definition

The minimum useful version is complete after Phase 7:

- scan firmware from CLI
- upload firmware from API or web UI
- extract metadata, hashes, strings, entropy
- detect suspicious strings and secrets
- save scan history
- produce structured JSON output

Everything after that makes the project stronger, more innovative, and more showcase-ready.
