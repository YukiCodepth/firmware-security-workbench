# Prior-Art Research

This document tracks existing tools, standards, and data sources related to Firmware Security Workbench.

Research date: 2026-04-22

## Why We Do Prior-Art Research

Prior-art research helps us avoid weak claims like "nothing like this exists."

The firmware security ecosystem already has strong tools. Our goal is to learn from them and make a focused, learner-friendly, local-first workbench with clear evidence reporting and risk-diff features.

## Existing Tools And Standards

### Binwalk

Source: https://github.com/ReFirmLabs/binwalk

Binwalk is a firmware analysis tool focused on identifying and extracting embedded files and data. The current Binwalk project describes version 3 as a Rust rewrite focused on speed and accuracy. It also supports entropy analysis to help identify unknown compression or encryption.

What it does well:

- embedded file identification
- extraction
- entropy analysis
- fast command-line workflow

What our project should not copy blindly:

- we should not try to become a better extractor in the MVP
- we can integrate with or learn from Binwalk later

Our gap:

- clearer beginner workflow after extraction
- evidence interpretation
- risk summaries and reports

### Firmwalker

Source: https://github.com/craigz28/firmwalker

Firmwalker is a Bash script that searches extracted or mounted firmware filesystems for interesting artifacts such as password files, SSL files, configuration files, scripts, binaries, keywords, URLs, emails, and IP addresses.

What it does well:

- simple filesystem reconnaissance
- quick checks for common IoT firmware artifacts
- easy to understand

What our project should not copy blindly:

- we should not be only a keyword-search shell script

Our gap:

- structured JSON findings
- confidence scoring
- web dashboard
- firmware diffing
- risk profile generation

### EMBA

Source: https://github.com/e-m-b-a/emba

EMBA is a large firmware security analyzer for embedded devices. It supports extraction, static analysis, dynamic analysis through emulation, SBOM generation, and web-based vulnerability reports.

What it does well:

- broad firmware analysis coverage
- SBOM support
- web reports
- static and dynamic analysis
- mature security workflow

What our project should not copy blindly:

- trying to match EMBA feature-for-feature would be too large for this project

Our gap:

- lighter local-first learning path
- smaller modular codebase
- evidence-first explanations for beginners
- firmware risk delta and Risk DNA as first-class concepts

### FACT

Sources:

- https://github.com/fkie-cad/FACT_core
- https://fkie-cad.github.io/FACT_core/

FACT, the Firmware Analysis and Comparison Tool, automates firmware analysis, provides a web UI, supports search and comparison, and offers a REST-like API. It is designed as a multiprocess application and can require significant CPU, RAM, and disk resources.

What it does well:

- firmware unpacking and analysis
- web interface
- REST API
- comparison features
- plugin-oriented workflow

What our project should not copy blindly:

- complex heavyweight infrastructure

Our gap:

- smaller beginner-friendly setup
- lower resource needs
- security education docs built into the project
- explicit confidence and evidence model

### Ghidra

Source: https://www.nsa.gov/serve-from-netstorage/ghidra/index.html

Ghidra is a software reverse engineering framework from the NSA. It supports disassembly, decompilation, graphing, scripting, many processor instruction sets, many executable formats, and interactive or automated analysis.

What it does well:

- deep reverse engineering
- decompilation
- scripting
- architecture support

What our project should not copy blindly:

- we should not try to replace a reverse engineering suite

Our gap:

- provide triage before deep Ghidra analysis
- produce reports that tell a developer what to inspect manually

### YARA

Sources:

- https://yara.readthedocs.io/en/latest/writingrules.html
- https://docs.virustotal.com/docs/what-is-yara

YARA is a pattern-matching rule system often used by malware researchers. Rules can match textual and binary patterns and can be used from the CLI or Python.

What it does well:

- reusable detection rules
- text and binary patterns
- malware and artifact classification

How we should use it:

- add YARA as an extensible detection layer
- keep project-specific firmware rules under `rules/yara/`

### CycloneDX

Sources:

- https://cyclonedx.org/
- https://github.com/CycloneDX/specification

CycloneDX is an international Bill of Materials standard. It supports SBOM and other bill-of-materials formats such as HBOM, CBOM, and VEX-related use cases.

What it does well:

- machine-readable component inventory
- supply-chain security use cases
- standardized output

How we should use it:

- export SBOM-style data after component discovery exists
- start with simple JSON, then map to CycloneDX later

### SPDX

Source: https://spdx.dev/about/overview/

SPDX is an open standard for communicating software bill of material information, including provenance, license, security, and related data. It is recognized as ISO/IEC 5962:2021.

How we should use it:

- consider SPDX export after CycloneDX support
- understand license and provenance fields for future reports

### NVD

Sources:

- https://www.nist.gov/itl/nvd
- https://www.nist.gov/programs-projects/national-vulnerability-database-nvd

The National Vulnerability Database is the U.S. government repository of standards-based vulnerability management data. NVD data supports vulnerability management, measurement, and compliance.

How we should use it:

- match possible vulnerabilities only when component evidence is strong
- avoid claiming confirmed vulnerabilities from weak version strings

### OSV

Source: https://osv.dev/

OSV is an open vulnerability database for open-source packages. It provides an API for querying vulnerabilities by package version or commit hash.

How we should use it:

- later use OSV for package ecosystems where firmware components can be identified confidently

### OWASP IoT Security Testing Guide

Sources:

- https://owasp.org/owasp-istg/03_test_cases/firmware/
- https://owasp.org/owasp-istg/03_test_cases/firmware/firmware_update_mechanism.html

OWASP's IoT firmware guidance includes important categories such as hardcoded secrets, unnecessary software, and insecure firmware update mechanisms.

How we should use it:

- align finding categories with recognized firmware security concerns
- keep the project defensive and methodology-based

## Key Competitive Insight

Existing tools already cover many core capabilities:

- extraction
- filesystem scanning
- web reports
- reverse engineering
- vulnerability lookup
- SBOM generation
- firmware comparison

So our unique value should not be "we scan firmware." That is already available.

Our unique value should be:

- teachable workflow
- lower setup friction
- evidence-first result model
- confidence-aware findings
- risk summaries written for developers
- firmware diff focused on newly introduced risk
- Firmware Risk DNA profile

## Innovation Claim We Can Defend

Safer claim:

> Firmware Security Workbench is a learner-friendly, local-first firmware analysis workbench that combines basic static analysis, evidence-backed findings, confidence scoring, firmware risk diffing, and a behavior-style Firmware Risk DNA profile.

Claims to avoid:

- "No one has built a firmware scanner before."
- "This detects all firmware vulnerabilities."
- "This confirms CVEs automatically."
- "This replaces Binwalk, EMBA, FACT, or Ghidra."

## Design Lessons From Prior Art

- Use structured output from the beginning.
- Keep the CLI useful before building the web UI.
- Separate evidence from interpretation.
- Make false positives visible instead of hiding them.
- Keep heavy features like emulation out of the MVP.
- Use standards like CycloneDX only when we have enough evidence.
- Prefer confidence levels over absolute claims.

## Future Integration Possibilities

Possible future integrations:

- Binwalk for extraction
- YARA for rule matching
- Ghidra headless for deep binary metadata
- CycloneDX for SBOM export
- OSV and NVD for vulnerability candidates
- OWASP ISTG categories for finding taxonomy
