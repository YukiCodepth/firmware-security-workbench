# Product Requirements

## Product Name

Firmware Security Workbench

## Product Type

Local-first firmware security analysis workbench with a CLI first and web dashboard later.

## Target Users

- embedded developers reviewing firmware before release
- students learning firmware security
- cybersecurity learners practicing safe static analysis
- open-source contributors adding detection rules
- small teams needing lightweight firmware review without a heavy enterprise setup

## User Problems

### Problem 1: Firmware analysis has too many disconnected tools

A beginner may need to learn `file`, `strings`, `binwalk`, YARA, Ghidra, CVE databases, and SBOM standards before getting a useful report.

This project should connect the basic workflow into one understandable tool.

### Problem 2: Raw findings are hard to interpret

Many tools output raw strings, files, signatures, or logs. The user still needs to decide what matters.

This project should separate evidence from interpretation and explain why a finding may matter.

### Problem 3: Firmware version changes are security-relevant

Teams need to know what risk was added or removed between firmware versions.

This project should compare old and new firmware and summarize risk deltas.

### Problem 4: Beginners need an ethical and guided workflow

Firmware security can quickly drift into offensive behavior if the project scope is unclear.

This project should stay defensive and clearly explain safe usage.

## MVP Features

The MVP should include:

- scan one firmware file from the CLI
- calculate file size and cryptographic hashes
- detect basic file type
- calculate entropy
- extract printable strings
- flag suspicious keywords
- flag likely secrets and credentials
- produce structured JSON output
- store scan history locally
- expose scan results through an API
- show scan summaries in a local web dashboard

## Post-MVP Features

After the MVP works, add:

- YARA rule engine
- SBOM-style component discovery
- possible CVE matching
- firmware diffing
- Firmware Risk DNA
- HTML, Markdown, and PDF-style reports
- sample firmware corpus
- Docker packaging
- GitHub Actions CI

## Non-Goals For MVP

The MVP will not include:

- firmware extraction from physical devices
- JTAG, SWD, UART, or SPI dumping
- exploit generation
- automated vulnerability confirmation
- firmware emulation
- malware execution
- cloud scanning
- multi-user authentication
- SaaS billing

## Safety Requirements

The tool must:

- analyze only files provided by the user
- avoid exploit-generation features
- label uncertain results as possible, likely, or confirmed based on evidence
- avoid claiming a CVE is present unless evidence supports it
- keep uploaded files local during the MVP
- document ethical use clearly

## Quality Requirements

The tool should be:

- understandable for learners
- modular for contributors
- testable through small functions
- usable without cloud services
- clear about false positives
- careful about unsupported security claims

## Success Metrics

The project reaches a strong `v1.0` when a user can:

- scan a firmware file locally
- see a clean summary of risk
- inspect evidence behind each finding
- compare two firmware versions
- export a readable report
- extend detection rules
- run the tool from a fresh clone using documented steps

## First Implementation Target

The first implementation target is a CLI command:

```bash
fwb scan samples/demo-firmware.bin --json
```

Expected early output:

```json
{
  "file": {
    "name": "demo-firmware.bin",
    "size_bytes": 12345,
    "sha256": "..."
  },
  "analysis": {
    "entropy": 6.72,
    "strings_count": 42,
    "suspicious_findings": []
  }
}
```
