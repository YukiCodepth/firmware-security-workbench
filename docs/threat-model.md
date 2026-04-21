# Threat Model

## Purpose

This threat model defines what Firmware Security Workbench is designed to help detect and what it intentionally avoids.

## Protected Users

The tool is intended to help:

- firmware developers
- embedded systems students
- security learners
- defensive security reviewers
- open-source maintainers

## Assets We Care About

The project helps protect:

- firmware confidentiality
- embedded credentials
- device update integrity
- software component visibility
- developer release quality
- audit evidence quality

## Supported Analysis Type

The MVP supports static analysis.

Static analysis means the firmware file is inspected without running it.

Examples:

- read bytes
- compute hashes
- extract strings
- detect patterns
- estimate entropy
- inspect file headers

## Out Of Scope

The MVP does not perform:

- exploit generation
- firmware emulation
- live device attacks
- credential cracking
- authentication bypass
- hardware dumping
- JTAG/SWD/UART extraction
- network scanning
- malware execution

## Threats The Tool Should Help Detect

### Hardcoded Secrets

Examples:

- API keys
- passwords
- private keys
- Wi-Fi credentials
- MQTT credentials
- cloud tokens

### Debug Leftovers

Examples:

- debug logs
- development endpoints
- test credentials
- verbose error messages
- developer file paths

### Risky Network Indicators

Examples:

- HTTP URLs
- MQTT brokers
- IP addresses
- domains
- update servers
- telemetry endpoints

### Weak Update Signals

Examples:

- unsigned update hints
- insecure update URLs
- rollback-related strings
- OTA endpoints without clear integrity evidence

### Component Risk

Examples:

- outdated library strings
- vulnerable component candidates
- ambiguous version patterns that need review

## Evidence vs Interpretation

The tool should always keep evidence separate from interpretation.

Evidence:

```text
String found: wifi_password=demo1234
Offset: 0x00012a40
```

Interpretation:

```text
Likely hardcoded Wi-Fi credential.
Severity: high
Confidence: high
```

## Confidence Model

Use confidence to avoid false certainty:

- `low`: weak evidence
- `medium`: meaningful evidence but needs manual review
- `high`: strong evidence pattern

## Severity Model

Use severity to describe possible impact:

- `info`: useful context
- `low`: minor issue or weak risk
- `medium`: security-relevant issue
- `high`: likely serious issue
- `critical`: severe issue with strong evidence

## Ethical Guardrails

The tool must not:

- help users attack systems
- generate exploit payloads
- hide malicious behavior
- encourage scanning firmware without authorization
- claim more certainty than the evidence supports

## Safe Usage Statement

Use this tool only on firmware you own, created yourself, downloaded from a vendor for legitimate research, or are authorized to assess.

## Initial Assumption

The first version assumes firmware files are provided by the user. Device extraction and live testing are future topics and must be handled with separate safety rules.
