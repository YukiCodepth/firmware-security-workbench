# MVP Scope

## MVP Meaning

MVP means "minimum viable product." It is the smallest version that is useful enough to demonstrate the core idea.

For this project, the MVP is not the final dream. It is the first version that proves the scanner workflow works.

## MVP Boundary

The MVP ends after Phase 7.

At that point, the project should support:

- CLI firmware scanning
- basic file metadata
- SHA256 hashing
- entropy calculation
- printable strings extraction
- suspicious keyword matching
- likely secret detection
- local scan history
- API upload and scan endpoint
- simple web dashboard

## MVP User Story

As a learner or embedded developer, I want to upload or scan a firmware file so that I can quickly understand whether it contains obvious risky artifacts such as hardcoded passwords, URLs, debug strings, or high-entropy regions.

## MVP Input

Accepted input:

- raw `.bin` files
- ELF `.elf` files if parser support is ready
- any binary file for generic scanning

Deferred input:

- `.hex`
- `.uf2`
- compressed vendor update packages
- encrypted firmware
- firmware extracted from hardware interfaces

## MVP Output

The MVP should produce:

- JSON scan result
- terminal summary
- stored scan history
- dashboard summary

Report formats like HTML, Markdown, and PDF are post-MVP.

## MVP Detection Categories

The MVP should detect:

- passwords and password-like strings
- private key markers
- certificates
- IP addresses
- URLs
- email addresses
- debug strings
- OTA/update-related strings
- admin/root/default credential hints
- high-entropy file regions

## MVP Confidence Levels

Findings should use confidence levels:

- `low`: weak signal, needs manual review
- `medium`: useful pattern but not enough evidence alone
- `high`: strong pattern, likely security-relevant

Example:

```text
"password" string alone -> low confidence
"wifi_password=demo1234" -> high confidence
```

## MVP Severity Levels

Findings should use severity levels:

- `info`
- `low`
- `medium`
- `high`
- `critical`

Severity describes possible impact. Confidence describes how sure we are.

## MVP Non-Goals

The MVP does not need:

- perfect firmware unpacking
- full reverse engineering
- accurate architecture identification for every file
- confirmed vulnerability proof
- exploit demonstration
- cloud deployment
- beautiful UI animations

## Definition of Done

The MVP is done when:

- scanner can analyze at least one sample firmware-like binary
- scan output is structured and documented
- findings are stored locally
- API can trigger a scan
- dashboard can display scan summaries
- tests cover core scan logic
- README explains how to run the tool
