# Glossary

## Firmware

Software stored on a device that controls hardware behavior. Firmware usually runs closer to hardware than normal desktop applications.

## Raw Binary

A `.bin` firmware file is often a raw sequence of bytes with little or no metadata. The tool must infer meaning from content and patterns.

## ELF

Executable and Linkable Format. ELF files can contain sections, symbols, addresses, and other useful metadata.

## HEX

Intel HEX is a text-based firmware format that stores address and byte data in readable records.

## UF2

UF2 is a firmware update format often used by microcontroller boards. It stores firmware in blocks that are easy to drag and drop onto devices.

## Hash

A fixed-length fingerprint of a file. SHA256 helps identify whether two firmware files are exactly the same.

## Entropy

A measure of randomness. High entropy can suggest compressed data, encrypted data, packed sections, or random-looking content.

## Strings

Readable text extracted from binary data. Strings can reveal versions, paths, URLs, debug messages, credentials, and library names.

## Secret

Sensitive data that should not be hardcoded in firmware, such as passwords, API keys, private keys, Wi-Fi credentials, and tokens.

## YARA

A rule language used to identify patterns in files. YARA is common in malware analysis and can also help detect firmware artifacts.

## SBOM

Software Bill of Materials. A list of software components that appear inside a product or firmware image.

## CVE

Common Vulnerabilities and Exposures. A public identifier for a known security vulnerability.

## CVSS

Common Vulnerability Scoring System. A scoring system that estimates the severity of a vulnerability.

## Confidence

How sure the tool is about a finding. Firmware analysis often relies on evidence patterns, so confidence is safer than unsupported certainty.
