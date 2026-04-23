# Phase 3: Firmware Metadata + Format Detection

## Goal

Upgrade the scanner from simple file type guessing to richer format-aware metadata extraction for:

- ELF
- Intel HEX
- UF2

## What You Learn In Phase 3

- why firmware formats carry different levels of metadata
- how ELF headers expose architecture and entry-point hints
- how Intel HEX records map data into memory ranges
- how UF2 blocks describe target addresses and family hints
- how to keep format parsing defensive when files are malformed

## New Capabilities

- file-level `format_details` in JSON output
- architecture hint extraction when possible
- parser status reporting:
  - `ok`
  - `partial`
  - `invalid`
  - `not_applicable`

### ELF metadata

- class (`ELF32` or `ELF64`)
- endianness
- OS ABI
- machine code and machine name
- entry point
- program header and section header counts
- section name preview when available
- symbol table size hints

### Intel HEX metadata

- record counts
- record type counts
- checksum failures
- data byte totals
- EOF record detection
- address range estimation

### UF2 metadata

- valid and invalid block counts
- payload size range
- target address range
- family IDs and known family names
- trailing byte detection

## Commands

Scan raw binary:

```bash
./scripts/fwb scan samples/demo-firmware.bin --json
```

Scan Intel HEX:

```bash
./scripts/fwb scan samples/demo-firmware.hex --json
```

## Verification

```bash
python3 -m unittest discover -s tests -v
```

Phase 3 should pass tests that validate format parsing for ELF, Intel HEX, and UF2.
