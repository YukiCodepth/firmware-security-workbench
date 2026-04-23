# Phase 2: CLI Scanner MVP

## Goal

Build the first working firmware scanner command and release `v0.1.0` after verification.

## What You Learn In Phase 2

- what a CLI tool is and why it comes before UI
- how to read firmware bytes safely
- how to compute SHA256
- how entropy helps classify binary randomness
- how printable strings expose firmware clues
- how keyword-based suspicious finding detection works
- how JSON output supports automation

## Command Shape

The first command is:

```bash
./scripts/fwb scan samples/demo-firmware.bin
```

JSON mode:

```bash
./scripts/fwb scan samples/demo-firmware.bin --json
```

Save JSON output:

```bash
./scripts/fwb scan samples/demo-firmware.bin --out reports/generated/demo-scan.json
```

## MVP Output

Phase 2 output includes:

- file metadata (name, size, extension, type guess)
- SHA256 hash
- entropy score
- extracted strings count
- suspicious findings with:
  - keyword matches
  - severity
  - confidence
  - byte offset

## Verification Commands

Run tests:

```bash
python3 -m unittest discover -s tests -v
```

Run scanner manually:

```bash
./scripts/fwb scan samples/demo-firmware.bin
./scripts/fwb scan samples/demo-firmware.bin --json
```

## Completion Criteria

Phase 2 is complete when:

- scanner command runs locally
- output includes required metadata and analysis fields
- tests pass
- branch is pushed and merged into `main`
- release candidate notes for `v0.1.0` are ready
