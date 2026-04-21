# Phase 1: Product Requirements + Prior-Art Research

## Goal

Before building scanner code, we define what the product should do, what it should not do yet, and how it will be different from existing tools.

## What You Should Learn In This Phase

### Product Requirements

Product requirements answer these questions:

- Who is the tool for?
- What problems should it solve first?
- What features are mandatory for the first useful version?
- What features should wait until later?
- What does "done" mean for each feature?

For this project, requirements protect us from building random features without a clear direction.

### Prior-Art Research

Prior-art research means studying tools, papers, standards, and workflows that already exist.

This is important because "nobody has built this" is a dangerous claim. A better and more honest goal is:

- understand what already exists
- avoid copying existing tools without improvement
- find gaps in usability, education, workflow, and reporting
- make our unique value clear

### Threat Model

A threat model explains what risks the tool is designed to help detect and what risks are outside its scope.

For Firmware Security Workbench, the MVP focuses on static analysis of firmware files. It does not extract firmware from devices, exploit devices, emulate firmware, or attack networks.

## Phase 1 Deliverables

- `docs/product-requirements.md`
- `docs/mvp-scope.md`
- `docs/prior-art.md`
- `docs/threat-model.md`

## Key Decision

The project will not try to beat large tools like EMBA or FACT in total feature count. Instead, the first version will focus on:

- a clean learner-friendly workflow
- local-first scanning
- clear evidence-based reporting
- confidence levels
- firmware version diffing
- Firmware Risk DNA

## Next Phase

`Phase 2: CLI Scanner MVP`

Phase 2 will create the first real scanner command:

```bash
fwb scan path/to/firmware.bin
```

The command will calculate file metadata, hashes, entropy, extracted strings, suspicious keyword hits, and JSON output.
