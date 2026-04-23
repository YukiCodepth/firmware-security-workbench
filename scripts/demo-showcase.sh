#!/usr/bin/env bash
set -euo pipefail

mkdir -p reports/generated

./scripts/fwb scan samples/corpus/esp32-lab-vuln.bin \
  --json \
  --no-save \
  --out reports/generated/esp32.scan.json \
  --sbom-out reports/generated/esp32.sbom.json

./scripts/fwb scan samples/corpus/stm32-lab-vuln.bin \
  --json \
  --no-save \
  --out reports/generated/stm32.scan.json \
  --sbom-out reports/generated/stm32.sbom.json

./scripts/fwb diff \
  samples/corpus/esp32-lab-vuln.bin \
  samples/corpus/stm32-lab-vuln.bin \
  --json \
  --out reports/generated/esp32-vs-stm32.diff.json

./scripts/fwb report reports/generated/esp32.scan.json \
  --kind scan \
  --format markdown \
  --out reports/generated/esp32.scan.md

./scripts/fwb report reports/generated/esp32-vs-stm32.diff.json \
  --kind diff \
  --format html \
  --out reports/generated/esp32-vs-stm32.diff.html

echo "Showcase artifacts generated under reports/generated"
