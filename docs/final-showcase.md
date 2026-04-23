# Final Showcase Guide (`v1.0.0`)

## Core Demo Flow

1. Scan a firmware sample and export SBOM:
   - `./scripts/fwb scan samples/corpus/esp32-lab-vuln.bin --json --sbom-out reports/generated/esp32.sbom.json`
2. Scan a second firmware and run diff:
   - `./scripts/fwb diff samples/corpus/esp32-lab-vuln.bin samples/corpus/stm32-lab-vuln.bin --json --out reports/generated/esp32-vs-stm32.diff.json`
3. Render a markdown report from scan JSON:
   - `./scripts/fwb report reports/generated/esp32.scan.json --kind scan --format markdown --out reports/generated/esp32.scan.md`
4. Render an HTML report from diff JSON:
   - `./scripts/fwb report reports/generated/esp32-vs-stm32.diff.json --kind diff --format html --out reports/generated/esp32-vs-stm32.diff.html`
5. Run local API + dashboard:
   - `uvicorn backend.app:app --reload --port 8000`
   - Open `http://127.0.0.1:8000/dashboard`

## What To Show

- Findings, secrets, endpoints, rules, SBOM, CVE candidates in one scan.
- Risk DNA fingerprint and score.
- Diff trend (`risk_increased` / `risk_decreased`).
- Report export in JSON/Markdown/HTML.
- CI workflow and Docker container runtime.

## Release Checklist

- `python3 -m unittest discover -s tests -v` passes.
- CLI scan/diff/report commands execute successfully.
- Dashboard loads and can query CVE/SBOM/rules with assistant.
- Docker image builds and serves API.
- README, ROADMAP, and docs reflect final feature set.
