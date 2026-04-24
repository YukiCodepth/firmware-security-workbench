# Phase 19: Next-Gen UI + Desktop Packaging

## Goal

Phase 19 upgrades Firmware Security Workbench from a functional dashboard into a polished security console and adds the first GitHub-based desktop package workflow.

The app now has a shared visual direction across the browser dashboard and desktop shell: dark operational workspace, compact evidence surfaces, Risk DNA cockpit, hardening studio, and release-grade desktop packaging path.

## What This Phase Adds

- Redesigned browser dashboard with mission-control layout.
- Redesigned desktop shell to match the dashboard visual system.
- Shared product direction for web and native desktop experience.
- GitHub Actions workflow for desktop builds on:
  - macOS
  - Windows
  - Linux
- Tauri capability scaffold for native permissions.
- Repeatable desktop dependency lockfile with `npm ci`.
- Branded desktop icon source that is regenerated before packaging.
- Test coverage for desktop shell files and packaging workflow presence.

## How To Preview The Web Dashboard

```bash
uvicorn backend.app:app --reload --port 8000
```

Open:

```text
http://127.0.0.1:8000/dashboard
```

## How To Preview The Desktop Shell

```bash
cd desktop
python3 -m http.server 4173 --directory app
```

Open:

```text
http://127.0.0.1:4173
```

## How To Build Desktop Packages On GitHub

Open GitHub Actions and run:

```text
Desktop Packages
```

The workflow uploads desktop bundle artifacts for each operating system.

You can also create a desktop package tag. Use a fresh tag for each packaging attempt:

```bash
git tag desktop-v0.4.0
git push origin desktop-v0.4.0
```

## Packaging Notes

The current desktop app is an alpha shell that talks to the existing FastAPI backend when it is running. The package workflow builds focused release artifacts for macOS (`dmg`), Windows (`msi`), and Linux (`deb`) and regenerates platform icons from `desktop/app-icon.svg` before running Tauri.

The next packaging milestone should bundle the scanner/runtime as a Tauri sidecar so the desktop app is fully self-contained.

## Next Phase

Phase 20 should add native workflows:

- native file picker
- scan queue
- report viewer
- desktop-local scan storage
- bundled scanner sidecar
