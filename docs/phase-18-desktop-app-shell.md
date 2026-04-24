# Phase 18: Desktop App Shell

## Goal

Phase 18 starts the move from browser dashboard to native desktop app for macOS, Windows, and Linux.

The selected direction is Tauri 2 with a local web frontend. This keeps the app lightweight and gives us a future path for bundling the Python scanner as a sidecar binary.

## What This Phase Adds

- `desktop/app`: polished desktop-first UI shell that can run in a browser today.
- `desktop/src-tauri`: native Tauri 2 scaffold for later macOS, Windows, and Linux installers.
- API-aware scan form that calls the existing FastAPI backend when it is running.
- Demo fallback data so the desktop shell still looks alive when the API is offline.
- Risk DNA, evidence feed, hardening scenarios, and release timeline views.

## How To Preview Today

Start the existing backend:

```bash
uvicorn backend.app:app --reload --port 8000
```

In a second terminal:

```bash
cd desktop
python3 -m http.server 4173 --directory app
```

Open:

```text
http://127.0.0.1:4173
```

## How Native Packaging Will Work Later

The desktop app will eventually bundle the scanner using a Tauri sidecar. Tauri requires platform-specific sidecar binaries with target triples, so we will add those in a later phase after the UI shell is stable.

Planned packaging path:

- macOS: `.app` and `.dmg`
- Windows: `.msi` or NSIS installer
- Linux: `.deb`, `.rpm`, or AppImage

## Next Phase

Phase 19 should turn the shell into a real desktop workflow:

- native file picker
- scan queue
- local result store
- desktop report viewer
- backend launcher or bundled scanner sidecar
