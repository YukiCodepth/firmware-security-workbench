# Architecture

Firmware Security Workbench is designed as modular layers.

## High-Level Modules

```text
Firmware File
     |
     v
Input Layer
     |
     v
Analysis Engine
     |
     +--> Metadata Extractor
     +--> Hash and Entropy Analyzer
     +--> Strings Extractor
     +--> Secret Scanner
     +--> YARA Engine
     +--> Component Detector
     +--> CVE Risk Matcher
     +--> Firmware Diff Engine
     +--> Firmware Risk DNA Engine
     |
     v
Storage Layer
     |
     v
Reports and UI
```

## CLI Layer

The CLI will be the first interface. It should be fast, scriptable, and useful before the web UI exists.

Example future command:

```bash
fwb scan samples/demo-firmware.bin
```

## Backend Layer

The backend will use FastAPI. It will expose upload, scan, history, and report endpoints.

## Frontend Layer

The frontend will be a local dashboard for people who prefer visual analysis over command-line output.

## Detection Rules

Rules should live outside core code where possible. This keeps the scanner extensible and makes it easier for contributors to add detections.

## Report Layer

Reports should separate evidence from interpretation.

Evidence example:

```text
String found: mqtt://broker.example.local
Offset: 0x00102a40
```

Interpretation example:

```text
The firmware likely contains MQTT networking behavior.
Confidence: medium
```
