# Contributing

Thanks for helping improve Firmware Security Workbench.

## Development Workflow

All work should happen on a phase or feature branch.

```bash
git checkout main
git pull origin main
git checkout -b phase/XX-short-name
```

Commit small, focused changes:

```bash
git add .
git commit -m "Phase XX: describe the change"
```

When the phase is complete, merge it back into `main`.

## Commit Style

Use clear commit messages:

- `Phase 02: add CLI scan command`
- `Docs: explain firmware metadata model`
- `Test: cover entropy calculation`
- `Fix: handle empty firmware files`

## Security and Ethics

This project is for defensive security, firmware review, and learning. Do not contribute code that enables unauthorized access, exploit deployment, credential abuse, or malware behavior.

## Quality Bar

Before a phase is considered complete:

- code should be readable
- public functions should have clear names
- tests should cover core logic where possible
- docs should explain new concepts for learners
- reports should avoid unsupported claims
