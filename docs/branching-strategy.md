# Branching Strategy

## Branches

`main` is the stable branch. It should stay clean, documented, and usable.

Each project phase uses a dedicated branch:

```text
phase/00-project-foundation
phase/01-requirements-prior-art
phase/02-cli-scanner-mvp
```

## Why This Matters

This makes the project easier to learn, review, and showcase. Each branch tells a story:

- what we planned to build
- what changed
- how the project improved
- when the phase was completed

## Standard Phase Workflow

Start from `main`:

```bash
git checkout main
git pull origin main
git checkout -b phase/XX-short-name
```

Build the phase:

```bash
git status
git add .
git commit -m "Phase XX: short description"
```

Push when a GitHub remote exists:

```bash
git push -u origin phase/XX-short-name
```

Merge after review:

```bash
git checkout main
git pull origin main
git merge phase/XX-short-name
git push origin main
```

## Current Limitation

The local machine currently has Git installed but not GitHub CLI. Until a GitHub remote is added, phase branches and merges can still happen locally.
