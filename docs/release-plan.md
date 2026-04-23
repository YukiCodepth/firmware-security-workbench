# Release Plan

## What GitHub Releases Are

A GitHub Release is an official project snapshot. It tells users that the project reached a meaningful milestone.

A release can include:

- version number
- release notes
- source code snapshot
- screenshots or demo notes
- downloadable assets
- compiled binaries later

## What GitHub Packages Are

GitHub Packages are for publishing installable artifacts.

Examples:

- Docker images
- Python packages
- npm packages
- compiled binaries or archives

Packages are not needed right now. The project should first become useful from source code. Packages can come later when the install process is stable.

## Versioning Strategy

Firmware Security Workbench will use milestone-style semantic versions:

```text
vMAJOR.MINOR.PATCH
```

For this project:

- `v0.x.0` means pre-1.0 development releases
- `v1.0.0` means the first stable open-source release
- patch releases like `v0.5.1` are for small fixes after a milestone

## Planned Releases

| Version | Release Name | Purpose |
| --- | --- | --- |
| `v0.1.0` | CLI Scanner Preview | Prove the core scanner works from terminal |
| `v0.2.0` | Firmware Metadata + Format Detection | Add stronger firmware type and metadata support |
| `v0.3.0` | Local Scan History + API | Add SQLite storage and FastAPI upload/scan API |
| `v0.4.0` | Web Dashboard Alpha | Make the project usable from a browser |
| `v0.5.0` | Security Detection MVP | Complete the first useful product milestone |
| `v0.6.0` | YARA + Rules Engine | Add extensible rule-based detection |
| `v0.7.0` | SBOM + CVE Candidate Engine | Add component inventory and vulnerability candidates |
| `v0.8.0` | Firmware Diff + Risk DNA Beta | Add the signature risk intelligence layer |
| `v0.9.0` | Reports + Packaging RC | Prepare the project for stable release |
| `v1.0.0` | Stable Open-Source Release | First polished public release |

## Release Checklist

Before creating a release:

- `main` must be clean
- tests or manual verification must pass
- README must explain how to run the current version
- release notes must describe what changed
- known limitations must be documented
- screenshots should be added for UI releases
- example commands should be tested

## Release Assets By Stage

Early releases should include:

- source code snapshot
- release notes
- example command output

Dashboard releases should include:

- screenshots
- short demo GIF or video link later
- sample firmware scan output

Packaging releases should include:

- Docker image instructions
- possible Python package instructions
- checksums for downloadable assets if binaries are published

## Package Policy

Do not publish packages during the early documentation and CLI planning phases.

Possible future packages:

- Docker image for local deployment
- Python package for the `fwb` CLI
- standalone executable binaries for common platforms

Package publishing should wait until:

- install steps are stable
- CLI command names are stable
- report schema is reasonably stable
- tests cover the core scanner

## Release Notes Format

Each release should include:

```markdown
# Firmware Security Workbench vX.Y.Z

## Highlights

## Added

## Changed

## Fixed

## Known Limitations

## How To Try It
```

## Important Rule

Releases are for users. Phase branches are for development.

Do not create a release just because a phase ended. Create a release when the project has a meaningful capability that someone can try.
