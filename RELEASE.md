# Release Guide

This document describes the release process for Moat, its Helm chart, and the Moat operator controller. Each component has its own independent release process.

## Overview

The Moat project consists of three independently versioned components:

1. **Moat** - The main Rust application (reverse proxy and firewall)
2. **Chart** - The Helm chart for deploying Moat and the operator
3. **Controller** - The Kubernetes operator (Go-based)

Each component can be released independently using the Makefile targets. Releases create Git tags that trigger GitHub Actions workflows for building and publishing artifacts.

## Release Types

### 1. Moat Release

Releases the main Moat application.

**Command:**
```bash
make release-moat VERSION=x.y.z
```

**What it does:**
- Updates `Cargo.toml` version field
- Updates `install.sh` VERSION variable
- Runs `cargo update -p moat` to update Cargo.lock
- Commits changes with message: `chore: release moat x.y.z`
- Creates Git tag: `vx.y.z`
- Pushes commit and tag to `origin/main`

**GitHub Workflow:**
- Triggers `.github/workflows/release.yaml`
- Builds Docker images for multiple platforms (linux/amd64, linux/arm64)
- Builds binary artifacts for multiple architectures
- Creates GitHub release with artifacts

**Example:**
```bash
make release-moat VERSION=0.1.0
```

### 2. Chart Release

Releases the Helm chart for deploying Moat and the operator.

**Command:**
```bash
make release-chart VERSION=x.y.z
```

**What it does:**
- Updates `moat-operator/helm/Chart.yaml`:
  - `version` field (chart version)
  - `appVersion` field (application version)
  - `dependencies[].version` for the moat subchart
- Updates `moat-operator/helm/charts/moat/Chart.yaml`:
  - `version` field (chart version)
  - `appVersion` field (application version)
- Commits changes with message: `chore: release chart x.y.z`
- Creates Git tag: `chart/vx.y.z`
- Pushes commit and tag to `origin/main`

**GitHub Workflow:**
- Triggers `.github/workflows/moat-chart-release.yaml`
- Uses `helm/chart-releaser-action` to package and publish the chart
- Publishes to GitHub Pages (chart repository)

**Example:**
```bash
make release-chart VERSION=0.2.0
```

### 3. Controller Release

Releases the Moat operator (Kubernetes controller).

**Command:**
```bash
make release-controller VERSION=x.y.z
```

**What it does:**
- Creates an empty commit (controller doesn't have version files to update)
- Commits with message: `chore: release controller x.y.z`
- Creates Git tag: `controller/vx.y.z`
- Pushes commit and tag to `origin/main`

**GitHub Workflow:**
- Triggers `.github/workflows/moat-operator-release.yaml`
- Builds Docker image for multiple platforms (linux/amd64, linux/arm64)
- Builds binary artifacts for multiple architectures
- Creates GitHub release with artifacts

**Example:**
```bash
make release-controller VERSION=0.1.0
```

## Prerequisites

Before releasing, ensure:

1. **Working directory is clean:**
   ```bash
   git status
   ```
   All changes should be committed before running a release.

2. **You're on the main branch:**
   ```bash
   git checkout main
   git pull origin main
   ```

3. **You have push permissions:**
   - Must be able to push to `origin/main`
   - Must be able to create tags

4. **Version follows semantic versioning:**
   - Format: `MAJOR.MINOR.PATCH` (e.g., `1.2.3`)
   - Follow [Semantic Versioning](https://semver.org/) guidelines

## Release Process

### Step-by-Step Guide

1. **Prepare your release:**
   - Ensure all changes are committed
   - Test your changes thoroughly
   - Update CHANGELOG if maintained

2. **Choose the appropriate release command:**
   - For Moat application: `make release-moat VERSION=x.y.z`
   - For Helm chart: `make release-chart VERSION=x.y.z`
   - For Controller: `make release-controller VERSION=x.y.z`

3. **Verify the release:**
   - Check that the tag was created: `git tag -l`
   - Check GitHub Actions for workflow execution
   - Verify artifacts are published correctly

## Tag Naming Convention

- **Moat releases:** `vx.y.z` (e.g., `v0.1.0`)
- **Chart releases:** `chart/vx.y.z` (e.g., `chart/v0.2.0`)
- **Controller releases:** `controller/vx.y.z` (e.g., `controller/v0.1.0`)

## Versioning Guidelines

- **MAJOR version:** Incompatible API changes
- **MINOR version:** New functionality in a backwards compatible manner
- **PATCH version:** Backwards compatible bug fixes

## Troubleshooting

### Release fails with "VERSION is required"
- Ensure you're providing the VERSION parameter: `make release-moat VERSION=x.y.z`

### Release fails with "uncommitted changes"
- Commit or stash your changes before running a release

### Tag already exists
- Delete the tag locally: `git tag -d vx.y.z`
- Delete the tag remotely: `git push origin --delete vx.y.z`
- Then retry the release

### GitHub workflow not triggered
- Check that the tag format matches the expected pattern
- Verify GitHub Actions is enabled for the repository
- Check workflow file conditions match the tag pattern

## Notes

- All releases push to the `main` branch
- Releases are automated via GitHub Actions after tag creation
- Chart releases require the chart to be packaged correctly
- Controller releases create empty commits since there are no version files to update

