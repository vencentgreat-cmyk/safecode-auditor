# Changelog

## 0.2.0 — 2026-07-30

### Added

- Typed `Finding`, `Location`, `Severity`, `Confidence`, and `Fix` models.
- Stable IDs for Firebase, secret, and configuration rules.
- Exact start line and column tracking for Firestore `allow` rules.
- Offset-preserving comment handling that distinguishes strings from comments.
- Deterministic, versioned JSON reports.
- SARIF 2.1.0 reports for GitHub Code Scanning.
- Scanning of a single `.rules` file as well as directories.
- Configurable CI failure threshold with `--fail-on`.
- Stable baselines with `--generate-baseline` and `--baseline`.
- Repeatable `--ignore-rule` suppression.
- Composite GitHub Action and consumer workflow template.
- MIT license and expanded installation/integration documentation.

### Changed

- Migrated FIRE001–FIRE004 to one canonical rule registry.
- Replaced duplicate `main.py` behavior with delegation to the package CLI.
- Made directory traversal and structured report ordering deterministic.
- Updated package version to 0.2.0 and moved packaging to setuptools.

### Compatibility

- Default terminal output and dictionary-style Firebase finding access remain
  compatible with v0.1.
- The default scan still exits successfully unless `--fail-on` is supplied.

### Validation

- 46 automated tests pass.
- The wheel builds and installs in a clean virtual environment.
- The installed `safecode` command generates valid JSON and SARIF.
- Action and workflow YAML files parse successfully.
