# Changelog

## 0.2.2 - 2026-07-31

### Fixed
- Firestore AST: `_root_identifier_name` now traverses `MemberAccess` chains, so chained built-in methods such as `request.resource.data.keys().hasOnly(...)` are no longer misclassified as custom function calls.
- Branch-aware AST checks: for an `||` expression, a security predicate is now required on both sides; for an `&&` expression, one side is sufficient; a predicate under `!` never counts.
- FIRE003 (WriteWithoutValidation) now fires when validation exists only on one side of an `||`, or is negated with `!`.

### Added
- Ruff (`ruff check` and `ruff format --check`) enforced in CI.
- End-to-end Action smoke test workflow that consumes `./action.yml` against a clean fixture and against the vulnerable fixtures.
- `action.yml` distinguishes exit code 1 (configuration or execution error) from exit code 2 (findings met threshold), with distinct annotations and a `scan-exit-code` output.

### Validation
- 59 automated tests pass on Python 3.11 and 3.12.

## 0.2.1 - 2026-07-30

### Added
- Detection for Firestore writes with no detected data validation.
- Sensitive-value redaction in report output.
- Python 3.12 compatibility metadata.

### Changed
- Improved terminal and structured report handling.
- Removed tracked Python cache files from the repository.
- Updated the package version to 0.2.1.

### Validation
- 50 automated tests pass.
