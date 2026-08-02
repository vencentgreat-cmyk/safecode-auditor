# Changelog

## 0.3.0 - 2026-08-01

### Added
- Realtime Database permission-inheritance detector (CFG008): flags child owner-check rules that are overridden by a permissive ancestor.
- JSON source-locator with accurate line and column tracking for RTDB rules.
- RTDB rules tree model (`scanner/rtdb_tree`) for structured analysis.
- Bare boolean recognition (`true`, `false`, `null`) in JSON locator for RTDB rules that use unquoted literals.
- Unconditional read detection for bare Firestore `allow read;`, `allow get;`, and `allow list;` rules (previously only write operations were detected).
- `--explain RULE_ID` CLI flag for detailed per-rule documentation.
- `--list-rules` CLI flag to list all supported rule IDs.
- `firebase.json` project discovery: automatically locates rules files referenced in standard Firebase project configuration.
- `SECURITY.md` with vulnerability reporting guidance and supported-version policy.
- `RELEASE_CHECKLIST.md` for release process documentation.
- Synthetic example rules files (`examples/`) demonstrating vulnerable and fixed RTDB and Firestore configurations.
- Baseline schema `"2.0.0"` with improved fingerprint stability (description-independent).

### Changed
- JSON reporter now derives tool version from the authoritative package source instead of a hard-coded value.
- CLI baseline loading now uses a backward-compatible matcher that accepts both v1 and v2 fingerprints from old baselines.
- `Severity` and `Confidence` enums now inherit from `StrEnum` instead of `(str, Enum)`.
- SARIF output includes `partialFingerprints.primaryLocationLineHash` for GitHub Code Scanning correlation.
- SARIF region includes `endLine` and `endColumn` when genuinely known.
- README fully rewritten with accurate feature coverage, troubleshooting, and upgrade guidance.
- GitHub Actions workflow dependencies pinned to immutable commit SHAs with version comments.
- Rule metadata centralized in `safecode_auditor/explain.py`.

### Fixed
- Bare Firestore `allow read;` / `allow get;` / `allow list;` rules are now correctly detected as open access (previously treated as non-rules).
- JSON report tool version was stale (`0.2.0` instead of actual version).

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