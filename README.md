# SafeCode Auditor

[![CI](https://github.com/vencentgreat-cmyk/safecode-auditor/actions/workflows/safecode-scan.yml/badge.svg)](https://github.com/vencentgreat-cmyk/safecode-auditor/actions/workflows/safecode-scan.yml)

SafeCode Auditor is a PR-ready security scanner for Firebase Security Rules,
hardcoded credentials, and unsafe application configuration. It parses Firestore
rule conditions into an AST, reports exact source locations, and emits JSON or
SARIF for CI and GitHub Code Scanning. Realtime Database rules are analysed
with a JSON source-locator that tracks accurate line and column positions.

## Supported Python Versions

Python 3.11 and later. No external dependencies beyond the standard library.

## Install

### From PyPI (recommended when available)

```bash
pip install safecode-auditor
```

### From source (always available)

```bash
git clone https://github.com/vencentgreat-cmyk/safecode-auditor.git
cd safecode-auditor
python -m pip install .
```

## Quick Start

### First scan — Firestore

```bash
safecode firestore.rules
```

### First scan — Realtime Database

```bash
safecode database.rules.json
```

### Scan a whole directory

```bash
safecode .
```

The directory scanner finds `firestore.rules`, `database.rules.json`,
`firebase.rules`, and any file ending in `.rules`. It also scans `.env` files,
Docker Compose files, source files for secrets, and `firebase.json` for project
configuration.

## What It Detects

### Firestore Rules (FIRE001–FIRE004)

| Rule ID | Severity | Finding |
| ------- | -------- | ------- |
| FIRE001 | Critical | Public access: `if true`, bare `allow read;`, or bare `allow write;` |
| FIRE002 | High     | Authentication without an ownership check on user-scoped paths |
| FIRE003 | High     | Authenticated writes without data validation |
| FIRE004 | Medium   | UID existence check (`!= null`) used as authorization |

Bare `allow read;`, `allow get;`, `allow list;`, `allow write;`, `allow create;`,
`allow update;`, and `allow delete;` (without an `if` clause) are all treated as
unconditional access and reported as FIRE001.

### Realtime Database Rules (CFG006–CFG008)

| Rule ID | Severity | Finding |
| ------- | -------- | ------- |
| CFG006  | High     | Unrestricted read access (`.read: "true"` or `.read: true`) |
| CFG007  | High     | Unrestricted write access (`.write: "true"` or `.write: true`) |
| CFG008  | High     | Ineffective child rule: a stricter descendant is overridden by a permissive ancestor |

CFG008 (permission inheritance) is the most interesting RTDB detector. Realtime
Database rules **cascade**: once an ancestor grants `.read` or `.write` at a
node, every descendant inherits that permission. A stricter owner-check rule
attached to a descendant (e.g. `$uid === auth.uid`) is made **ineffective** by a
permissive ancestor (e.g. `auth != null`). The detector reports these cases so
developers can tighten the ancestor rule or restructure the rules tree.

The analyser recognises these permissive ancestor patterns:

- `true`
- `auth != null` / `auth !== null`
- `auth.uid != null` / `auth.uid !== null`

It recognises stricter descendant patterns that include a `$wildcard` segment
compared against `auth.uid`. Other expression forms are left alone to avoid
false positives.

Accurate line and column numbers are reported for both the child rule (where the
annotation lands) and the ancestor (referenced in the finding message).

### Secrets (SEC001–SEC007)

| Rule ID | Severity | Finding |
| ------- | -------- | ------- |
| SEC001  | High     | OpenAI API Key |
| SEC002  | High     | AWS Access Key |
| SEC003  | High     | AWS Secret Key |
| SEC004  | High     | GitHub Token |
| SEC005  | High     | Hardcoded Password |
| SEC006  | High     | Database URL with credentials |
| SEC007  | High     | Generic Secret |

### Configuration (CFG001–CFG005)

| Rule ID | Severity | Finding |
| ------- | -------- | ------- |
| CFG001  | High     | Exposed ENV Secret |
| CFG002  | High     | Exposed Database URL |
| CFG003  | High     | Exposed Password in ENV |
| CFG004  | High     | Docker Hardcoded Password |
| CFG005  | High     | Docker Hardcoded Secret |

## Output Formats

### Terminal (default)

```bash
safecode . --format terminal
```

Suitable for local development. Shows a banner, per-module sections, and a
severity summary.

### JSON

```bash
safecode . --format json
safecode . --format json --output results.json
```

Deterministic, versioned JSON. Secret values in descriptions are redacted.

### SARIF (GitHub Code Scanning)

```bash
safecode . --format sarif --output results.sarif
```

SARIF 2.1.0 compliant. Upload to GitHub Code Scanning via
`github/codeql-action/upload-sarif`.

## Severity Thresholds and Exit Codes

```bash
safecode . --fail-on high
```

| Threshold | Behaviour |
| --------- | --------- |
| `none`    | Never fail (default) |
| `low`     | Fail if any finding is present |
| `medium`  | Fail on medium, high, or critical |
| `high`    | Fail on high or critical |
| `critical`| Fail only on critical |

Exit codes:

| Code | Meaning |
| ---- | ------- |
| 0    | Scan completed; no unsuppressed finding met the threshold |
| 1    | Invalid arguments, missing target, bad baseline, or output error |
| 2    | A finding met `--fail-on` |

## Baselines

Suppress known findings so only new issues fail CI.

```bash
# Capture current findings
safecode . --generate-baseline .saferules-baseline.json

# Scan excluding those findings
safecode . --baseline .saferules-baseline.json --fail-on high
```

Commit the baseline file. New findings on the same rule/file/location will still
be reported.

## Ignoring Rules

```bash
safecode . --ignore-rule FIRE001 --ignore-rule CFG006
```

Prefer a baseline for accepted technical debt; use rule suppression only when a
rule is intentionally irrelevant to the project.

## GitHub Action

```yaml
name: SafeRules PR Guard

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write
  actions: read

jobs:
  saferules:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - uses: vencentgreat-cmyk/safecode-auditor@v0
        with:
          path: .
          fail-on: high
```

Action inputs:

| Input | Default | Purpose |
| ----- | ------- | ------- |
| `path` | `.` | File or directory to scan |
| `fail-on` | `high` | `none`, `low`, `medium`, `high`, or `critical` |
| `baseline` | empty | Path to a committed baseline |
| `ignore-rules` | empty | Comma-separated stable rule IDs |
| `upload-sarif` | `true` | Upload annotations to GitHub Code Scanning |

A complete workflow template is at
[`examples/saferules-workflow.yml`](examples/saferules-workflow.yml).

For private repositories, GitHub Code Security must be available and enabled
for SARIF upload. Set `upload-sarif: "false"` if unavailable; threshold
enforcement still works.

### Version Pinning

- Use `@v0` for the latest stable release (auto-updating).
- Pin to a specific tag like `@v0.2.2` for reproducible CI.

## Architecture

```
Firestore:
  source
    → offset-preserving comment state machine
    → nested match/allow parser
    → condition tokenizer and recursive-descent AST parser
    → semantic signals
    → FIRE001–FIRE004 registry
    → typed Finding with Location, Severity, Confidence, and Fix
    → terminal / JSON / SARIF reporters

Realtime Database:
  source
    → JSON source-location scanner (line/column tracking)
    → rules tree builder
    → dangerous-key detector (CFG006, CFG007)
    → permission-inheritance analyser (CFG008)
    → terminal / JSON / SARIF reporters

Secrets & Config:
  source
    → regex-based scanners
    → secret redaction
    → terminal / JSON / SARIF reporters
```

## Troubleshooting

### `safecode: command not found`

Ensure the Python scripts directory is on your PATH, or run:

```bash
python -m safecode_auditor.cli <args>
```

### No findings on a rules file with known issues

- Verify the file is named `firestore.rules`, `database.rules.json`,
  `firebase.rules`, or ends in `.rules`.
- Check that rules are not commented out.
- Run with `--format json` to see the raw finding list.

### Baseline not suppressing a finding

- The finding's fingerprint may have changed (different file path, operation
  list, or condition text).
- Regenerate the baseline with `--generate-baseline`.

### CFG008 not firing on a permissive ancestor

- The ancestor expression must exactly match one of the five recognised patterns
  (`true`, `auth != null`, `auth !== null`, `auth.uid != null`,
  `auth.uid !== null`).
- The child expression must contain a `$wildcard` compared against `auth.uid`.

## Current Limitations

- Custom authorization helper bodies are recognised but not interpreted.
- Public read access may be intentional for public content; use `--ignore-rule`
  or a baseline to suppress known-accepted cases.
- Baselines use content-based fingerprints; reordering rules or changing
  descriptions may invalidate fingerprints.
- The Realtime Database analyser uses syntactic pattern matching, not a full
  expression AST. Compound permissive conditions are conservatively ignored
  rather than risking false positives.
- `firebase.json` discovery supports `database.rules` and `firestore.rules`
  keys. Complex multi-site or multi-project configurations are not detected.
- The GitHub Action and SARIF document can be validated locally, but Code
  Scanning annotations require a real workflow run.

## Development

```bash
python -m pip install pytest
python -m pytest -q
python -m compileall -q safecode_auditor scanner main.py
```

Lint with Ruff:

```bash
python -m pip install ruff==0.6.9
ruff check .
ruff format --check .
```

## Roadmap

- [x] Typed and backward-compatible finding model
- [x] Reliable Firestore source locations
- [x] Stable rule IDs and confidence
- [x] Deterministic JSON and SARIF
- [x] Single-file and directory scanning
- [x] Severity thresholds, baseline, and rule suppression
- [x] Composite GitHub Action
- [x] Accurate source locations for Realtime Database findings
- [x] Realtime Database permission inheritance analysis (CFG008)
- [x] Bare boolean recognition for RTDB rules
- [x] Unconditional read detection for bare Firestore rules
- [ ] Real RTDB expression AST for deeper semantic analysis
- [ ] Coarse before/after permission diff
- [ ] Firebase Emulator verification for high-risk findings
- [ ] Semantic condition implication

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.