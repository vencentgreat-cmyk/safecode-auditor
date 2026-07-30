# SafeCode Auditor

[![CI](https://github.com/vencentgreat-cmyk/safecode-auditor/actions/workflows/safecode-scan.yml/badge.svg)](https://github.com/vencentgreat-cmyk/safecode-auditor/actions/workflows/safecode-scan.yml)

SafeCode Auditor is a PR-ready security scanner for Firebase Security Rules,
hardcoded credentials, and unsafe application configuration. Its Firestore
analyzer parses rule conditions into an AST, reports exact source locations,
and emits JSON or SARIF for CI and GitHub Code Scanning.

## What it detects

| Rule ID | Severity | Finding |
|---|---:|---|
| `FIRE001` | Critical | Public access through `if true` or a bare write rule |
| `FIRE002` | High | Authentication without an ownership check |
| `FIRE003` | High | Authenticated writes without data validation |
| `FIRE004` | Medium | A UID existence check used as authorization |
| `SEC001`–`SEC007` | High | API keys, tokens, passwords, and database credentials |
| `CFG001`–`CFG007` | High | Unsafe `.env`, Docker, and Firebase configuration |

When a Firestore expression cannot be parsed, heuristic findings are retained
but explicitly marked as low confidence.

## Install and scan

Requires Python 3.11 or newer.

```bash
git clone https://github.com/vencentgreat-cmyk/safecode-auditor.git
cd safecode-auditor
python -m pip install .
```

Scan a directory or one rules file:

```bash
safecode .
safecode firestore.rules
```

The default terminal report remains suitable for local use. Machine-readable
reports are deterministic and versioned:

```bash
safecode . --format json
safecode . --format sarif --output saferules.sarif
```

Fail CI only when a finding reaches a chosen threshold:

```bash
safecode . --fail-on high
```

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | Scan completed and no unsuppressed finding met the threshold |
| `1` | Invalid arguments, target, output, or baseline |
| `2` | A finding met `--fail-on` |

## Adopt safely with a baseline

Create a baseline from existing findings:

```bash
safecode . --format json --generate-baseline .saferules-baseline.json
```

Commit that file and fail only on new High/Critical findings:

```bash
safecode . \
  --baseline .saferules-baseline.json \
  --fail-on high
```

Suppress an intentionally accepted rule by stable ID:

```bash
safecode . --ignore-rule FIRE001
```

`--ignore-rule` can be repeated. Prefer a baseline for existing technical debt;
use rule suppression only when a rule is intentionally irrelevant to the
project.

## GitHub Pull Request integration

The repository includes a composite GitHub Action. A consumer workflow needs
read access to the repository and `security-events: write` to upload SARIF:

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

Optional Action inputs:

| Input | Default | Purpose |
|---|---|---|
| `path` | `.` | File or directory to scan |
| `fail-on` | `high` | `none`, `low`, `medium`, `high`, or `critical` |
| `baseline` | empty | Path to a committed baseline |
| `ignore-rules` | empty | Comma-separated stable rule IDs |
| `upload-sarif` | `true` | Upload annotations to GitHub Code Scanning |

Private repositories must have GitHub Code Security available and enabled for
SARIF upload. If it is unavailable, set `upload-sarif: "false"`; threshold
enforcement still works.

A complete workflow template is available at
[`examples/saferules-workflow.yml`](examples/saferules-workflow.yml).

## Firestore analysis architecture

```text
source
  → offset-preserving comment state machine
  → nested match/allow parser
  → condition tokenizer and recursive-descent AST parser
  → semantic signals
  → FIRE001–FIRE004 registry
  → typed Finding with Location, Severity, Confidence, and Fix
  → terminal / JSON / SARIF reporters
```

Comment removal preserves every character offset and newline position. This
allows an `allow` rule to be mapped back to its exact start line and column,
including inside nested `match` blocks. Strings containing `//`, such as URLs,
are not treated as comments.

The original dictionary-style finding access remains compatible with v0.1,
while the versioned JSON schema exposes stable IDs, confidence, locations, and
structured fixes.

## Development

```bash
python -m pip install pytest
python -m pytest -q
python -m compileall -q safecode_auditor scanner main.py
```

The test suite covers the expression parser, all four Firestore rules,
backward-compatible output, nested source locations, comment edge cases,
deterministic JSON/SARIF, single-file scanning, thresholds, suppression, and
baseline behavior.

## Current boundaries

- Custom authorization helper bodies are recognized but not interpreted.
- Public read access may be intentional for public content.
- Baselines suppress exact stable fingerprints; semantic permission diff is a
  later milestone.
- The Action and SARIF document can be validated locally, but Code Scanning
  annotations require a real GitHub workflow run.

## Roadmap

- [x] Typed and backward-compatible finding model
- [x] Reliable Firestore source locations
- [x] Stable rule IDs and confidence
- [x] Deterministic JSON and SARIF
- [x] Single-file and directory scanning
- [x] Severity thresholds, baseline, and rule suppression
- [x] Composite GitHub Action
- [ ] Coarse before/after permission diff
- [ ] Firebase Emulator verification for high-risk findings
- [ ] Semantic condition implication

## License

Add a license before publishing the Action to the GitHub Marketplace. MIT is a
good default for an open-source developer tool.
