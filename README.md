# SafeCode Auditor 🔍
![CI](https://github.com/vencentgreat-cmyk/safecode-auditor/actions/workflows/safecode-scan.yml/badge.svg)

> A lightweight security scanner designed for the vibe coding era.

As AI-generated code becomes mainstream, developers often ship apps with hardcoded secrets, exposed API keys, and misconfigured databases. SafeCode Auditor automatically detects these vulnerabilities before they reach production.

---

## The Problem

Vibe coders using tools like Cursor or ChatGPT frequently generate code that contains:
- Hardcoded API keys and passwords committed to GitHub
- `.env` files with exposed credentials
- Docker configurations with plaintext secrets
- Firebase databases open to the public internet

SafeCode Auditor catches these issues in seconds.

---

## Features

| Module | What it detects |
|---|---|
| Secret Sniffer | OpenAI keys, AWS credentials, GitHub tokens, hardcoded passwords |
| Config Checker | `.env` leaks, Docker secrets, Firebase open read/write rules |
| Firebase Analyzer | Logic-based vulnerability detection: OpenAccess, AuthButNoOwner, WeakUidCheck, WriteWithoutValidation |

---

## Quick Start

**Requirements:** Python 3.11+

**Install dependencies:**
```bash
pip install pytest
```

**Run a scan:**
```bash
python main.py ./your_project
```

**Example output:**
```
============================================================
  SafeCode Auditor - Vibe Coding Security Scanner
============================================================

🔍 Scanning: ./your_project

🚨 Found 3 potential security issue(s):

[1] Rule    : AWS Access Key
    File    : ./your_project/config.py
    Line    : 12
    Content : AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
    Fix     : Move to environment variable: AWS_ACCESS_KEY_ID=your_key in .env
```
---

## Real-World Testing

Tested against [mycalls/applimode](https://github.com/mycalls/applimode), a real Firebase social app on GitHub.

**Results: 12 findings detected**

| Severity | Type | Path | Risk |
|---|---|---|---|
| CRITICAL | OpenAccess | /adminSettings | Admin config publicly readable by anyone |
| CRITICAL | OpenAccess | /users | All user data publicly readable |
| CRITICAL | OpenAccess | /posts | All posts publicly readable |
| HIGH | WriteWithoutValidation | /userPrompts | Write operations lack data validation |

This demonstrates the tool's ability to detect real security issues in production Firebase applications.

---

## Project Structure
```
safecode-auditor/
├── scanner/
│   ├── secret_sniffer.py    # Scans source code for hardcoded secrets
│   ├── config_checker.py    # Scans config files for dangerous settings
│   └── firebase_analyzer.py # Logic-based Firebase Rules vulnerability engine
├── test_targets/            # Intentionally vulnerable files for testing
├── tests/                   # Automated test suite (16/16 passing)
└── main.py                  # CLI entry point

---

## Test Coverage

```bash
pytest tests/ -v
# 16 passed in 0.12s
```

All 16 tests cover real-world vulnerability patterns found in vibe-coded applications.

---

## Tech Stack

- **Language:** Python 3.11+
- **Core:** Regex pattern matching, recursive block parser, semantic rule analysis
- **Testing:** pytest
- **CI/CD:** GitHub Actions
- **Target files:** `.py`, `.js`, `.ts`, `.env`, `.json`, `.yml`, `.yaml`, `.rules`

---

## Roadmap

- [x] Secret sniffer for source code files
- [x] Config checker for `.env`, Docker, Firebase
- [x] Firebase logic vulnerability analyzer
- [x] GitHub Actions CI/CD integration
- [ ] CORS misconfiguration detection
- [ ] JWT weak secret detection
- [ ] HTML report export

---

*Built to address real security risks in the vibe coding era.*