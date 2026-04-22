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

**Option 1: Install as CLI tool (recommended)**

```bash
git clone https://github.com/vencentgreat-cmyk/safecode-auditor.git
cd safecode-auditor
pip install .
```

Then scan any project from anywhere:

```bash
safecode ./your_project
```

**Option 2: Run directly**

```bash
pip install pytest
python main.py ./your_project
```

**Example output:**
============================================================
SafeCode Auditor - Vibe Coding Security Scanner
🔍 Scanning: ./your_project
🚨 Found 3 potential security issue(s):
[1] Rule    : AWS Access Key
File    : ./your_project/config.py
Line    : 12
Content : AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
Fix     : Move to environment variable: AWS_ACCESS_KEY_ID=your_key in .env

---

## Real-World Testing

To validate accuracy, SafeCode Auditor was tested against 3 real open-source Firebase projects on GitHub, covering different levels of security maturity. Project names and specific details have been anonymized to follow responsible disclosure practices.

---

### Sample A: Social App (beginner-level security)

A Firebase-based social application with minimal security configuration.

| Severity | Type | Path | Assessment |
|---|---|---|---|
| CRITICAL | OpenAccess | /adminSettings | ✅ True positive — admin config publicly readable |
| CRITICAL | OpenAccess | /users | ✅ True positive — all user data publicly readable |
| CRITICAL | OpenAccess | /posts | ✅ True positive — all posts publicly readable |
| HIGH | WriteWithoutValidation | /userPrompts | ✅ True positive — write lacks data validation |

**12 total findings. All confirmed true positives.**

---

### Sample B: Team Management App (intermediate security)

A more mature project using custom role-based authentication functions.

| Severity | Type | Path | Assessment |
|---|---|---|---|
| CRITICAL | OpenAccess | /reports | ✅ True positive — `allow read, write;` with no condition |
| CRITICAL | OpenAccess | /division-users | ✅ True positive — `allow create;` with no condition |
| CRITICAL | OpenAccess | /division-codes | ✅ True positive — `allow write;` with no condition |
| HIGH | AuthButNoOwner | /users | ⚠️ False positive — custom `isAuthorised()` function handles access |

**11 total findings, 3 confirmed true positives. False positives occur when projects use custom auth functions.**

---

### Sample C: Social Clone App (typical vibe-coded structure)

A social media clone — representative of AI-assisted development patterns.

| Severity | Type | Path | Assessment |
|---|---|---|---|
| HIGH | AuthButNoOwner | /users | ✅ True positive — any logged-in user can read all user profiles |
| CRITICAL | OpenAccess | /tweets | ⚠️ Intentional — public read is by design for a social feed |

**4 total findings, 1 confirmed true positive.**

---

### Known Limitations

- **Custom auth functions**: Projects using role-based helpers like `isAuthorised()` generate false positives on `AuthButNoOwner` and `WriteWithoutValidation` checks. The analyzer cannot resolve custom function logic.
- **Intentional public access**: Public read on content collections is sometimes by design. Context matters.
- **Best suited for**: Vibe-coded apps and beginner Firebase projects where simple `request.auth` patterns are common.

---

## Project Structure
safecode-auditor/
├── scanner/
│   ├── secret_sniffer.py    # Scans source code for hardcoded secrets
│   ├── config_checker.py    # Scans config files for dangerous settings
│   └── firebase_analyzer.py # Logic-based Firebase Rules vulnerability engine
├── safecode_auditor/
│   └── cli.py               # CLI entry point for pip install
├── test_targets/            # Intentionally vulnerable files for testing
├── tests/                   # Automated test suite (16/16 passing)
├── main.py                  # Direct run entry point
└── pyproject.toml           # Package configuration

---

## Test Coverage

```bash
pytest tests/ -v
# 16 passed in 0.06s
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
- [x] Installable CLI tool via `pip install`
- [ ] CORS misconfiguration detection
- [ ] JWT weak secret detection
- [ ] HTML report export

---

*Built to address real security risks in the vibe coding era.*