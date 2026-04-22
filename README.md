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

---

## Quick Start

**Requirements:** Python 3.11+

**Install dependencies:**
```bash