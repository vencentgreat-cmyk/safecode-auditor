# SafeCode Auditor 🔍
![CI](https://github.com/vencentgreat-cmyk/safecode-auditor/actions/workflows/safecode-scan.yml/badge.svg)

> A lightweight security analyzer designed for the vibe coding era.

As AI-assisted development becomes mainstream, developers often ship applications with insecure configurations, overly permissive access rules, and missing validation logic.

SafeCode Auditor detects these issues early — before they reach production.

---

## 🚨 The Problem

AI-generated (vibe-coded) applications frequently introduce subtle security flaws:

- Hardcoded API keys and secrets
- Misconfigured Firebase access rules
- Overly permissive authentication logic
- Missing validation on user input

These issues are often **logically incorrect, not syntactically invalid** — making them harder to detect with traditional scanners.

---

## 🚀 Key Features

### 🔐 Secret Sniffer
Detects:
- OpenAI API keys
- AWS credentials
- GitHub tokens
- Hardcoded passwords

---

### ⚙️ Config Checker
Scans:
- `.env` files
- Docker configurations
- Firebase JSON configs

---

### 🔥 Firebase Analyzer (AST-powered)

Unlike traditional tools that rely on string matching, SafeCode Auditor now includes a:

> **Lightweight expression parser that converts Firebase rule conditions into an Abstract Syntax Tree (AST)**

This enables **semantic analysis** of authorization logic.

#### Detects:

- 🔴 OpenAccess  
  → `if true`

- 🟠 AuthButNoOwner  
  → `request.auth != null` without ownership check

- 🟡 WeakUidCheck  
  → `request.auth.uid != null`

- 🟠 WriteWithoutValidation  
  → Missing `request.resource.data` validation

---

### 🧠 Why AST Matters

Traditional scanners:
```text
String matching → fragile, high false positives

SafeCode Auditor:

Parse → AST → Analyze logic structure

Example:

request.auth.uid == userId && request.auth != null

Becomes:

AND(
  EQ(request.auth.uid, userId),
  NOT_NULL(request.auth)
)

This allows:

Accurate detection of ownership checks
Support for reversed conditions (userId == request.auth.uid)
Reduced false positives
Better handling of real-world rule complexity
📦 Project Structure
safecode-auditor/
├── scanner/
│   ├── secret_sniffer.py
│   ├── config_checker.py
│   ├── firebase_analyzer.py   # AST-based logic engine
│   ├── expression_parser.py   # NEW: expression parser
├── tests/
│   ├── test_sniffer.py
│   ├── test_firebase_ast.py   # NEW: AST test coverage
🧪 Test Coverage
pytest tests/ -v

Includes:

Ownership detection
Weak UID checks
Validation logic detection
AST parsing edge cases
Invalid expression fallback
⚠️ Known Limitations
Custom auth functions (e.g., isOwner()) are not fully resolved yet
Full data-flow analysis is not implemented (future work)
🧭 Roadmap
 Secret detection
 Config scanning
 Firebase rule analyzer
 AST-based expression parsing
 Improved false positive reduction
 Custom function resolution
 JSON / HTML report export
🧠 Vision

SafeCode Auditor aims to evolve from a scanner into:

A developer safety layer that prevents security mistakes during AI-assisted development