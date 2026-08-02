# Security Policy

## Supported Versions

Only the most recent release receives security updates.

| Version | Supported |
| ------- | --------- |
| latest  | ✅ |
| < latest | ❌ |

The latest version is identified by the highest-numbered Git tag
(on GitHub) or the newest published package (on PyPI). The floating
`v0` tag is maintained for GitHub Action consumers and points at
the most recent stable release.

## Reporting a Vulnerability

If you discover a security vulnerability **in SafeCode Auditor itself**
(not in a project scanned by SafeCode), please report it privately.

**Please do not report security vulnerabilities through public GitHub
issues, discussions, or pull requests.**

Instead, use the **GitHub Security Advisory** workflow:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Follow the instructions to open a private advisory.

Alternatively, use the GitHub-integrated **Private Vulnerability
Reporting** feature if enabled for this repository.

### What to include

- A clear description of the vulnerability.
- Steps to reproduce the issue.
- The affected version(s) of SafeCode Auditor.
- Any potential impact or exploit scenario.
- If possible, a suggested fix or mitigation.

### What to expect

- You should receive an acknowledgment within one week.
- We will investigate and keep you informed of progress.
- Once resolved, we will publish a security advisory and credit you
  (unless you prefer to remain anonymous).
- We do not offer a guaranteed resolution SLA at this stage.

## Scope

### In scope

- Vulnerabilities in SafeCode Auditor's own code:
  parser bugs that could be exploited, insecure file handling, secret
  leakage in tool output, dependency vulnerabilities, or CI/CD
  supply-chain issues.

### Out of scope

- Security findings produced by SafeCode Auditor when scanning your
  project. Those are *results*, not vulnerabilities in the tool.
  Handle them as you would any other static analysis finding.
- Vulnerabilities in third-party tools that SafeCode integrates with
  (GitHub Actions, Code Scanning, Firebase Emulator). Report those
  to the respective vendor.

## Disclosure

- Do not include Firebase database URLs, API keys, passwords, user
  data, or any credentials in a vulnerability report.
- Do not disclose vulnerabilities publicly before a fix is released
  and an advisory is published.
- We will coordinate disclosure with you.

## Security Model

SafeCode Auditor is a **static analysis tool**. It reads local files
and produces reports. It does not:

- Connect to remote servers (except as configured by the user).
- Modify scanned files.
- Access Firebase projects or production data.
- Collect or transmit telemetry.

The primary security concern is that the tool could be tricked into
leaking sensitive data through its output (JSON, SARIF, terminal)
or that malformed input could cause unexpected behavior.