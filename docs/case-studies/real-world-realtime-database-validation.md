Real-World Validation: Firebase Realtime Database

Status: Local validation completed on August 1, 2026Scope: An anonymized Android application using Firebase Realtime DatabaseDisclosure: Project identifiers, database URLs, credentials, user data, and local paths are intentionally excluded.

Executive Summary

SafeCode Auditor was tested against a local copy of the Firebase Realtime Database rules from an existing Android application. The goal was to determine whether the scanner could detect a real security misconfiguration outside its own unit-test fixtures.

The scan found one HIGH-severity issue: unrestricted public read access. With the failure threshold set to high, SafeCode returned exit code 2. This confirmed both the detection rule and the non-zero exit behavior required for future CI enforcement.

This was a real-world local validation, not yet a GitHub Actions, pull-request blocking, or SARIF integration test.

How SafeCode Works

flowchart TD
    A["Application repository"] --> B["SafeCode CLI or GitHub Action"]
    B --> C["Secret Sniffer"]
    B --> D["Configuration Checker"]
    B --> E["Firebase Logic Analyzer"]
    C --> F["Normalized findings"]
    D --> F
    E --> F
    F --> G["Terminal, JSON, or SARIF report"]
    F --> H["Severity threshold and exit code"]

SafeCode separates detection from reporting. Each scanner module produces normalized findings, which can then be displayed for a developer, consumed by another tool, or used to fail a CI job when the configured severity threshold is reached.

How Developers Use It

Local development

flowchart LR
    A["Developer changes rules"] --> B["Run SafeCode locally"]
    B --> C{"High-risk finding?"}
    C -- Yes --> D["Review and remediate"]
    D --> B
    C -- No --> E["Commit with confidence"]

Example:

safecode <path-to-rules-file> --format terminal --fail-on high

Planned pull-request integration

flowchart TD
    A["Contributor opens a pull request"] --> B["GitHub Action runs SafeCode"]
    B --> C["Scan changed configuration and rules"]
    C --> D["Upload SARIF findings"]
    C --> E{"Threshold reached?"}
    E -- Yes --> F["Fail the security check"]
    E -- No --> G["Allow normal review to continue"]

The GitHub Action flow above describes the intended product experience. It remains a planned external integration test and should not be described as completed until it has been validated in a repository controlled solely for SafeCode testing.

Validation Setup

Item

Value

Target

Local copy of rules from an existing Android application

Firebase product

Realtime Database

Execution environment

Local Windows development environment

Reporter

Terminal

Failure threshold

High

Application repository modified

No

Production Firebase configuration modified

No

Production data accessed

No

The relevant anonymized rule pattern was:

{
  "rules": {
    ".read": "true",
    ".write": "auth != null"
  }
}

Observed Result

SafeCode reported:

Field

Observed value

Severity

HIGH

Finding

Firebase: Unrestricted read access

Risk

Unauthenticated users may be able to read protected database content

Suggested remediation

Require authentication or define narrower, path-specific authorization

Total findings

1

Process exit code

2

The exit code was expected because --fail-on high was enabled. In other words, the command did not fail because the scanner crashed; it intentionally stopped the workflow because a finding met the selected security threshold.

What This Validation Proved

The test demonstrated that SafeCode can:

Scan Firebase configuration taken from a real application rather than a synthetic fixture.

Detect unrestricted Realtime Database read access.

Classify the issue at the expected severity.

Produce a clear remediation message.

Return a deterministic non-zero exit code suitable for CI enforcement.

What It Did Not Prove

This test did not validate:

installation from a separate repository through uses: ...@v0;

execution inside GitHub Actions;

pull-request annotations;

SARIF upload to GitHub Code Scanning;

branch protection or merge blocking;

automatic deployment or modification of Firebase rules.

These distinctions keep the evidence accurate and reproducible.

Gaps Discovered During Validation

1. Missing source location

The configuration checker reported line N/A. Findings should point to the exact JSON key and line so developers can navigate directly to the problem.

Planned improvement: parse JSON with source-location tracking and attach file, line, and rule-path metadata to each finding.

2. Limited Realtime Database semantics

The current finding came from the configuration checker. The deeper AST-based Firebase analyzer focuses on Firestore rules and does not yet provide equivalent semantic analysis for Realtime Database JSON rules.

Planned improvement: add a dedicated Realtime Database analyzer that understands nested .read, .write, .validate, wildcard paths, inherited permissions, and authorization expressions.

3. Remediation needs context

Replacing public access with auth != null is safer, but authentication alone may still be too broad for sensitive or user-specific paths.

Planned improvement: provide path-aware remediation guidance and distinguish authentication from authorization.

4. External Action validation remains incomplete

Local CLI behavior is verified, but the complete consumer experience still needs an isolated end-to-end test.

Planned improvement: use a dedicated SafeCode demo repository to verify Action installation, SARIF annotations, severity thresholds, and PR check behavior without modifying a shared project.

Development Roadmap

Priority

Milestone

Evidence of completion

P0

Add JSON-aware line locations

Realtime Database findings include exact file and line numbers

P0

Add Realtime Database semantic analysis

Tests cover nested permissions, wildcards, validation, and inherited access

P1

Create an isolated integration repository

An external repository successfully invokes the published Action

P1

Validate SARIF and PR annotations

Findings appear on the correct lines in GitHub Code Scanning

P1

Verify threshold behavior in CI

High findings fail the check; lower findings follow configuration

P2

Publish a sanitized before/after example

Documentation shows detection, remediation, and a clean rescan

P2

Expand rule-specific remediation

Guidance reflects the affected path and authorization model

Recommended Next Validation

The next test should use a repository owned exclusively for SafeCode integration testing. It should contain representative insecure and secure Firebase rule samples plus a minimal workflow that calls the published Action.

The expected end-to-end evidence is:

A deliberately insecure test branch produces a HIGH finding and exit code 2.

GitHub Actions marks the security job as failed for the expected reason.

The SARIF result appears on the correct source line.

A remediation commit removes the finding.

The same workflow passes with exit code 0.

This produces a complete detect → block → remediate → verify story without adding test artifacts to a shared application repository.

Safe Public Evidence

This document is suitable for a public repository because it is anonymized. Before publishing screenshots or logs, remove:

repository and Firebase project names;

database URLs and project identifiers;

usernames and absolute local paths;

credentials, tokens, and user data;

details that would identify an unresolved live target.

Once the affected application has been reviewed and remediated, a sanitized before/after result can be added here.

Portfolio-Safe Description

Validated SafeCode Auditor against Firebase Realtime Database rules from an existing Android application. The scanner identified a real HIGH-severity public-read configuration and enforced the configured threshold with exit code 2. The exercise also exposed product gaps in JSON source locations and semantic analysis for Realtime Database rules, which were converted into roadmap items.