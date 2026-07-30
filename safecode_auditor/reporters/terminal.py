"""The human-readable terminal reporter."""

from .common import normalize_finding


SEVERITY_ICONS = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH    ",
    "MEDIUM": "🟡 MEDIUM  ",
    "LOW": "🟢 LOW     ",
}


def print_banner():
    print("=" * 62)
    print("   SafeCode Auditor — Vibe Coding Security Scanner")
    print("=" * 62)


def print_section_header(title):
    print(f"\n{'━' * 62}")
    print(f"  {title}")
    print(f"{'━' * 62}")


def print_secret_finding(i, finding):
    severity = finding.get("severity", "HIGH")
    icon = SEVERITY_ICONS.get(severity, severity)
    normalized = normalize_finding(finding)
    safe_content = normalized["description"]

    print(f"\n  [{i}] {icon} — {finding['rule']}")
    print(f"       File : {finding['file']} (line {finding['line']})")
    print(f"       Found: {safe_content[:80]}")
    print(f"       Fix  : {finding['fix'][:120]}")


def print_firebase_finding(i, finding):
    icon = SEVERITY_ICONS.get(
        finding["severity"],
        finding["severity"],
    )
    ops = ", ".join(finding["operations"])

    print(f"\n  [{i}] {icon} — {finding['vuln_type']}")
    print(f"       Path : {finding['path']}")
    print(f"       Ops  : {ops}")
    print(f"       Why  : {finding['explanation']}")
    print(f"       Fix  : {finding['fix'].splitlines()[0]}")


def print_summary(secret_findings, config_findings, firebase_findings):
    all_findings = (
        secret_findings
        + config_findings
        + firebase_findings
    )
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in secret_findings + config_findings:
        severity = finding.get("severity", "HIGH")
        counts[severity] = counts.get(severity, 0) + 1

    for finding in firebase_findings:
        severity = finding["severity"]
        counts[severity] = counts.get(severity, 0) + 1

    print(f"\n{'=' * 62}")
    print("  SCAN SUMMARY")
    print(f"{'=' * 62}")
    print(f"  🔴 CRITICAL : {counts['CRITICAL']}")
    print(f"  🟠 HIGH     : {counts['HIGH']}")
    print(f"  🟡 MEDIUM   : {counts['MEDIUM']}")
    print(f"  {'─' * 30}")
    print(f"  TOTAL       : {len(all_findings)} issue(s) found")
    print(f"{'=' * 62}\n")