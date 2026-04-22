import sys
import os
from scanner.secret_sniffer import scan_directory
from scanner.config_checker import scan_config_directory
from scanner.firebase_analyzer import scan_firebase_directory

# ── Display helpers ────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

SEVERITY_ICONS = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH    ",
    "MEDIUM":   "🟡 MEDIUM  ",
    "LOW":      "🟢 LOW     ",
}

def print_banner():
    """Print the tool banner"""
    print("=" * 62)
    print("   SafeCode Auditor — Vibe Coding Security Scanner")
    print("=" * 62)

def print_section_header(title):
    """Print a section divider"""
    print(f"\n{'━' * 62}")
    print(f"  {title}")
    print(f"{'━' * 62}")

def print_secret_finding(i, f):
    """Print a finding from Secret Sniffer or Config Checker"""
    severity = f.get("severity", "HIGH")
    icon = SEVERITY_ICONS.get(severity, severity)
    print(f"\n  [{i}] {icon} — {f['rule']}")
    print(f"       File : {f['file']} (line {f['line']})")
    print(f"       Found: {f['content'][:80]}")
    print(f"       Fix  : {f['fix'][:120]}")

def print_firebase_finding(i, f):
    """Print a finding from Firebase Analyzer"""
    icon = SEVERITY_ICONS.get(f['severity'], f['severity'])
    ops = ", ".join(f['operations'])
    print(f"\n  [{i}] {icon} — {f['vuln_type']}")
    print(f"       Path : {f['path']}")
    print(f"       Ops  : {ops}")
    print(f"       Why  : {f['explanation']}")
    print(f"       Fix  : {f['fix'].splitlines()[0]}")

def print_summary(secret_findings, config_findings, firebase_findings):
    """Print a consolidated summary"""
    all_findings = secret_findings + config_findings + firebase_findings

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in secret_findings + config_findings:
        sev = f.get("severity", "HIGH")
        counts[sev] = counts.get(sev, 0) + 1
    for f in firebase_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"\n{'=' * 62}")
    print("  SCAN SUMMARY")
    print(f"{'=' * 62}")
    print(f"  🔴 CRITICAL : {counts['CRITICAL']}")
    print(f"  🟠 HIGH     : {counts['HIGH']}")
    print(f"  🟡 MEDIUM   : {counts['MEDIUM']}")
    print(f"  {'─' * 30}")
    print(f"  TOTAL       : {len(all_findings)} issue(s) found")
    print(f"{'=' * 62}\n")

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    """Main entry point for the CLI"""
    print_banner()

    if len(sys.argv) < 2:
        print("\n  Usage  : python main.py <path_to_scan>")
        print("  Example: python main.py ./my_project\n")
        sys.exit(1)

    target = sys.argv[1]

    if not os.path.exists(target):
        print(f"\n  ❌ Error: Path '{target}' does not exist.\n")
        sys.exit(1)

    print(f"\n  🔍 Scanning: {target}\n")

    # ── Module 1: Secret Sniffer ───────────────────────────────────────────────
    print_section_header("MODULE 1 — SECRET SNIFFER (source code)")
    secret_findings = scan_directory(target)

    if not secret_findings:
        print("\n  ✅ No hardcoded secrets found.")
    else:
        for i, f in enumerate(secret_findings, 1):
            # Normalize severity field for secret findings
            if "severity" not in f:
                f["severity"] = "HIGH"
            print_secret_finding(i, f)

    # ── Module 2: Config Checker ───────────────────────────────────────────────
    print_section_header("MODULE 2 — CONFIG CHECKER (.env / Docker / Firebase)")
    config_findings = scan_config_directory(target)

    if not config_findings:
        print("\n  ✅ No dangerous config settings found.")
    else:
        for i, f in enumerate(config_findings, 1):
            if "severity" not in f:
                f["severity"] = "HIGH"
            print_secret_finding(i, f)

    # ── Module 3: Firebase Analyzer ───────────────────────────────────────────
    print_section_header("MODULE 3 — FIREBASE ANALYZER (logic vulnerabilities)")
    firebase_findings = scan_firebase_directory(target)

    if not firebase_findings:
        print("\n  ✅ No Firebase logic vulnerabilities found.")
    else:
        for i, f in enumerate(firebase_findings, 1):
            print_firebase_finding(i, f)

    # ── Summary ────────────────────────────────────────────────────────────────
    print_summary(secret_findings, config_findings, firebase_findings)


if __name__ == "__main__":
    main()