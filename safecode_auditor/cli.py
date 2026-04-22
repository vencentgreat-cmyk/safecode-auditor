import sys
import os

# Import scanner modules directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.secret_sniffer import scan_directory
from scanner.config_checker import scan_config_directory
from scanner.firebase_analyzer import scan_firebase_directory

SEVERITY_ICONS = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH    ",
    "MEDIUM":   "🟡 MEDIUM  ",
    "LOW":      "🟢 LOW     ",
}

def print_banner():
    print("=" * 62)
    print("   SafeCode Auditor — Vibe Coding Security Scanner")
    print("=" * 62)

def print_section_header(title):
    print(f"\n{'━' * 62}")
    print(f"  {title}")
    print(f"{'━' * 62}")

def print_secret_finding(i, f):
    severity = f.get("severity", "HIGH")
    icon = SEVERITY_ICONS.get(severity, severity)
    print(f"\n  [{i}] {icon} — {f['rule']}")
    print(f"       File : {f['file']} (line {f['line']})")
    print(f"       Found: {f['content'][:80]}")
    print(f"       Fix  : {f['fix'][:120]}")

def print_firebase_finding(i, f):
    icon = SEVERITY_ICONS.get(f['severity'], f['severity'])
    ops = ", ".join(f['operations'])
    print(f"\n  [{i}] {icon} — {f['vuln_type']}")
    print(f"       Path : {f['path']}")
    print(f"       Ops  : {ops}")
    print(f"       Why  : {f['explanation']}")
    print(f"       Fix  : {f['fix'].splitlines()[0]}")

def print_summary(secret_findings, config_findings, firebase_findings):
    all_findings = secret_findings + config_findings + firebase_findings
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

def main():
    print_banner()

    if len(sys.argv) < 2:
        print("\n  Usage  : safecode <path_to_scan>")
        print("  Example: safecode ./my_project\n")
        sys.exit(1)

    target = sys.argv[1]

    if not os.path.exists(target):
        print(f"\n  ❌ Error: Path '{target}' does not exist.\n")
        sys.exit(1)

    print(f"\n  🔍 Scanning: {target}\n")

    print_section_header("MODULE 1 — SECRET SNIFFER (source code)")
    secret_findings = scan_directory(target)
    if not secret_findings:
        print("\n  ✅ No hardcoded secrets found.")
    else:
        for i, f in enumerate(secret_findings, 1):
            if "severity" not in f:
                f["severity"] = "HIGH"
            print_secret_finding(i, f)

    print_section_header("MODULE 2 — CONFIG CHECKER (.env / Docker / Firebase)")
    config_findings = scan_config_directory(target)
    if not config_findings:
        print("\n  ✅ No dangerous config settings found.")
    else:
        for i, f in enumerate(config_findings, 1):
            if "severity" not in f:
                f["severity"] = "HIGH"
            print_secret_finding(i, f)

    print_section_header("MODULE 3 — FIREBASE ANALYZER (logic vulnerabilities)")
    firebase_findings = scan_firebase_directory(target)
    if not firebase_findings:
        print("\n  ✅ No Firebase logic vulnerabilities found.")
    else:
        for i, f in enumerate(firebase_findings, 1):
            print_firebase_finding(i, f)

    print_summary(secret_findings, config_findings, firebase_findings)

if __name__ == "__main__":
    main()