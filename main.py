import sys
import os
from scanner.secret_sniffer import scan_directory
from scanner.config_checker import scan_config_directory

def print_banner():
    """Print the tool banner"""
    print("=" * 60)
    print("  SafeCode Auditor - Vibe Coding Security Scanner")
    print("=" * 60)

def print_findings(findings):
    """Print scan results in a formatted way"""
    if not findings:
        print("\n No issues found! Your code looks clean.")
        return

    print(f"\n Found {len(findings)} potential security issue(s):\n")
    print("-" * 60)

    for i, finding in enumerate(findings, start=1):
        print(f"[{i}] Rule    : {finding['rule']}")
        print(f"    File    : {finding['file']}")
        print(f"    Line    : {finding['line']}")
        print(f"    Content : {finding['content']}")
        print("-" * 60)

def main():
    """Main entry point for the CLI"""
    print_banner()

    # Check if user provided a target path
    if len(sys.argv) < 2:
        print("\nUsage: python main.py <path_to_scan>")
        print("Example: python main.py ./my_project")
        sys.exit(1)

    target = sys.argv[1]

    # Validate the path exists
    if not os.path.exists(target):
        print(f"\n Error: Path '{target}' does not exist.")
        sys.exit(1)

    print(f"\n🔍 Scanning: {target}\n")

    # Run both scanners
    secret_findings = scan_directory(target)
    config_findings = scan_config_directory(target)
    all_findings = secret_findings + config_findings

    print_findings(all_findings)

if __name__ == "__main__":
    main()