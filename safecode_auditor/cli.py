"""Command-line interface for SafeCode Auditor."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from safecode_auditor.baseline import (
    exclude_baseline,
    load_baseline,
    write_baseline,
)
from safecode_auditor.reporters.common import normalize_finding
from safecode_auditor.reporters.json_reporter import build_json_report
from safecode_auditor.reporters.sarif import build_sarif_report
from safecode_auditor.reporters.terminal import (
    print_banner,
    print_firebase_finding,
    print_secret_finding,
    print_section_header,
    print_summary,
)
from scanner.config_checker import scan_config_directory, scan_config_file
from scanner.firebase_analyzer import (
    scan_firebase_directory,
    scan_firebase_file,
)
from scanner.secret_sniffer import scan_directory, scan_file


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safecode",
        description="Scan source and Firebase rules for security issues.",
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument(
        "--format",
        choices=("terminal", "json", "sarif"),
        default="terminal",
        dest="output_format",
        help="Output format (default: terminal)",
    )
    parser.add_argument("--output", help="Write JSON or SARIF to this file")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="Exit 2 when a new finding meets this severity",
    )
    parser.add_argument(
        "--baseline",
        help="Exclude findings recorded in this baseline file",
    )
    parser.add_argument(
        "--generate-baseline",
        metavar="FILE",
        help="Write current finding fingerprints to FILE",
    )
    parser.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Ignore a rule ID; may be supplied more than once",
    )
    return parser


def _scan(target: str):
    if os.path.isdir(target) or not os.path.isfile(target):
        return (
            scan_directory(target),
            scan_config_directory(target),
            scan_firebase_directory(target),
        )

    secret_findings = scan_file(target)
    config_findings = scan_config_file(target)
    firebase_findings = []
    filename = os.path.basename(target).lower()
    if filename in {
        "firestore.rules",
        "database.rules.json",
        "firebase.rules",
    } or filename.endswith(".rules"):
        firebase_findings = scan_firebase_file(target)
    return secret_findings, config_findings, firebase_findings


def _write_structured(payload, output: str | None) -> None:
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if output:
        Path(output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


def _fails(findings, threshold: str) -> bool:
    if threshold == "none":
        return False
    ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    minimum = ranks[threshold.upper()]
    return any(ranks.get(normalize_finding(item)["severity"], 0) >= minimum for item in findings)


def _print_terminal(
    target: str,
    secret_findings,
    config_findings,
    firebase_findings,
) -> None:
    print_banner()
    print(f"\n  🔍 Scanning: {target}\n")

    print_section_header("MODULE 1 — SECRET SNIFFER (source code)")
    if not secret_findings:
        print("\n  ✅ No hardcoded secrets found.")
    else:
        for index, finding in enumerate(secret_findings, 1):
            if "severity" not in finding:
                finding["severity"] = "HIGH"
            print_secret_finding(index, finding)

    print_section_header("MODULE 2 — CONFIG CHECKER (.env / Docker / Firebase)")
    if not config_findings:
        print("\n  ✅ No dangerous config settings found.")
    else:
        for index, finding in enumerate(config_findings, 1):
            if "severity" not in finding:
                finding["severity"] = "HIGH"
            print_secret_finding(index, finding)

    print_section_header("MODULE 3 — FIREBASE ANALYZER (logic vulnerabilities)")
    if not firebase_findings:
        print("\n  ✅ No Firebase logic vulnerabilities found.")
    else:
        for index, finding in enumerate(firebase_findings, 1):
            print_firebase_finding(index, finding)

    print_summary(secret_findings, config_findings, firebase_findings)


def main(argv: list[str] | None = None):
    raw_args = sys.argv[1:] if argv is None else argv
    if not raw_args:
        print_banner()
        print("\n  Usage  : safecode <path_to_scan>")
        print("  Example: safecode ./my_project\n")
        raise SystemExit(1)

    args = _parser().parse_args(raw_args)
    target = args.target
    if not os.path.exists(target):
        if args.output_format == "terminal":
            print_banner()
            print(f"\n  ❌ Error: Path '{target}' does not exist.\n")
        else:
            print(f"Error: Path '{target}' does not exist.", file=sys.stderr)
        raise SystemExit(1)

    secret_findings, config_findings, firebase_findings = _scan(target)
    ignored = {rule_id.upper() for rule_id in args.ignore_rule}
    if ignored:
        secret_findings = [
            item for item in secret_findings if normalize_finding(item)["rule_id"] not in ignored
        ]
        config_findings = [
            item for item in config_findings if normalize_finding(item)["rule_id"] not in ignored
        ]
        firebase_findings = [
            item for item in firebase_findings if normalize_finding(item)["rule_id"] not in ignored
        ]
    all_original = secret_findings + config_findings + firebase_findings

    if args.generate_baseline:
        write_baseline(args.generate_baseline, all_original)

    if args.baseline:
        try:
            known = load_baseline(args.baseline)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: invalid baseline: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        secret_findings = exclude_baseline(secret_findings, known)
        config_findings = exclude_baseline(config_findings, known)
        firebase_findings = exclude_baseline(firebase_findings, known)

    all_findings = secret_findings + config_findings + firebase_findings
    if args.output_format == "terminal":
        if args.output:
            print(
                "Error: --output requires --format json or sarif.",
                file=sys.stderr,
            )
            raise SystemExit(1)
        _print_terminal(
            target,
            secret_findings,
            config_findings,
            firebase_findings,
        )
    elif args.output_format == "json":
        _write_structured(build_json_report(all_findings), args.output)
    else:
        _write_structured(build_sarif_report(all_findings), args.output)

    if _fails(all_findings, args.fail_on):
        return 2
    return None


if __name__ == "__main__":
    raise SystemExit(main())
