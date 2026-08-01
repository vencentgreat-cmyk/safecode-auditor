"""SARIF 2.1.0 output for GitHub Code Scanning."""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from safecode_auditor import __version__

from .common import normalize_finding, sort_key

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _level(severity: str) -> str:
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }.get(severity, "warning")


def _artifact_uri(filename: str) -> str:
    if os.path.isabs(filename):
        filename = os.path.relpath(filename, os.getcwd())
    return Path(filename).as_posix()


def build_sarif_report(findings: Iterable[Any]) -> dict[str, Any]:
    normalized = sorted(
        (normalize_finding(finding) for finding in findings),
        key=sort_key,
    )
    definitions: dict[str, dict[str, Any]] = {}
    results = []

    for finding in normalized:
        rule_id = finding["rule_id"]
        definitions.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding["rule_name"],
                "shortDescription": {"text": finding["title"]},
                "fullDescription": {"text": finding["description"]},
                "help": {
                    "text": finding["fix"]["description"],
                    "markdown": finding["fix"]["description"],
                },
                "properties": {
                    "security-severity": {
                        "CRITICAL": "9.5",
                        "HIGH": "8.0",
                        "MEDIUM": "5.0",
                        "LOW": "2.0",
                    }.get(finding["severity"], "5.0"),
                    "tags": ["security", finding["category"]],
                },
            },
        )
        location = finding["location"]
        region: dict[str, Any] = {
            "startLine": location["start_line"],
            "startColumn": location.get("start_column", 1),
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": _level(finding["severity"]),
                "message": {"text": finding["explanation"]},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _artifact_uri(location["file"])},
                            "region": region,
                        }
                    }
                ],
                "properties": {
                    "confidence": finding["confidence"],
                    "severity": finding["severity"],
                },
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SafeCode Auditor",
                        "informationUri": (
                            "https://github.com/vencentgreat-cmyk/" "safecode-auditor"
                        ),
                        "version": __version__,
                        "rules": [definitions[key] for key in sorted(definitions)],
                    }
                },
                "results": results,
            }
        ],
    }
