"""SARIF 2.1.0 output for GitHub Code Scanning."""

from __future__ import annotations

import hashlib
import json
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


def _partial_fingerprints(finding: dict[str, Any]) -> dict[str, str]:
    """Compute stable partial fingerprints for GitHub Code Scanning correlation.

    Builds the same identity as the baseline v2 fingerprint (rule ID, file,
    start line, start column, path, operations, condition) so that two
    findings with different semantic identities never collide, even if they
    happen to share the same file and line.
    """
    location = finding["location"]
    filename = location["file"]
    if os.path.isabs(filename):
        filename = os.path.relpath(filename, os.getcwd())
    identity = {
        "rule_id": finding["rule_id"],
        "file": os.path.normcase(os.path.normpath(filename)),
        "start_line": location.get("start_line", 1),
        "start_column": location.get("start_column", 1),
        "path": finding.get("path"),
        "operations": list(finding.get("operations", [])),
        "condition": finding.get("condition"),
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    primary_line = hashlib.sha256(encoded).hexdigest()
    return {
        "primaryLocationLineHash": hashlib.md5(
            primary_line.encode("utf-8")
        ).hexdigest(),
    }


def _security_severity(severity: str) -> str:
    return {
        "CRITICAL": "9.5",
        "HIGH": "8.0",
        "MEDIUM": "5.0",
        "LOW": "2.0",
    }.get(severity, "5.0")


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
                    "security-severity": _security_severity(finding["severity"]),
                    "tags": ["security", finding["category"]],
                },
            },
        )
        location = finding["location"]
        region: dict[str, Any] = {
            "startLine": location["start_line"],
        }
        start_column = location.get("start_column")
        if start_column is not None and start_column != 1:
            region["startColumn"] = start_column
        end_line = location.get("end_line")
        if end_line is not None:
            region["endLine"] = end_line
        end_column = location.get("end_column")
        if end_column is not None:
            region["endColumn"] = end_column

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _level(finding["severity"]),
            "message": {"text": finding["explanation"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _artifact_uri(location["file"])
                        },
                        "region": region,
                    }
                }
            ],
            "partialFingerprints": _partial_fingerprints(finding),
            "properties": {
                "confidence": finding["confidence"],
                "severity": finding["severity"],
            },
        }
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SafeCode Auditor",
                        "informationUri": (
                            "https://github.com/vencentgreat-cmyk/"
                            "safecode-auditor"
                        ),
                        "version": __version__,
                        "rules": [
                            definitions[key] for key in sorted(definitions)
                        ],
                    }
                },
                "results": results,
            }
        ],
    }
