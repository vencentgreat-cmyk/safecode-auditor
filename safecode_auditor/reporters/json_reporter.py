"""Deterministic JSON output."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from .common import normalize_finding, sort_key


def build_json_report(findings: Iterable[Any]) -> dict[str, Any]:
    normalized = sorted(
        (normalize_finding(finding) for finding in findings),
        key=sort_key,
    )
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in normalized:
        severity = finding["severity"]
        counts[severity] = counts.get(severity, 0) + 1
    return {
        "schema_version": "1.0.0",
        "tool": {
            "name": "SafeCode Auditor",
            "version": "0.2.0",
        },
        "summary": {
            "total": len(normalized),
            "by_severity": counts,
        },
        "findings": normalized,
    }
