"""Stable finding fingerprints and baseline persistence."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from safecode_auditor.reporters.common import normalize_finding


def fingerprint(finding: Any) -> str:
    item = normalize_finding(finding)
    location = item["location"]
    filename = location["file"]
    if os.path.isabs(filename):
        filename = os.path.relpath(filename, os.getcwd())
    identity = {
        "rule_id": item["rule_id"],
        "file": os.path.normcase(os.path.normpath(filename)),
        "path": item.get("path"),
        "operations": item.get("operations", []),
        "condition": item.get("condition"),
        "description": item.get("description"),
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_baseline(findings: Iterable[Any]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "fingerprints": sorted({fingerprint(item) for item in findings}),
    }


def write_baseline(path: str, findings: Iterable[Any]) -> None:
    Path(path).write_text(
        json.dumps(build_baseline(findings), indent=2) + "\n",
        encoding="utf-8",
    )


def load_baseline(path: str) -> set[str]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    values = payload.get("fingerprints")
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("baseline must contain a fingerprints string array")
    return set(values)


def exclude_baseline(findings: Iterable[Any], known: set[str]) -> list[Any]:
    return [item for item in findings if fingerprint(item) not in known]
