"""Stable finding fingerprints and baseline persistence.

Baselines use a versioned format.  Schema ``1.0.0`` baselines include
the finding description in the fingerprint; schema ``2.0.0`` baselines
exclude it so that wording improvements in newer tool versions do not
invalidate fingerprints.

When *loading* a baseline, the consumer gets a callable that checks both
fingerprint formats.  When *writing*, the caller chooses the schema.
New baselines are always written in ``2.0.0`` format by default.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any

from safecode_auditor.reporters.common import normalize_finding

CURRENT_SCHEMA = "2.0.0"


# ── fingerprint functions ──────────────────────────────────────────────


def _fingerprint_identity(item: dict[str, Any], include_description: bool) -> dict[str, Any]:
    location = item["location"]
    filename = location["file"]
    if os.path.isabs(filename):
        filename = os.path.relpath(filename, os.getcwd())
    identity: dict[str, Any] = {
        "rule_id": item["rule_id"],
        "file": os.path.normcase(os.path.normpath(filename)),
        "start_line": location.get("start_line", 1),
        "start_column": location.get("start_column", 1),
        "path": item.get("path"),
        "operations": list(item.get("operations", [])),
        "condition": item.get("condition"),
    }
    if include_description:
        identity["description"] = item.get("description")
    return identity


def _compute_fingerprint(identity: dict[str, Any]) -> str:
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def fingerprint_v1(finding: Any) -> str:
    """Original fingerprint including description in the hash."""
    item = normalize_finding(finding)
    return _compute_fingerprint(_fingerprint_identity(item, include_description=True))


def fingerprint_v2(finding: Any) -> str:
    """Improved fingerprint that excludes mutable prose descriptions."""
    item = normalize_finding(finding)
    return _compute_fingerprint(_fingerprint_identity(item, include_description=False))


def fingerprint(finding: Any) -> str:
    """Compute the current recommended fingerprint (v2, excludes description)."""
    return fingerprint_v2(finding)


# ── baseline builder ───────────────────────────────────────────────────


def build_baseline(
    findings: Iterable[Any],
    schema_version: str = CURRENT_SCHEMA,
) -> dict[str, Any]:
    fp_func = fingerprint_v1 if schema_version == "1.0.0" else fingerprint_v2
    return {
        "schema_version": schema_version,
        "fingerprints": sorted({fp_func(item) for item in findings}),
    }


def write_baseline(path: str, findings: Iterable[Any]) -> None:
    Path(path).write_text(
        json.dumps(build_baseline(findings), indent=2) + "\n",
        encoding="utf-8",
    )


# ── baseline loader (backward-compatible) ──────────────────────────────


def load_baseline(path: str) -> set[str]:
    """Return the set of fingerprint strings stored in *path*.

    The caller should pass the returned set to :func:`exclude_baseline`.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    values = payload.get("fingerprints")
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("baseline must contain a fingerprints string array")
    return set(values)


def load_baseline_matcher(
    path: str,
) -> Callable[[Any], bool]:
    """Return a predicate that returns ``True`` when a finding is suppressed.

    For schema-``1.0.0`` baselines the predicate checks both v1 and v2
    fingerprints so that description-only changes in a newer tool version
    do not silently re-surface previously accepted findings.

    For any other schema only the fingerprint format recorded in the
    baseline is used.
    """
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    schema = payload.get("schema_version", "1.0.0")
    fingerprints: Sequence[str] = payload.get("fingerprints", [])
    if not isinstance(fingerprints, list) or not all(
        isinstance(val, str) for val in fingerprints
    ):
        raise ValueError("baseline must contain a fingerprints string array")
    fp_set: set[str] = set(fingerprints)

    if schema == "1.0.0":
        # Backward-compatible: check both v1 and v2 fingerprints.
        def _predicate(finding: Any) -> bool:
            return (
                fingerprint_v1(finding) in fp_set
                or fingerprint_v2(finding) in fp_set
            )
    else:
        def _predicate(finding: Any) -> bool:
            return fingerprint_v2(finding) in fp_set

    return _predicate


# ── baseline exclusion ─────────────────────────────────────────────────


def exclude_baseline(findings: Iterable[Any], known: set[str]) -> list[Any]:
    """Exclude findings whose v2 fingerprint is in *known*.

    Prefer :func:`load_baseline_matcher` for new code; this function
    exists for backward compatibility with callers that use
    :func:`load_baseline` directly.
    """
    return [item for item in findings if fingerprint_v2(item) not in known]
