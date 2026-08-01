"""Tests for baseline fingerprint stability and compatibility."""

from __future__ import annotations

import json

from safecode_auditor.baseline import (
    CURRENT_SCHEMA,
    build_baseline,
    fingerprint_v1,
    fingerprint_v2,
    load_baseline,
    load_baseline_matcher,
    write_baseline,
)
from safecode_auditor.core.models import (
    Confidence,
    Finding,
    Fix,
    Location,
    Severity,
)


def _finding(**overrides):
    """Create a minimal typed Finding for fingerprint testing."""
    kwargs = {
        "rule_id": "FIRE001",
        "rule_name": "OpenAccess",
        "title": "Public access is allowed",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "description": "Collection is fully open to the public.",
        "explanation": "Using 'if true' allows anyone.",
        "location": Location(file="firestore.rules", start_line=3, start_column=24),
        "path": "/public/{docId}",
        "operations": ("read",),
        "condition": "true",
        "fix": Fix(description="Add auth check."),
    }
    kwargs.update(overrides)
    return Finding(**kwargs)


class TestFingerprintStability:
    """Fingerprints should be stable across description wording changes."""

    def test_v2_excludes_description(self):
        original = _finding(description="Old wording in v0.2.2.")
        changed = _finding(description="Improved wording with more detail in v0.3.0.")
        assert fingerprint_v2(original) == fingerprint_v2(changed)

    def test_v1_includes_description(self):
        original = _finding(description="Old wording.")
        changed = _finding(description="New wording.")
        assert fingerprint_v1(original) != fingerprint_v1(changed)

    def test_v2_changes_with_different_rule_id(self):
        a = _finding(rule_id="FIRE001")
        b = _finding(rule_id="FIRE002")
        assert fingerprint_v2(a) != fingerprint_v2(b)

    def test_v2_changes_with_different_line(self):
        a = _finding(location=Location(file="firestore.rules", start_line=1))
        b = _finding(location=Location(file="firestore.rules", start_line=5))
        assert fingerprint_v2(a) != fingerprint_v2(b)

    def test_v2_deterministic(self):
        f = _finding()
        fps = {fingerprint_v2(f) for _ in range(100)}
        assert len(fps) == 1


class TestBaselineBackwardCompatibility:
    """New code should accept old baselines."""

    def test_v1_baseline_suppresses_v1_fingerprinted_finding(self, tmp_path):
        finding = _finding()
        baseline_path = tmp_path / "baseline.json"
        payload = build_baseline([finding], schema_version="1.0.0")
        baseline_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        is_suppressed = load_baseline_matcher(str(baseline_path))
        assert is_suppressed(finding)

    def test_v1_baseline_still_works_when_description_unchanged(self, tmp_path):
        """If description hasn't changed, v1 baseline suppresses the finding."""
        finding = _finding(description="Stable description.")
        baseline_path = tmp_path / "baseline.json"
        payload = build_baseline([finding], schema_version="1.0.0")
        baseline_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        same = _finding(description="Stable description.")
        is_suppressed = load_baseline_matcher(str(baseline_path))
        assert is_suppressed(same)

    def test_new_baseline_uses_current_schema(self, tmp_path):
        finding = _finding()
        baseline_path = tmp_path / "baseline.json"
        write_baseline(str(baseline_path), [finding])
        payload = json.loads(baseline_path.read_text(encoding="utf-8"))
        assert payload["schema_version"] == CURRENT_SCHEMA

    def test_v1_baseline_loads_correctly(self, tmp_path):
        finding = _finding()
        baseline_path = tmp_path / "baseline.json"
        payload = build_baseline([finding], schema_version="1.0.0")
        baseline_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        known = load_baseline(str(baseline_path))
        assert fingerprint_v1(finding) in known

    def test_new_baseline_uses_v2_fingerprints(self, tmp_path):
        finding = _finding()
        baseline_path = tmp_path / "baseline.json"
        write_baseline(str(baseline_path), [finding])
        known = load_baseline(str(baseline_path))
        assert fingerprint_v2(finding) in known

    def test_description_change_requires_regeneration(self, tmp_path):
        """When description changes, user must regenerate baseline for v1→v2."""
        old = _finding(description="Old wording.")
        new = _finding(description="New wording — improved clarity.")

        baseline_path = tmp_path / "baseline.json"
        payload = build_baseline([old], schema_version="1.0.0")
        baseline_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        is_suppressed = load_baseline_matcher(str(baseline_path))
        # v1 fingerprint differs because description changed.
        # v2 fingerprint also won't match v1-stored fingerprints.
        # User must regenerate the baseline.
        assert not is_suppressed(new)

    def test_multiple_findings_on_same_location_produce_unique(self):
        f1 = _finding(rule_id="FIRE001", path="/x/{y}")
        f2 = _finding(
            rule_id="FIRE002", path="/x/{y}", condition="request.auth != null"
        )
        assert fingerprint_v2(f1) != fingerprint_v2(f2)
