from safecode_auditor.core.models import Finding
from safecode_auditor.parsing.comments import strip_comments_preserve_offsets
from scanner.firebase_analyzer import FirebaseRuleAnalyzer


def test_comment_stripping_preserves_length_and_newline_offsets():
    source = (
        'let url = "https://example.test/path"; // trailing comment\n'
        "/* block\ncomment */\n"
        "allow read: if true;\n"
    )
    cleaned = strip_comments_preserve_offsets(source)

    assert len(cleaned) == len(source)
    assert [
        index for index, char in enumerate(cleaned) if char == "\n"
    ] == [index for index, char in enumerate(source) if char == "\n"]
    assert '"https://example.test/path"' in cleaned
    assert "trailing comment" not in cleaned
    assert "block" not in cleaned


def test_finding_has_reliable_line_column_and_stable_rule_id():
    source = (
        "rules_version = '2';\n"
        "/* a comment\n"
        "   across lines */\n"
        "match /users/{userId} {\n"
        "  allow read: if true;\n"
        "}\n"
    )

    finding = FirebaseRuleAnalyzer().analyze(source, "firestore.rules")[0]

    assert isinstance(finding, Finding)
    assert finding.rule_id == "FIRE001"
    assert finding.location.start_line == 5
    assert finding.location.start_column == 3
    assert finding["line"] == 5


def test_nested_match_rule_uses_absolute_source_location():
    source = (
        "service cloud.firestore {\n"
        "  match /databases/{database}/documents {\n"
        "    match /users/{userId} {\n"
        "      match /private/{docId} {\n"
        "        allow read: if true;\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n"
    )

    finding = FirebaseRuleAnalyzer().analyze(source)[0]

    assert finding.path == "/private/{docId}"
    assert finding.location.start_line == 5
    assert finding.location.start_column == 9


def test_ast_fallback_finding_has_low_confidence():
    source = """
    match /users/{userId} {
      allow read: if request.auth != null && invalid ???;
    }
    """

    finding = FirebaseRuleAnalyzer().analyze(source)[0]

    assert finding.rule_id == "FIRE002"
    assert finding.confidence.value == "LOW"


def test_all_four_firebase_rules_have_stable_ids():
    cases = {
        "allow read: if true;": "FIRE001",
        "allow read: if request.auth != null;": "FIRE002",
        "allow write: if request.auth != null;": "FIRE003",
        "allow read: if request.auth.uid != null;": "FIRE004",
    }
    for rule, expected in cases.items():
        source = f"match /users/{{userId}} {{ {rule} }}"
        finding = FirebaseRuleAnalyzer().analyze(source)[0]
        assert finding.rule_id == expected
