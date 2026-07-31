from scanner.firebase_analyzer import FirebaseRuleAnalyzer
def test_owner_check_detected_as_safe():
    rules = """
    match /users/{userId} {
      allow read: if request.auth.uid == userId;
    }
    """
    analyzer = FirebaseRuleAnalyzer()
    findings = analyzer.analyze(rules)

    assert len(findings) == 0
def test_owner_check_reverse_order():
    rules = """
    match /users/{userId} {
      allow read: if userId == request.auth.uid;
    }
    """
    analyzer = FirebaseRuleAnalyzer()
    findings = analyzer.analyze(rules)

    assert len(findings) == 0
def test_weak_uid_check():
    rules = """
    match /users/{userId} {
      allow read: if request.auth.uid != null;
    }
    """
    analyzer = FirebaseRuleAnalyzer()
    findings = analyzer.analyze(rules)

    vuln_types = [f["vuln_type"] for f in findings]
    assert "WeakUidCheck" in vuln_types
def test_write_with_validation():
    rules = """
    match /posts/{postId} {
      allow write: if request.auth != null
                   && request.resource.data.keys().hasOnly(['title']);
    }
    """
    analyzer = FirebaseRuleAnalyzer()
    findings = analyzer.analyze(rules)

    assert len(findings) == 0 
def test_invalid_expression_does_not_crash():
    rules = """
    match /users/{userId} {
      allow read: if request.auth != ???;
    }
    """
    analyzer = FirebaseRuleAnalyzer()
    findings = analyzer.analyze(rules)

    assert isinstance(findings, list)
def test_owner_check_via_resource_data_ownerid_is_safe():
    rules = """
    match /users/{userId} {
      allow read: if request.auth != null && request.auth.uid == resource.data.ownerId;
    }
    """
    analyzer = FirebaseRuleAnalyzer()
    findings = analyzer.analyze(rules)

    assert len(findings) == 0
def test_owner_check_via_resource_data_ownerid_reverse_order_is_safe():
    rules = """
    match /users/{userId} {
      allow read: if request.auth != null && resource.data.ownerId == request.auth.uid;
    }
    """
    analyzer = FirebaseRuleAnalyzer()
    findings = analyzer.analyze(rules)

    assert len(findings) == 0
def test_authenticated_read_on_generic_user_wildcard_requires_owner_check():
    rules = """
    match /users/{id} {
      allow read: if request.auth != null;
    }
    """
    findings = FirebaseRuleAnalyzer().analyze(rules)

    vuln_types = [finding["vuln_type"] for finding in findings]
    assert "AuthButNoOwner" in vuln_types


def test_owner_check_or_true_is_open_access():
    rules = """
    match /users/{userId} {
      allow read: if request.auth.uid == userId || true;
    }
    """
    findings = FirebaseRuleAnalyzer().analyze(rules)

    vuln_types = [finding["vuln_type"] for finding in findings]
    assert "OpenAccess" in vuln_types


def test_negated_owner_check_is_not_treated_as_safe():
    rules = """
    match /users/{userId} {
      allow read: if !(request.auth.uid == userId);
    }
    """
    findings = FirebaseRuleAnalyzer().analyze(rules)

    assert findings != []


def test_request_data_presence_is_not_write_validation():
    rules = """
    match /posts/{postId} {
      allow write: if request.auth != null
                   && request.resource.data != null;
    }
    """
    findings = FirebaseRuleAnalyzer().analyze(rules)

    vuln_types = [finding["vuln_type"] for finding in findings]
    assert "WriteWithoutValidation" in vuln_types   
def test_owner_check_or_auth_only_does_not_guarantee_ownership():
    rules = """
    match /users/{userId} {
      allow read: if request.auth.uid == userId
                  || request.auth != null;
    }
    """
    findings = FirebaseRuleAnalyzer().analyze(rules)

    vuln_types = [finding["vuln_type"] for finding in findings]
    assert "AuthButNoOwner" in vuln_types


def test_owner_check_on_both_or_branches_is_safe():
    rules = """
    match /users/{userId} {
      allow read: if request.auth.uid == userId
                  || userId == request.auth.uid;
    }
    """
    findings = FirebaseRuleAnalyzer().analyze(rules)

    assert findings == []


def test_validation_on_only_one_or_branch_is_not_guaranteed():
    rules = """
    match /posts/{postId} {
      allow write: if (
        request.auth != null
        && request.resource.data.keys().hasOnly(["title"])
      ) || request.auth != null;
    }
    """
    findings = FirebaseRuleAnalyzer().analyze(rules)

    vuln_types = [finding["vuln_type"] for finding in findings]
    assert "WriteWithoutValidation" in vuln_types


def test_negated_validation_is_not_treated_as_safe():
    rules = """
    match /posts/{postId} {
      allow write: if request.auth != null
                   && !request.resource.data.keys().hasOnly(["title"]);
    }
    """
    findings = FirebaseRuleAnalyzer().analyze(rules)

    vuln_types = [finding["vuln_type"] for finding in findings]
    assert "WriteWithoutValidation" in vuln_types