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
   