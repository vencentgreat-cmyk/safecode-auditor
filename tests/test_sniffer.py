import sys
import os

# Add the project root to the path so we can import scanner
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.secret_sniffer import scan_file

# Get the path to our test target file
BAD_CONFIG = os.path.join(os.path.dirname(__file__), "..", "test_targets", "bad_config.py")

def test_detects_aws_access_key():
    findings = scan_file(BAD_CONFIG)
    rules_found = [f["rule"] for f in findings]
    assert "AWS Access Key" in rules_found, "Should detect AWS Access Key"

def test_detects_aws_secret_key():
    findings = scan_file(BAD_CONFIG)
    rules_found = [f["rule"] for f in findings]
    assert "AWS Secret Key" in rules_found, "Should detect AWS Secret Key"

def test_detects_hardcoded_password():
    findings = scan_file(BAD_CONFIG)
    rules_found = [f["rule"] for f in findings]
    assert "Hardcoded Password" in rules_found, "Should detect hardcoded password"

def test_detects_database_url():
    findings = scan_file(BAD_CONFIG)
    rules_found = [f["rule"] for f in findings]
    assert "Database URL" in rules_found, "Should detect database URL"

def test_detects_github_token():
    findings = scan_file(BAD_CONFIG)
    rules_found = [f["rule"] for f in findings]
    assert "GitHub Token" in rules_found, "Should detect GitHub token"

def test_clean_file_has_no_findings():
    """A file with no secrets should return zero findings"""
    # Write a temporary clean file and scan it
    clean_path = os.path.join(os.path.dirname(__file__), "temp_clean.py")
    with open(clean_path, "w") as f:
        f.write("def hello():\n    print('Hello, world!')\n")
    
    findings = scan_file(clean_path)
    os.remove(clean_path)  # Clean up after test
    
    assert len(findings) == 0, "Clean file should have no findings"