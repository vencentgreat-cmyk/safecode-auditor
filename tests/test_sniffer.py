import sys
import os

# Add the project root to the path so we can import scanner
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.secret_sniffer import scan_file
from scanner.config_checker import scan_config_file, scan_config_directory

# Paths to test target files
BAD_CONFIG = os.path.join(os.path.dirname(__file__), "..", "test_targets", "bad_config.py")
ENV_FILE = os.path.join(os.path.dirname(__file__), "..", "test_targets", ".env")
DOCKER_FILE = os.path.join(os.path.dirname(__file__), "..", "test_targets", "docker-compose.yml")
FIREBASE_FILE = os.path.join(os.path.dirname(__file__), "..", "test_targets", "firebase.json")

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
    clean_path = os.path.join(os.path.dirname(__file__), "temp_clean.py")
    with open(clean_path, "w") as f:
        f.write("def hello():\n    print('Hello, world!')\n")
    findings = scan_file(clean_path)
    os.remove(clean_path)
    assert len(findings) == 0, "Clean file should have no findings"

def test_detects_openai_key():
    findings = scan_file(BAD_CONFIG)
    rules_found = [f["rule"] for f in findings]
    assert "OpenAI API Key" in rules_found, "Should detect OpenAI API Key"

def test_detects_env_secret_key():
    findings = scan_config_file(ENV_FILE)
    rules_found = [f["rule"] for f in findings]
    assert "Exposed ENV Secret" in rules_found, "Should detect exposed SECRET_KEY in .env"

def test_detects_env_password():
    findings = scan_config_file(ENV_FILE)
    rules_found = [f["rule"] for f in findings]
    assert "Exposed Password in ENV" in rules_found, "Should detect exposed password in .env"

def test_detects_docker_password():
    findings = scan_config_file(DOCKER_FILE)
    rules_found = [f["rule"] for f in findings]
    assert "Docker Hardcoded Password" in rules_found, "Should detect hardcoded password in docker-compose"

def test_detects_firebase_unrestricted_read():
    findings = scan_config_file(FIREBASE_FILE)
    rules_found = [f["rule"] for f in findings]
    assert "Firebase: Unrestricted read access" in rules_found, "Should detect Firebase open read rule"

def test_detects_firebase_unrestricted_write():
    findings = scan_config_file(FIREBASE_FILE)
    rules_found = [f["rule"] for f in findings]
    assert "Firebase: Unrestricted write access" in rules_found, "Should detect Firebase open write rule"
from scanner.firebase_analyzer import FirebaseRuleAnalyzer, scan_firebase_file

# Paths to firebase test samples
OPEN_ACCESS_RULES = os.path.join(os.path.dirname(__file__), "..", "test_targets", "open_access.rules")
AUTH_NO_OWNER_RULES = os.path.join(os.path.dirname(__file__), "..", "test_targets", "auth_no_owner.rules")
WEAK_UID_RULES = os.path.join(os.path.dirname(__file__), "..", "test_targets", "weak_uid.rules")

def test_firebase_detects_open_access():
    findings = scan_firebase_file(OPEN_ACCESS_RULES)
    vuln_types = [f["vuln_type"] for f in findings]
    assert "OpenAccess" in vuln_types, "Should detect OpenAccess in open_access.rules"

def test_firebase_detects_auth_but_no_owner():
    findings = scan_firebase_file(AUTH_NO_OWNER_RULES)
    vuln_types = [f["vuln_type"] for f in findings]
    assert "AuthButNoOwner" in vuln_types, "Should detect AuthButNoOwner pattern"

def test_firebase_detects_weak_uid_check():
    findings = scan_firebase_file(WEAK_UID_RULES)
    vuln_types = [f["vuln_type"] for f in findings]
    assert "WeakUidCheck" in vuln_types, "Should detect WeakUidCheck pattern"

def test_firebase_clean_rules_no_findings():
    """Well-written rules should pass cleanly"""
    analyzer = FirebaseRuleAnalyzer()
    clean_rules = """
    rules_version = '2';
    service cloud.firestore {
      match /databases/{database}/documents {
        match /users/{userId} {
          allow read, write: if request.auth != null && request.auth.uid == userId;
        }
      }
    }
    """
    findings = analyzer.analyze(clean_rules, "clean.rules")
    assert len(findings) == 0, "Clean rules should have no findings"