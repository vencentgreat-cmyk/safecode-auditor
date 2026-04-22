import re
import os

# Rules specifically for configuration files
CONFIG_RULES = [
    ("Exposed ENV Secret",      r"(?i)^(SECRET_KEY|API_KEY|ACCESS_TOKEN|AUTH_TOKEN)\s*=\s*.{4,}"),
    ("Exposed Database URL",    r"(?i)^(DATABASE_URL|DB_URL)\s*=\s*(mongodb|mysql|postgres)://\S+:\S+@"),
    ("Exposed Password in ENV", r"(?i)^(PASSWORD|PASSWD|DB_PASS|DB_PASSWORD)\s*=\s*.{4,}"),
    ("Docker Hardcoded Password", r"(?i)(MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|DB_PASSWORD)\s*:\s*\S+"),
    ("Docker Hardcoded Secret",   r"(?i)(SECRET_KEY|API_KEY)\s*:\s*\S+"),
]

# Firebase-style dangerous rules
FIREBASE_DANGER_PATTERNS = [
    (r'"\.read"\s*:\s*"true"',  "Firebase: Unrestricted read access"),
    (r'"\.write"\s*:\s*"true"', "Firebase: Unrestricted write access"),
    (r'"read"\s*:\s*"true"',    "Firebase: Unrestricted read access"),
    (r'"write"\s*:\s*"true"',   "Firebase: Unrestricted write access"),
]

def scan_config_file(filepath):
    """Scan a single config file for dangerous settings"""
    findings = []
    filename = os.path.basename(filepath).lower()

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            content = "".join(lines)
    except Exception:
        return findings

    # Scan .env files line by line
    if filename == ".env" or filename.endswith(".env"):
        for line_num, line in enumerate(lines, start=1):
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            for rule_name, pattern in CONFIG_RULES:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": line_num,
                        "rule": rule_name,
                        "content": line
                    })

    # Scan docker-compose files
    elif "docker-compose" in filename:
        for line_num, line in enumerate(lines, start=1):
            for rule_name, pattern in CONFIG_RULES:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": line_num,
                        "rule": rule_name,
                        "content": line.strip()
                    })

    # Scan Firebase rules (JSON)
    elif "firebase" in filename or filename == "database.rules.json":
        for pattern, rule_name in FIREBASE_DANGER_PATTERNS:
            if re.search(pattern, content):
                findings.append({
                    "file": filepath,
                    "line": "N/A",
                    "rule": rule_name,
                    "content": "Dangerous rule detected in Firebase config"
                })

    return findings


def scan_config_directory(directory):
    """Scan entire directory for dangerous config files"""
    all_findings = []
    target_files = {".env", "docker-compose.yml", "docker-compose.yaml",
                    "database.rules.json", "firebase.json"}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", "__pycache__"]]

        for filename in files:
            if filename.lower() in target_files or filename.endswith(".env"):
                filepath = os.path.join(root, filename)
                findings = scan_config_file(filepath)
                all_findings.extend(findings)

    return all_findings