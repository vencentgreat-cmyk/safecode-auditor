import re
import os

# Rules for configuration files: (rule_name, regex_pattern, fix_suggestion)
CONFIG_RULES = [
    (
        "Exposed ENV Secret",
        r"(?i)^(SECRET_KEY|API_KEY|ACCESS_TOKEN|AUTH_TOKEN)\s*=\s*.{4,}",
        "Add .env to your .gitignore immediately. Load secrets with python-dotenv or os.getenv()"
    ),
    (
        "Exposed Database URL",
        r"(?i)^(DATABASE_URL|DB_URL)\s*=\s*(mongodb|mysql|postgres)://\S+:\S+@",
        "Never commit .env files. Add .env to .gitignore and use environment variables in production"
    ),
    (
        "Exposed Password in ENV",
        r"(?i)^(PASSWORD|PASSWD|DB_PASS|DB_PASSWORD)\s*=\s*.{4,}",
        "Add .env to .gitignore. Use a secrets manager like AWS Secrets Manager or HashiCorp Vault in production"
    ),
    (
        "Docker Hardcoded Password",
        r"(?i)(MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|DB_PASSWORD)\s*:\s*\S+",
        "Use Docker secrets or environment variables: replace value with ${DB_PASSWORD} and set in .env"
    ),
    (
        "Docker Hardcoded Secret",
        r"(?i)(SECRET_KEY|API_KEY)\s*:\s*\S+",
        "Use Docker secrets: replace hardcoded value with ${SECRET_KEY} and inject at runtime"
    ),
]

# Firebase dangerous rule patterns: (regex, rule_name, fix_suggestion)
FIREBASE_DANGER_PATTERNS = [
    (
        r'"\.read"\s*:\s*"true"',
        "Firebase: Unrestricted read access",
        'Replace ".read": "true" with ".read": "auth != null" to require authentication'
    ),
    (
        r'"\.write"\s*:\s*"true"',
        "Firebase: Unrestricted write access",
        'Replace ".write": "true" with ".write": "auth != null" to require authentication'
    ),
    (
        r'"read"\s*:\s*"true"',
        "Firebase: Unrestricted read access",
        'Replace "read": "true" with "read": "auth != null" to require authentication'
    ),
    (
        r'"write"\s*:\s*"true"',
        "Firebase: Unrestricted write access",
        'Replace "write": "true" with "write": "auth != null" to require authentication'
    ),
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
            line_stripped = line.strip()
            if line_stripped.startswith("#") or not line_stripped:
                continue
            for rule_name, pattern, fix in CONFIG_RULES:
                if re.search(pattern, line_stripped):
                    findings.append({
                        "file": filepath,
                        "line": line_num,
                        "rule": rule_name,
                        "content": line_stripped,
                        "fix": fix
                    })

    # Scan docker-compose files
    elif "docker-compose" in filename:
        for line_num, line in enumerate(lines, start=1):
            for rule_name, pattern, fix in CONFIG_RULES:
                if re.search(pattern, line):
                    findings.append({
                        "file": filepath,
                        "line": line_num,
                        "rule": rule_name,
                        "content": line.strip(),
                        "fix": fix
                    })

    # Scan Firebase rules
    elif "firebase" in filename or filename == "database.rules.json":
        for pattern, rule_name, fix in FIREBASE_DANGER_PATTERNS:
            if re.search(pattern, content):
                findings.append({
                    "file": filepath,
                    "line": "N/A",
                    "rule": rule_name,
                    "content": "Dangerous rule detected in Firebase config",
                    "fix": fix
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