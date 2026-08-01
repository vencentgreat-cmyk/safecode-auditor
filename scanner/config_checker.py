import os
import re

# Rules for configuration files: (rule_name, regex_pattern, fix_suggestion)
CONFIG_RULES = [
    (
        "Exposed ENV Secret",
        r"(?i)^(SECRET_KEY|API_KEY|ACCESS_TOKEN|AUTH_TOKEN)\s*=\s*.{4,}",
        "Add .env to your .gitignore immediately. Load secrets with python-dotenv or os.getenv()",
    ),
    (
        "Exposed Database URL",
        r"(?i)^(DATABASE_URL|DB_URL)\s*=\s*(mongodb|mysql|postgres)://\S+:\S+@",
        "Never commit .env files. Add .env to .gitignore and use environment variables in production",
    ),
    (
        "Exposed Password in ENV",
        r"(?i)^(PASSWORD|PASSWD|DB_PASS|DB_PASSWORD)\s*=\s*.{4,}",
        "Add .env to .gitignore. Use a secrets manager like AWS Secrets Manager or HashiCorp Vault in production",
    ),
    (
        "Docker Hardcoded Password",
        r"(?i)(MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|DB_PASSWORD)\s*:\s*\S+",
        "Use Docker secrets or environment variables: replace value with ${DB_PASSWORD} and set in .env",
    ),
    (
        "Docker Hardcoded Secret",
        r"(?i)(SECRET_KEY|API_KEY)\s*:\s*\S+",
        "Use Docker secrets: replace hardcoded value with ${SECRET_KEY} and inject at runtime",
    ),
]

# Firebase dangerous rule patterns: (regex, rule_name, fix_suggestion)
FIREBASE_DANGER_PATTERNS = [
    (
        r'"\.read"\s*:\s*"true"',
        "Firebase: Unrestricted read access",
        'Replace ".read": "true" with ".read": "auth != null" to require authentication',
    ),
    (
        r'"\.write"\s*:\s*"true"',
        "Firebase: Unrestricted write access",
        'Replace ".write": "true" with ".write": "auth != null" to require authentication',
    ),
    (
        r'"read"\s*:\s*"true"',
        "Firebase: Unrestricted read access",
        'Replace "read": "true" with "read": "auth != null" to require authentication',
    ),
    (
        r'"write"\s*:\s*"true"',
        "Firebase: Unrestricted write access",
        'Replace "write": "true" with "write": "auth != null" to require authentication',
    ),
]


def scan_config_file(filepath):
    """Scan a single config file for dangerous settings"""
    findings = []
    filename = os.path.basename(filepath).lower()

    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
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
                    findings.append(
                        {
                            "file": filepath,
                            "line": line_num,
                            "rule": rule_name,
                            "content": line_stripped,
                            "fix": fix,
                        }
                    )

    # Scan docker-compose files
    elif "docker-compose" in filename:
        for line_num, line in enumerate(lines, start=1):
            for rule_name, pattern, fix in CONFIG_RULES:
                if re.search(pattern, line):
                    findings.append(
                        {
                            "file": filepath,
                            "line": line_num,
                            "rule": rule_name,
                            "content": line.strip(),
                            "fix": fix,
                        }
                    )

    # Scan Firebase rules
    elif "firebase" in filename or filename == "database.rules.json":
        findings.extend(_scan_firebase_rules(filepath, content))

    return findings


def scan_config_directory(directory):
    """Scan entire directory for dangerous config files"""
    if os.path.isfile(directory):
        return scan_config_file(directory)

    all_findings = []
    target_files = {
        ".env",
        "docker-compose.yml",
        "docker-compose.yaml",
        "database.rules.json",
        "firebase.json",
    }

    for root, dirs, files in os.walk(directory):
        dirs[:] = sorted(d for d in dirs if d not in ["node_modules", ".git", "__pycache__"])

        for filename in sorted(files):
            if filename.lower() in target_files or filename.endswith(".env"):
                filepath = os.path.join(root, filename)
                findings = scan_config_file(filepath)
                all_findings.extend(findings)

    return all_findings


# ── Firebase rules helpers ──────────────────────────────────────────────────


# Keys in Firebase Realtime Database rules whose value ``"true"`` grants
# unrestricted access. Kept as a mapping so that a single lookup gives
# both the rule name and the fix suggestion for a matched key.
_FIREBASE_DANGEROUS_KEY_RULES = {
    ".read": (
        "Firebase: Unrestricted read access",
        'Replace ".read": "true" with ".read": "auth != null" to require authentication',
    ),
    ".write": (
        "Firebase: Unrestricted write access",
        'Replace ".write": "true" with ".write": "auth != null" to require authentication',
    ),
    "read": (
        "Firebase: Unrestricted read access",
        'Replace "read": "true" with "read": "auth != null" to require authentication',
    ),
    "write": (
        "Firebase: Unrestricted write access",
        'Replace "write": "true" with "write": "auth != null" to require authentication',
    ),
}


def _scan_firebase_rules(filepath, content):
    """Return findings for dangerous Firebase Rules keys with source positions.

    Runs two passes over the file:

    1. The whole-file dangerous-key scan (``.read: "true"`` etc.), which
       relies on the JSON locator for accurate positions.
    2. The permission-inheritance analysis (:mod:`scanner.rtdb_inheritance`),
       which flags descendant rules made ineffective by a permissive
       ancestor.

    Falls back to the legacy whole-file regex match when the input is
    not well-formed JSON, so that malformed but still-suspicious rules
    files continue to be flagged (with ``line`` reported as ``"N/A"``).
    """
    from scanner.json_locator import JsonScanError, scan_json_string_values
    from scanner.rtdb_inheritance import analyze_inheritance
    from scanner.rtdb_tree import build_rtdb_tree

    findings = []
    try:
        entries = scan_json_string_values(content)
    except JsonScanError:
        return _scan_firebase_rules_legacy(filepath, content)

    # Pass 1: dangerous keys with permissive constant values.
    for entry in entries:
        if entry.value != "true":
            continue
        rule = _FIREBASE_DANGEROUS_KEY_RULES.get(entry.key)
        if rule is None:
            continue
        rule_name, fix = rule
        findings.append(
            {
                "file": filepath,
                "line": entry.line,
                "column": entry.column,
                "rule": rule_name,
                "content": "Dangerous rule detected in Firebase config",
                "fix": fix,
            }
        )

    # Pass 2: permission inheritance.
    tree = build_rtdb_tree(entries)
    for inheritance in analyze_inheritance(tree):
        findings.append(_inheritance_to_finding(filepath, inheritance))

    return findings


def _inheritance_to_finding(filepath, inheritance):
    """Convert an ``InheritanceFinding`` into the config_checker dict shape."""
    child = _format_path(inheritance.child_path) or "the rules root"
    ancestor = _format_path(inheritance.ancestor_path) or "the rules root"
    kind = inheritance.kind
    child_line = inheritance.child_expr.line
    ancestor_line = inheritance.ancestor_expr.line
    ancestor_expr_text = inheritance.ancestor_expr.expression.strip()

    content = (
        f"'.{kind}' at {child} is overridden by a permissive '.{kind}' at "
        f"{ancestor} (line {ancestor_line}): the ancestor "
        f"'{ancestor_expr_text}' already grants access, so the child rule "
        f"cannot restrict it."
    )
    fix = (
        f"Tighten the ancestor '.{kind}' rule at line {ancestor_line} so "
        f"the child rule at line {child_line} can actually enforce "
        f"access control."
    )
    return {
        "file": filepath,
        "line": child_line,
        "column": inheritance.child_expr.column,
        "rule": "Firebase: Overridden child rule under permissive ancestor",
        "content": content,
        "fix": fix,
    }


def _format_path(path):
    """Render a tuple JSON path as a human-readable slash string."""
    return "/".join(path)


def _scan_firebase_rules_legacy(filepath, content):
    """Whole-file regex fallback for malformed JSON."""
    findings = []
    for pattern, rule_name, fix in FIREBASE_DANGER_PATTERNS:
        if re.search(pattern, content):
            findings.append(
                {
                    "file": filepath,
                    "line": "N/A",
                    "rule": rule_name,
                    "content": "Dangerous rule detected in Firebase config",
                    "fix": fix,
                }
            )
    return findings
