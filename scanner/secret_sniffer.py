import re
import os

# Rule library: (rule_name, regex_pattern, fix_suggestion)
RULES = [
    (
        "OpenAI API Key",
        r"sk-[a-zA-Z0-9-_]{20,}",
        "Move to environment variable: OPENAI_API_KEY=your_key in .env, then use os.getenv('OPENAI_API_KEY')"
    ),
    (
        "AWS Access Key",
        r"AKIA[0-9A-Z]{16}",
        "Move to environment variable: AWS_ACCESS_KEY_ID=your_key in .env, then use os.getenv('AWS_ACCESS_KEY_ID')"
    ),
    (
        "AWS Secret Key",
        r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "Move to environment variable: AWS_SECRET_ACCESS_KEY=your_key in .env, never hardcode AWS credentials"
    ),
    (
        "GitHub Token",
        r"ghp_[a-zA-Z0-9]{36}",
        "Move to environment variable: GITHUB_TOKEN=your_token in .env, then use os.getenv('GITHUB_TOKEN')"
    ),
    (
        "Hardcoded Password",
        r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
        "Move to environment variable: DB_PASSWORD=your_password in .env, then use os.getenv('DB_PASSWORD')"
    ),
    (
        "Database URL",
        r"(?i)(mongodb|mysql|postgres)://\S+:\S+@",
        "Move to environment variable: DATABASE_URL=your_url in .env, then use os.getenv('DATABASE_URL')"
    ),
    (
        "Generic Secret",
        r"(?i)(secret|api_key|access_token)\s*=\s*['\"][^'\"]{8,}['\"]",
        "Move all secrets to .env file and load with python-dotenv or os.getenv()"
    ),
]

def scan_file(filepath):
    """Scan a single file and return a list of findings"""
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    for line_num, line in enumerate(lines, start=1):
        for rule_name, pattern, fix in RULES:
            if re.search(pattern, line):
                findings.append({
                    "file": filepath,
                    "line": line_num,
                    "rule": rule_name,
                    "content": line.strip(),
                    "fix": fix
                })

    return findings


def scan_directory(directory):
    """Recursively scan an entire directory for security issues"""
    all_findings = []
    extensions = (".py", ".js", ".ts", ".env", ".json", ".yml", ".yaml")

    for root, dirs, files in os.walk(directory):
        # Skip directories that don't need scanning
        dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", "__pycache__"]]

        for filename in files:
            if filename.endswith(extensions):
                filepath = os.path.join(root, filename)
                findings = scan_file(filepath)
                all_findings.extend(findings)

    return all_findings