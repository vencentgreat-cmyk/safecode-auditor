import re
import os

# Rule library: each rule is (rule_name, regex_pattern)
RULES = [
    ("OpenAI API Key",     r"sk-[a-zA-Z0-9]{20,}"),
    ("AWS Access Key",     r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key",     r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("GitHub Token",       r"ghp_[a-zA-Z0-9]{36}"),
    ("Hardcoded Password", r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]"),
    ("Database URL",       r"(?i)(mongodb|mysql|postgres)://\S+:\S+@"),
]

def scan_file(filepath):
    """Scan a single file and return a list of findings"""
    findings = []
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        return findings

    for line_num, line in enumerate(lines, start=1):
        for rule_name, pattern in RULES:
            if re.search(pattern, line):
                findings.append({
                    "file": filepath,
                    "line": line_num,
                    "rule": rule_name,
                    "content": line.strip()
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