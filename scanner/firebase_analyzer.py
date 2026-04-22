import re
import os

# ── Vulnerability pattern definitions ──────────────────────────────────────────
VULN_PATTERNS = {
    "OpenAccess": {
        "severity": "CRITICAL",
        "description": "Collection is fully open to the public, no authentication required.",
        "explanation": "Using 'if true' allows anyone on the internet to read or write data without any credentials."
    },
    "AuthButNoOwner": {
        "severity": "HIGH",
        "description": "Authentication is required but any logged-in user can access all other users' data.",
        "explanation": "Checking 'request.auth != null' only verifies the user is logged in. It does NOT prevent user A from reading user B's private data."
    },
    "WriteWithoutValidation": {
        "severity": "HIGH",
        "description": "Write operation has no data validation.",
        "explanation": "Allowing writes without validating request.resource.data means users can write any data structure, including malicious payloads."
    },
    "WeakUidCheck": {
        "severity": "MEDIUM",
        "description": "UID check uses != null instead of == userId.",
        "explanation": "'request.auth.uid != null' only checks that a UID exists, not that it matches the resource owner. Any logged-in user passes this check."
    }
}


class MatchBlock:
    """Represents a single match block in Firebase Rules"""
    def __init__(self, path, wildcards, rules, children):
        self.path = path
        self.wildcards = wildcards
        self.rules = rules
        self.children = children

    def __repr__(self):
        return f"MatchBlock(path={self.path}, wildcards={self.wildcards}, rules={self.rules})"


class FirebaseRuleAnalyzer:
    """
    Parses Firebase Security Rules and detects logical vulnerabilities.
    Goes beyond simple keyword matching to understand rule structure and context.
    """

    def __init__(self):
        self.findings = []

    def parse(self, content):
        """Parse raw rules content into a list of MatchBlock trees"""
        content = re.sub(r'//[^\n]*', '', content)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        return self._parse_blocks(content)

    def _extract_block(self, content, start):
        """Extract content inside matching braces starting at position"""
        depth = 1
        i = start
        while i < len(content) and depth > 0:
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
            i += 1
        return content[start:i-1]

    def _parse_blocks(self, content):
        """Recursively parse all match blocks in content"""
        blocks = []
        pattern = re.compile(r'match\s+((?:/[\w{}\-=*]+)+)\s*\{')

        i = 0
        while i < len(content):
            m = pattern.search(content, i)
            if not m:
                break

            path = m.group(1)

            if '/databases/' in path and '/documents' in path:
                block_start = m.end()
                block_content = self._extract_block(content, block_start)
                blocks.extend(self._parse_blocks(block_content))
                i = m.end() + len(block_content)
                continue

            wildcards = re.findall(r'\{(\w+)(?:=\*\*)?\}', path)
            block_start = m.end()
            block_content = self._extract_block(content, block_start)

            rules = self._parse_rules(block_content)
            children = self._parse_blocks(block_content)

            blocks.append(MatchBlock(path, wildcards, rules, children))
            i = m.end() + len(block_content)

        return blocks

    def _parse_rules(self, content):
        """Extract allow rules from a block, ignoring nested match blocks"""
        clean = re.sub(r'match\s+/[^\{]+\{[^}]*\}', '', content, flags=re.DOTALL)

        rules = []
        pattern = re.compile(r'allow\s+([\w,\s]+)\s*:\s*if\s+(.+?);', re.DOTALL)

        for m in pattern.finditer(clean):
            operations = [op.strip() for op in m.group(1).split(',')]
            condition = m.group(2).strip()
            rules.append({"operations": operations, "condition": condition})

        bare = re.compile(r'allow\s+([\w,\s]+)\s*;')
        for m in bare.finditer(clean):
            operations = [op.strip() for op in m.group(1).split(',')]
            rules.append({"operations": operations, "condition": None})

        return rules

    def analyze(self, content, filepath="firestore.rules"):
        """Main entry point: parse and analyze a rules file"""
        self.findings = []
        blocks = self.parse(content)
        for block in blocks:
            self._analyze_block(block, filepath)
        return self.findings

    def _analyze_block(self, block, filepath):
        """Analyze a single MatchBlock for vulnerabilities"""
        for rule in block.rules:
            condition = rule["condition"]
            operations = rule["operations"]

            vuln = self._classify_condition(condition, block.wildcards, operations)
            if vuln:
                self.findings.append({
                    "file": filepath,
                    "path": block.path,
                    "operations": operations,
                    "condition": condition,
                    "vuln_type": vuln,
                    "severity": VULN_PATTERNS[vuln]["severity"],
                    "description": VULN_PATTERNS[vuln]["description"],
                    "explanation": VULN_PATTERNS[vuln]["explanation"],
                    "fix": self._generate_fix(block.path, block.wildcards, vuln, operations)
                })

        for child in block.children:
            self._analyze_block(child, filepath)

    def _classify_condition(self, condition, wildcards, operations):
        """Core logic engine: classify a condition into a vulnerability pattern"""
        if condition is None:
            return "OpenAccess"

        cond = condition.strip()
        if cond == "true":
            return "OpenAccess"

        # Normalize whitespace to handle inconsistent formatting from vibe coders
        cond_no_spaces = cond.replace(" ", "").replace("\n", "").replace("\t", "")

        if "request.auth.uid!=null" in cond_no_spaces:
            return "WeakUidCheck"

        has_auth = "request.auth" in cond_no_spaces
        has_owner = any(
            f"request.auth.uid=={w}" in cond_no_spaces or
            f"{w}==request.auth.uid" in cond_no_spaces
            for w in wildcards
        )
        is_user_path = any(
            keyword in " ".join(wildcards).lower()
            for keyword in ["user", "member", "account", "profile", "person"]
        )

        if has_auth and not has_owner and is_user_path:
            read_ops = {"read", "get", "list"}
            if any(op in read_ops for op in operations):
                return "AuthButNoOwner"

        write_ops = {"write", "create", "update"}
        if any(op in write_ops for op in operations):
                if has_auth and not has_owner and "request.resource.data" not in cond_no_spaces:
                    return "WriteWithoutValidation"

        return None

    def _generate_fix(self, path, wildcards, vuln_type, operations):
        """Generate recommended fix code based on path context and vuln type"""
        uid_var = wildcards[-1] if wildcards else "userId"

        if vuln_type == "OpenAccess":
            return f"""Replace 'if true' with an authentication check:
  allow read: if request.auth != null && request.auth.uid == {uid_var};"""

        if vuln_type == "AuthButNoOwner":
            return f"""Add owner check to bind the user to their own data:
  // Current (vulnerable):  if request.auth != null
  // Fixed:
  allow read: if request.auth != null && request.auth.uid == {uid_var};"""

        if vuln_type == "WeakUidCheck":
            return f"""Replace '!= null' with an equality check against the path variable:
  // Current (vulnerable):  if request.auth.uid != null
  // Fixed:
  allow read: if request.auth.uid == {uid_var};"""

        if vuln_type == "WriteWithoutValidation":
            return f"""Add data validation to write rules:
  allow write: if request.auth.uid == {uid_var}
               && request.resource.data.keys().hasOnly(['field1', 'field2']);"""

        return "Review this rule manually."


# ── Module-level entry points ──────────────────────────────────────────────────

def scan_firebase_file(filepath):
    """Entry point compatible with the rest of the scanner pipeline"""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return []

    analyzer = FirebaseRuleAnalyzer()
    return analyzer.analyze(content, filepath)


def scan_firebase_directory(directory):
    """Scan a directory for all Firebase rules files"""
    findings = []
    target_names = {"firestore.rules", "database.rules.json", "firebase.rules"}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ["node_modules", ".git", "__pycache__"]]
        for filename in files:
            if filename.lower() in target_names or filename.endswith(".rules"):
                filepath = os.path.join(root, filename)
                findings.extend(scan_firebase_file(filepath))

    return findings