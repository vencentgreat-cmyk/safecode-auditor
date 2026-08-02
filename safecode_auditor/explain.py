"""Maintainable rule documentation used by ``--explain`` and references.

This module is the canonical source for human-readable rule metadata.
Detector implementations remain in their respective scanner modules;
this module only describes what each rule means and how to fix it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    title: str
    severity: str
    category: str
    why_it_matters: str
    vulnerable_example: str
    safer_example: str
    limitations: str
    remediation: str
    suppression_guidance: str


def _firestore(name: str) -> str:
    return f"Firestore Security Rules — {name}"


def _rtdb(name: str) -> str:
    return f"Realtime Database Rules — {name}"


RULES: dict[str, RuleInfo] = {
    # ── Firestore ──────────────────────────────────────────────────
    "FIRE001": RuleInfo(
        rule_id="FIRE001",
        title="Public access is allowed",
        severity="CRITICAL",
        category=_firestore("Open Access"),
        why_it_matters=(
            "Anyone on the internet can read or write this data without "
            "any credentials. This is the most dangerous Firestore "
            "misconfiguration and is a common cause of data breaches."
        ),
        vulnerable_example=("match /public/{docId} {\n" "  allow read, write: if true;\n" "}"),
        safer_example=(
            "match /users/{userId} {\n"
            "  allow read, write: if request.auth != null\n"
            "    && request.auth.uid == userId;\n"
            "}"
        ),
        limitations=(
            "Public access to genuinely public content (e.g. a blog) "
            "may be intentional. Use --ignore-rule FIRE001 or a "
            "baseline to suppress accepted cases."
        ),
        remediation=(
            "Replace 'if true' or bare 'allow read;' with an "
            "authentication and ownership check. At minimum, require "
            "'request.auth != null'. For user-scoped data, add an "
            "ownership check: 'request.auth.uid == userId'."
        ),
        suppression_guidance=(
            "Use --ignore-rule FIRE001 only when you have verified the "
            "collection is intentionally public. Prefer a baseline for "
            "existing accepted open-access rules."
        ),
    ),
    "FIRE002": RuleInfo(
        rule_id="FIRE002",
        title="Authenticated users are not restricted to owned data",
        severity="HIGH",
        category=_firestore("Authorization"),
        why_it_matters=(
            "Any logged-in user can access all other users' private "
            "data. Checking 'request.auth != null' only verifies the "
            "user is logged in — it does not prevent user A from "
            "reading user B's data."
        ),
        vulnerable_example=(
            "match /users/{userId} {\n" "  allow read: if request.auth != null;\n" "}"
        ),
        safer_example=(
            "match /users/{userId} {\n"
            "  allow read: if request.auth != null\n"
            "    && request.auth.uid == userId;\n"
            "}"
        ),
        limitations=(
            "Only fires on paths containing 'user', 'member', 'account', "
            "'profile', or 'person' keywords. Custom function calls in "
            "the condition suppress this finding to avoid false "
            "positives on complex authorization logic."
        ),
        remediation=(
            "Add an ownership check that compares request.auth.uid "
            "against the resource path wildcard or a user identifier "
            "field in the document."
        ),
        suppression_guidance=(
            "Suppress only if the collection is intentionally shared "
            "among all authenticated users (e.g. a team-shared document "
            "set) and you have reviewed the access model."
        ),
    ),
    "FIRE003": RuleInfo(
        rule_id="FIRE003",
        title="Writes are accepted without data validation",
        severity="HIGH",
        category=_firestore("Data Integrity"),
        why_it_matters=(
            "Users can write any data structure, including malicious "
            "payloads, unexpected fields, or oversized values. Without "
            "validation, an attacker can corrupt your data model."
        ),
        vulnerable_example=(
            "match /posts/{postId} {\n" "  allow create: if request.auth != null;\n" "}"
        ),
        safer_example=(
            "match /posts/{postId} {\n"
            "  allow create: if request.auth != null\n"
            "    && request.resource.data.keys().hasOnly(\n"
            "      ['title', 'body']);\n"
            "}"
        ),
        limitations=(
            "Custom function calls in the condition suppress this "
            "finding. Only checks for recognised validation methods "
            "(hasOnly, hasAll, hasAny, size, matches) on "
            "request.resource.data."
        ),
        remediation=(
            "Add data validation to write rules using methods like "
            "hasOnly(), hasAll(), size(), or matches() on "
            "request.resource.data to constrain allowed fields and "
            "value types."
        ),
        suppression_guidance=(
            "Suppress only when validation is enforced through custom "
            "functions (not currently analysed) or when writes are "
            "admin-only through external mechanisms."
        ),
    ),
    "FIRE004": RuleInfo(
        rule_id="FIRE004",
        title="UID existence is used as authorization",
        severity="MEDIUM",
        category=_firestore("Authorization"),
        why_it_matters=(
            "Checking 'request.auth.uid != null' only verifies that "
            "a UID exists — it does not check that it matches the "
            "resource owner. Any logged-in user passes this check."
        ),
        vulnerable_example=(
            "match /users/{userId} {\n" "  allow read: if request.auth.uid != null;\n" "}"
        ),
        safer_example=(
            "match /users/{userId} {\n" "  allow read: if request.auth.uid == userId;\n" "}"
        ),
        limitations=(
            "Fires only when an explicit UID-null check exists. If the "
            "condition has an ownership check, FIRE004 is suppressed "
            "in favour of more specific findings."
        ),
        remediation=(
            "Replace 'request.auth.uid != null' with an equality check "
            "against the path wildcard or a document field representing "
            "the owner."
        ),
        suppression_guidance=(
            "Rarely appropriate to suppress. If suppressed, ensure "
            "ownership is enforced by a different rule in the same "
            "match block."
        ),
    ),
    # ── RTDB dangerous keys ─────────────────────────────────────────
    "CFG006": RuleInfo(
        rule_id="CFG006",
        title="Unrestricted read access",
        severity="HIGH",
        category=_rtdb("Open Access"),
        why_it_matters=(
            "The '.read' rule is set to 'true', granting read access "
            "to every Realtime Database node without authentication. "
            "This exposes all data at this path and below."
        ),
        vulnerable_example=("{\n" '  "rules": {\n' '    ".read": "true"\n' "  }\n" "}"),
        safer_example=(
            "{\n"
            '  "rules": {\n'
            '    ".read": "auth != null",\n'
            '    "users": {\n'
            '      "$uid": {\n'
            '        ".read": "$uid === auth.uid"\n'
            "      }\n"
            "    }\n"
            "  }\n"
            "}"
        ),
        limitations=(
            "Detects only the exact value 'true' (string or bare "
            "boolean). More complex expressions that evaluate to true "
            "are not detected. Public content may legitimately use "
            "open read access."
        ),
        remediation=(
            "Replace '\"true\"' with an authentication check like "
            "'auth != null'. For user-specific paths, add ownership "
            "checks using '$wildcard === auth.uid'."
        ),
        suppression_guidance=(
            "Use --ignore-rule CFG006 only when the path is "
            "intentionally public (e.g. a read-only content feed)."
        ),
    ),
    "CFG007": RuleInfo(
        rule_id="CFG007",
        title="Unrestricted write access",
        severity="HIGH",
        category=_rtdb("Open Access"),
        why_it_matters=(
            "The '.write' rule is set to 'true', allowing anyone to "
            "write to this database path without authentication. This "
            "can lead to data loss, corruption, or abuse."
        ),
        vulnerable_example=("{\n" '  "rules": {\n' '    ".write": true\n' "  }\n" "}"),
        safer_example=(
            "{\n"
            '  "rules": {\n'
            '    ".write": "auth != null",\n'
            '    "users": {\n'
            '      "$uid": {\n'
            '        ".write": "$uid === auth.uid"\n'
            "      }\n"
            "    }\n"
            "  }\n"
            "}"
        ),
        limitations=(
            "Same as CFG006: only exact 'true' values are detected. "
            "Compound expressions that evaluate to true are not caught."
        ),
        remediation=(
            "Replace '\"true\"' with authentication ('auth != null') "
            "and ownership checks. Never allow open write access to "
            "any production database path."
        ),
        suppression_guidance=(
            "Almost never appropriate to suppress. Open write access "
            "is rarely intentional in production."
        ),
    ),
    "CFG008": RuleInfo(
        rule_id="CFG008",
        title="Ineffective child rule under permissive ancestor",
        severity="HIGH",
        category=_rtdb("Permission Inheritance"),
        why_it_matters=(
            "Realtime Database rules cascade: once an ancestor grants "
            "'.read' or '.write', all descendants inherit that "
            "permission. A stricter rule on a child node cannot "
            "restrict what the ancestor already allowed. Developers "
            "often write an owner-check rule on a child node believing "
            "it protects that data, but if a permissive ancestor "
            "(e.g. 'auth != null') exists above, the child rule is "
            "ignored by Firebase."
        ),
        vulnerable_example=(
            "{\n"
            '  "rules": {\n'
            '    ".read": "auth != null",\n'
            '    "users": {\n'
            '      "$uid": {\n'
            '        ".read": "$uid === auth.uid"\n'
            "      }\n"
            "    }\n"
            "  }\n"
            "}"
        ),
        safer_example=(
            "{\n"
            '  "rules": {\n'
            '    "users": {\n'
            '      "$uid": {\n'
            '        ".read": "$uid === auth.uid"\n'
            "      }\n"
            "    }\n"
            "  }\n"
            "}"
        ),
        limitations=(
            "Only recognises five permissive ancestor patterns: 'true', "
            "'auth != null', 'auth !== null', 'auth.uid != null', and "
            "'auth.uid !== null'. Compound conditions or custom "
            "function calls that are also permissive are not detected "
            "(conservative by design to avoid false positives). "
            "Child owner checks must match the pattern '$wildcard == "
            "auth.uid' or 'auth.uid == $wildcard'."
        ),
        remediation=(
            "Tighten the ancestor rule so it does not inadvertently "
            "grant broad access, or move the restrictive child rule to "
            "a part of the tree not under a permissive ancestor. "
            "The finding message identifies both the child location "
            "and the ancestor location causing the override."
        ),
        suppression_guidance=(
            "Suppress only if the permissive ancestor is intentional "
            "and the child owner check is redundant (i.e., you "
            "understand the child rule has no effect). Better to "
            "fix the rules tree."
        ),
    ),
    # ── Secrets ─────────────────────────────────────────────────────
    "SEC001": RuleInfo(
        rule_id="SEC001",
        title="OpenAI API Key",
        severity="HIGH",
        category="Source Code — Hardcoded Secret",
        why_it_matters="Exposed API keys can be used by attackers to make requests on your behalf, incurring costs.",
        vulnerable_example='OPENAI_API_KEY = "sk-proj-abcdef..."',
        safer_example="OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')",
        limitations="Pattern-based; may match non-key strings that resemble API key formats.",
        remediation="Move to environment variable, load with os.getenv(), and add to .gitignore.",
        suppression_guidance="Suppress only after rotating the key and confirming it is a false positive.",
    ),
    "SEC002": RuleInfo(
        rule_id="SEC002",
        title="AWS Access Key",
        severity="HIGH",
        category="Source Code — Hardcoded Secret",
        why_it_matters="Exposed AWS keys grant access to your cloud resources.",
        vulnerable_example='AWS_ACCESS_KEY_ID = "AKIA..."',
        safer_example="AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')",
        limitations="Pattern matches AKIA prefix; false positives on documentation or test fixtures possible.",
        remediation="Rotate the key immediately, move to environment variable, and check CloudTrail for unauthorized use.",
        suppression_guidance="Only suppress after rotating and confirming no exposure.",
    ),
    "SEC003": RuleInfo(
        rule_id="SEC003",
        title="AWS Secret Key",
        severity="HIGH",
        category="Source Code — Hardcoded Secret",
        why_it_matters="The AWS Secret Key paired with an Access Key grants full access to your AWS resources.",
        vulnerable_example='AWS_SECRET_ACCESS_KEY = "wJalrXUtn..."',
        safer_example="AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')",
        limitations="Pattern-based; context-insensitive.",
        remediation="Rotate immediately and move to environment variable.",
        suppression_guidance="Only suppress after rotation and verification.",
    ),
    "SEC004": RuleInfo(
        rule_id="SEC004",
        title="GitHub Token",
        severity="HIGH",
        category="Source Code — Hardcoded Secret",
        why_it_matters="Exposed GitHub tokens can be used to access your repositories and impersonate you.",
        vulnerable_example='GITHUB_TOKEN = "ghp_..."',
        safer_example="GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')",
        limitations="Matches ghp_ prefix pattern only.",
        remediation="Revoke the token immediately from GitHub settings and regenerate.",
        suppression_guidance="Suppress only after token revocation.",
    ),
    "SEC005": RuleInfo(
        rule_id="SEC005",
        title="Hardcoded Password",
        severity="HIGH",
        category="Source Code — Hardcoded Secret",
        why_it_matters="Passwords in source code are visible to anyone with repository access and persist in Git history.",
        vulnerable_example='DB_PASSWORD = "mysecretpassword"',
        safer_example="DB_PASSWORD = os.getenv('DB_PASSWORD')",
        limitations="Pattern-based; may match variable assignments that are not actually passwords.",
        remediation="Move to environment variable, rotate the password, and scrub Git history.",
        suppression_guidance="Suppress only when confirmed as a non-password string.",
    ),
    "SEC006": RuleInfo(
        rule_id="SEC006",
        title="Database URL with embedded credentials",
        severity="HIGH",
        category="Source Code — Hardcoded Secret",
        why_it_matters="Database URLs with embedded credentials expose your database to anyone with source access.",
        vulnerable_example='DATABASE_URL = "postgres://user:password@host/db"',
        safer_example="DATABASE_URL = os.getenv('DATABASE_URL')",
        limitations="Matches common database URL patterns; may not catch all connection string formats.",
        remediation="Move to environment variable, rotate database credentials.",
        suppression_guidance="Suppress only after rotation.",
    ),
    "SEC007": RuleInfo(
        rule_id="SEC007",
        title="Generic Secret",
        severity="HIGH",
        category="Source Code — Hardcoded Secret",
        why_it_matters="Generic secret patterns catch API keys and tokens that don't match specific vendor formats.",
        vulnerable_example='API_KEY = "abcdef1234567890"',
        safer_example="API_KEY = os.getenv('API_KEY')",
        limitations="Broad pattern; higher false-positive rate. Review findings carefully.",
        remediation="Move to environment variable and rotate the credential.",
        suppression_guidance="Review carefully before suppressing; may indicate a real credential.",
    ),
    # ── Config ──────────────────────────────────────────────────────
    "CFG001": RuleInfo(
        rule_id="CFG001",
        title="Exposed ENV Secret",
        severity="HIGH",
        category="Configuration — .env File",
        why_it_matters="Secrets in committed .env files are visible to everyone with repository access.",
        vulnerable_example='SECRET_KEY = "mysecret"',
        safer_example="# .env file is in .gitignore; secrets loaded via os.getenv()",
        limitations="Line-based detection in .env files only.",
        remediation="Add .env to .gitignore immediately. Load secrets with python-dotenv or os.getenv().",
        suppression_guidance="Suppress only for documented example .env files with placeholder values.",
    ),
    "CFG002": RuleInfo(
        rule_id="CFG002",
        title="Exposed Database URL",
        severity="HIGH",
        category="Configuration — .env File",
        why_it_matters="Database URLs with credentials in committed .env files expose your database.",
        vulnerable_example='DATABASE_URL = "mongodb://user:password@host/db"',
        safer_example="# Use environment variables or a secrets manager",
        limitations="Matches common database URL patterns in .env files.",
        remediation="Add .env to .gitignore and use environment variables in production.",
        suppression_guidance="Suppress only for example files with placeholder credentials.",
    ),
    "CFG003": RuleInfo(
        rule_id="CFG003",
        title="Exposed Password in ENV",
        severity="HIGH",
        category="Configuration — .env File",
        why_it_matters="Passwords in committed .env files grant access to protected resources.",
        vulnerable_example='DB_PASSWORD = "hunter2"',
        safer_example="# Use a secrets manager or environment variable injection",
        limitations="Keyword-based detection (PASSWORD, PASSWD, DB_PASS, DB_PASSWORD).",
        remediation="Add .env to .gitignore. Use a secrets manager in production.",
        suppression_guidance="Suppress only for documentation examples with obvious placeholder values.",
    ),
    "CFG004": RuleInfo(
        rule_id="CFG004",
        title="Docker Hardcoded Password",
        severity="HIGH",
        category="Configuration — Docker Compose",
        why_it_matters="Hardcoded passwords in docker-compose files are visible in version control and may be used in production.",
        vulnerable_example='MYSQL_ROOT_PASSWORD: "admin123"',
        safer_example="MYSQL_ROOT_PASSWORD: ${DB_PASSWORD}",
        limitations="Detects MYSQL_ROOT_PASSWORD, POSTGRES_PASSWORD, DB_PASSWORD keys.",
        remediation="Use Docker secrets or environment variables with ${VAR} substitution.",
        suppression_guidance="Suppress only for local development files that are never deployed.",
    ),
    "CFG005": RuleInfo(
        rule_id="CFG005",
        title="Docker Hardcoded Secret",
        severity="HIGH",
        category="Configuration — Docker Compose",
        why_it_matters="Hardcoded API keys or secrets in Docker configuration are visible in version control.",
        vulnerable_example='SECRET_KEY: "sk-abcdef"',
        safer_example="SECRET_KEY: ${SECRET_KEY}",
        limitations="Detects SECRET_KEY and API_KEY patterns.",
        remediation="Use Docker secrets or environment variable substitution.",
        suppression_guidance="Suppress only for local development with non-sensitive placeholder values.",
    ),
}


def get_rule(rule_id: str) -> RuleInfo | None:
    """Return the :class:`RuleInfo` for *rule_id*, or ``None``."""
    return RULES.get(rule_id.upper())


def list_rule_ids() -> list[str]:
    """Return the sorted list of supported rule IDs."""
    return sorted(RULES.keys())


def format_explain(rule_info: RuleInfo) -> str:
    """Format a :class:`RuleInfo` as a human-readable text block."""
    return (
        f"═══ {rule_info.rule_id} — {rule_info.title} ═══\n"
        f"\n"
        f"  Severity: {rule_info.severity}\n"
        f"  Category: {rule_info.category}\n"
        f"\n"
        f"  Why it matters:\n"
        f"    {rule_info.why_it_matters}\n"
        f"\n"
        f"  Vulnerable example:\n"
        f"{_indent(rule_info.vulnerable_example, 4)}\n"
        f"\n"
        f"  Safer example:\n"
        f"{_indent(rule_info.safer_example, 4)}\n"
        f"\n"
        f"  Remediation:\n"
        f"    {rule_info.remediation}\n"
        f"\n"
        f"  Limitations:\n"
        f"    {rule_info.limitations}\n"
        f"\n"
        f"  Suppression:\n"
        f"    {rule_info.suppression_guidance}\n"
    )


def _indent(text: str, spaces: int) -> str:
    prefix = " " * spaces
    return "\n".join(prefix + line for line in text.splitlines())
