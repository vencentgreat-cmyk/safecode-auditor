"""Permission inheritance analysis for Realtime Database rules.

Firebase Realtime Database rules *cascade*: once an ancestor grants
``.read`` or ``.write`` at some node, every descendant inherits that
permission. A stricter rule attached to a descendant does not shrink
what the ancestor already allowed.

This module walks a :class:`~scanner.rtdb_tree.RtdbNode` tree and
reports descendants whose stricter rules are made ineffective by a
permissive ancestor. The judgement is intentionally conservative:
recognising general expression equivalence is undecidable, so we only
report cases where both the ancestor and the descendant match one of a
small set of syntactic patterns.

Recognised permissive ancestor expressions:

* ``true`` — grants access unconditionally.
* ``auth != null`` / ``auth !== null`` — grants access to any signed-in
  user.
* ``auth.uid != null`` / ``auth.uid !== null`` — same effect.

A descendant expression is considered "stricter" only when it looks
like an owner check: it must reference a wildcard segment (``$something``)
of its own path and the ``auth.uid`` identity in the same expression.
This is a deliberately narrow pattern. Anything else is left alone so
that the analyzer does not accuse projects of vulnerabilities it
cannot actually prove.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from scanner.rtdb_tree import RtdbNode, RtdbRuleExpr

# ── Public data ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class InheritanceFinding:
    """One descendant node whose stricter rule is overridden by an ancestor.

    ``kind`` is either ``"read"`` or ``"write"``. ``ancestor_expr`` and
    ``child_expr`` carry the raw source position of each expression so
    that the reporter can point at either side.
    """

    kind: str
    child_path: tuple[str, ...]
    child_expr: RtdbRuleExpr
    ancestor_path: tuple[str, ...]
    ancestor_expr: RtdbRuleExpr
    severity: str  # "HIGH"


# ── Expression classification ──────────────────────────────────────────────


# Permissive-ancestor expressions after whitespace collapsing. Anything
# outside this set is treated as "we do not know", so the analyzer will
# not report anything about a descendant nested under it.
_PERMISSIVE_NORMALISED = frozenset(
    {
        "true",
        "auth!=null",
        "auth!==null",
        "auth.uid!=null",
        "auth.uid!==null",
    }
)


# A "stricter descendant" pattern requires an owner check: some
# ``$wildcard`` from the JSON path compared against ``auth.uid``. This
# regex is applied to the whitespace-collapsed expression string.
_OWNER_CHECK_PATTERN = re.compile(
    r"""
    (
        \$\w+ \s* ={2,3} \s* auth\.uid       # $uid == auth.uid
      | auth\.uid \s* ={2,3} \s* \$\w+       # auth.uid == $uid
    )
    """,
    re.VERBOSE,
)


def _normalise(expression: str) -> str:
    """Collapse whitespace so surface-level formatting does not matter."""
    return re.sub(r"\s+", "", expression)


def _is_permissive(expression: str) -> bool:
    return _normalise(expression) in _PERMISSIVE_NORMALISED


def _is_owner_check(expression: str) -> bool:
    # Apply the pattern to the *un-collapsed* expression so that the
    # regex's own whitespace tolerance ("$uid == auth.uid" with spaces)
    # is what gates the decision, not a pre-collapsed string. This
    # matches how a human reader would judge the rule.
    return bool(_OWNER_CHECK_PATTERN.search(expression))


# ── Analysis ───────────────────────────────────────────────────────────────


def analyze_inheritance(root: RtdbNode) -> list[InheritanceFinding]:
    """Walk ``root`` and return every ineffective-child finding."""
    findings: list[InheritanceFinding] = []
    _walk(root, None, None, findings)
    return findings


def _walk(
    node: RtdbNode,
    read_ancestor: tuple[tuple[str, ...], RtdbRuleExpr] | None,
    write_ancestor: tuple[tuple[str, ...], RtdbRuleExpr] | None,
    findings: list[InheritanceFinding],
) -> None:
    # Check ``.read`` at this node against a permissive read ancestor.
    if (
        node.read_rule is not None
        and read_ancestor is not None
        and _is_owner_check(node.read_rule.expression)
    ):
        ancestor_path, ancestor_expr = read_ancestor
        findings.append(
            InheritanceFinding(
                kind="read",
                child_path=node.path,
                child_expr=node.read_rule,
                ancestor_path=ancestor_path,
                ancestor_expr=ancestor_expr,
                severity="HIGH",
            )
        )

    # Same treatment for ``.write``.
    if (
        node.write_rule is not None
        and write_ancestor is not None
        and _is_owner_check(node.write_rule.expression)
    ):
        ancestor_path, ancestor_expr = write_ancestor
        findings.append(
            InheritanceFinding(
                kind="write",
                child_path=node.path,
                child_expr=node.write_rule,
                ancestor_path=ancestor_path,
                ancestor_expr=ancestor_expr,
                severity="HIGH",
            )
        )

    # Update the ancestor context for children. A permissive rule at
    # this node *replaces* whatever the ancestors had, because the
    # child rule takes over enforcement from this point down. A
    # non-permissive rule at this node does not disable the ancestor's
    # override: RTDB rules only *grant*, they never revoke.
    next_read_ancestor = read_ancestor
    if node.read_rule is not None and _is_permissive(node.read_rule.expression):
        next_read_ancestor = (node.path, node.read_rule)

    next_write_ancestor = write_ancestor
    if node.write_rule is not None and _is_permissive(node.write_rule.expression):
        next_write_ancestor = (node.path, node.write_rule)

    for child in node.children:
        _walk(child, next_read_ancestor, next_write_ancestor, findings)
