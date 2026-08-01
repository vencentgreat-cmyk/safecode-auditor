"""Realtime Database rules represented as a semantic tree.

The JSON locator (:mod:`scanner.json_locator`) surfaces every leaf key
along with its source position, but downstream permission-inheritance
analysis needs to reason about *nodes* in the Firebase Realtime Database
rules tree, not about individual keys. A node bundles the ``.read``,
``.write``, and ``.validate`` rule expressions that apply to a specific
JSON path, together with its child nodes.

This module builds such a tree from a sequence of
:class:`~scanner.json_locator.JsonStringValue` entries and provides only
the data model. It performs no semantic analysis of rule expressions
and enforces no policy.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from scanner.json_locator import JsonStringValue

# ── Data classes ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RtdbRuleExpr:
    """A single ``.read`` / ``.write`` / ``.validate`` expression.

    ``expression`` is the raw text from the JSON value, without any
    normalisation. Downstream code that wants to reason about the
    expression should tokenise it itself.
    """

    expression: str
    line: int
    column: int


@dataclass(frozen=True)
class RtdbNode:
    """A single node in the Realtime Database rules tree.

    ``path`` is the tuple of JSON path segments leading to this node,
    starting from the document root's ``"rules"`` object. The root
    node's path is ``()`` — the empty tuple.

    ``read_rule``, ``write_rule``, and ``validate_rule`` are set only
    when the corresponding key was present at this node. A missing key
    is ``None``; this is deliberately distinct from the key being
    present with an empty string.
    """

    path: tuple[str, ...]
    read_rule: RtdbRuleExpr | None = None
    write_rule: RtdbRuleExpr | None = None
    validate_rule: RtdbRuleExpr | None = None
    children: tuple[RtdbNode, ...] = field(default_factory=tuple)


# ── Tree construction ──────────────────────────────────────────────────────


# JSON keys that carry a rule expression at a node. Any other string
# leaf under ``"rules"`` is ignored by tree construction: a rules file
# is not supposed to hold arbitrary string values, and being permissive
# here would just complicate later analysis.
_RULE_KEYS = frozenset({".read", ".write", ".validate"})


def build_rtdb_tree(entries: Iterable[JsonStringValue]) -> RtdbNode:
    """Build a rules tree from JSON locator entries.

    Only entries whose path starts with ``"rules"`` participate; entries
    outside the ``rules`` object are silently ignored so that a
    ``firebase.json`` file with extra top-level keys (``hosting``,
    ``functions``, ...) does not confuse the tree.

    The returned root node covers the ``rules`` object itself, so its
    ``path`` is ``()``. A rule expression whose JSON path is
    ``("rules", ".read")`` therefore becomes ``root.read_rule``.

    Entries with the same ``.read`` / ``.write`` / ``.validate`` key
    appearing twice at the same JSON path are impossible for
    well-formed JSON; if the caller supplies such a sequence, the last
    entry wins. The function does not deduplicate, warn, or raise.
    """

    # Intermediate representation: {path_prefix: _MutableNode}. We build
    # this map in one pass over ``entries``, then materialise the final
    # frozen ``RtdbNode`` tree by walking the map recursively.
    scratch: dict[tuple[str, ...], _MutableNode] = {(): _MutableNode(path=())}

    for entry in entries:
        if not entry.path or entry.path[0] != "rules":
            continue

        # Strip the leading "rules" segment so that node paths are
        # relative to the rules root. This makes debugging output and
        # future finding messages clearer.
        rel_path = entry.path[1:]

        if not rel_path:
            # An entry directly under the document root — impossible for
            # a real rules file since ``"rules"`` is an object, but
            # tolerated as a no-op.
            continue

        *parent_segments, leaf = rel_path
        parent_path = tuple(parent_segments)

        # Ensure every ancestor along the way exists in ``scratch`` so
        # that nodes without their own rule expressions still appear in
        # the final tree.
        _ensure_ancestors(scratch, parent_path)

        parent = scratch[parent_path]
        expr = RtdbRuleExpr(
            expression=entry.value,
            line=entry.line,
            column=entry.column,
        )

        if leaf == ".read":
            parent.read_rule = expr
        elif leaf == ".write":
            parent.write_rule = expr
        elif leaf == ".validate":
            parent.validate_rule = expr
        # Any other key (a nested object like ``"users"``) is not a
        # rule expression — it has been walked past already when we
        # ensured the parent chain above. Nothing to do here.

    return _freeze(scratch, ())


# ── Internal helpers ───────────────────────────────────────────────────────


@dataclass
class _MutableNode:
    """Scratch structure used only during tree construction."""

    path: tuple[str, ...]
    read_rule: RtdbRuleExpr | None = None
    write_rule: RtdbRuleExpr | None = None
    validate_rule: RtdbRuleExpr | None = None
    children: dict[str, _MutableNode] = field(default_factory=dict)


def _ensure_ancestors(
    scratch: dict[tuple[str, ...], _MutableNode],
    path: tuple[str, ...],
) -> None:
    """Ensure every prefix of ``path`` exists in ``scratch``."""
    running: tuple[str, ...] = ()
    parent = scratch[()]
    for segment in path:
        running = running + (segment,)
        child = scratch.get(running)
        if child is None:
            child = _MutableNode(path=running)
            scratch[running] = child
            parent.children[segment] = child
        parent = child


def _freeze(
    scratch: dict[tuple[str, ...], _MutableNode],
    path: tuple[str, ...],
) -> RtdbNode:
    """Materialise the immutable ``RtdbNode`` tree rooted at ``path``."""
    mutable = scratch[path]
    child_nodes = tuple(
        _freeze(scratch, mutable.children[key].path) for key in sorted(mutable.children)
    )
    return RtdbNode(
        path=mutable.path,
        read_rule=mutable.read_rule,
        write_rule=mutable.write_rule,
        validate_rule=mutable.validate_rule,
        children=child_nodes,
    )
