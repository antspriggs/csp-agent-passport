"""Internal scope-matching helpers shared by issuer and verifier.

Two distinct operations live here:

- `scope_covers_required` — used by the verifier to check whether a token's
  `tool_scope` satisfies the policy's `required_scope`. A required scope is
  satisfied if any pattern in `tool_scope` matches it (fnmatch).

- `scope_attenuates` — used by the issuer when minting children, AND by the
  verifier when walking a chain. A child's `tool_scope` must be a subset of
  its parent's. Pattern implication is undecidable in general; we use a
  conservative rule that may reject some provably-valid attenuations but
  will *never* accept an over-broad child. False negatives (over-strict
  rejection) are acceptable; false positives (under-strict acceptance)
  are not.
"""

from __future__ import annotations

import fnmatch

_WILDCARD_CHARS = ("*", "?", "[")


def scope_covers_required(token_scopes: list[str], required: str) -> bool:
    """True if `required` matches at least one fnmatch pattern in `token_scopes`."""
    return any(fnmatch.fnmatchcase(required, pattern) for pattern in token_scopes)


def scope_attenuates(child: list[str], parent: list[str]) -> bool:
    """True if every pattern in `child` is implied by at least one in `parent`."""
    return all(any(_pattern_implies(cp, pp) for pp in parent) for cp in child)


def _has_wildcard(s: str) -> bool:
    return any(c in s for c in _WILDCARD_CHARS)


def _pattern_implies(child: str, parent: str) -> bool:
    """Conservative: True only when we can prove every string matching `child`
    also matches `parent`.

    Rules (in order):
    - Equal patterns imply each other.
    - `parent == "*"` matches everything.
    - If `child` is a literal (no wildcard chars), check fnmatch coverage.
    - Otherwise (both have wildcards but aren't equal): refuse.
    """
    if child == parent:
        return True
    if parent == "*":
        return True
    if not _has_wildcard(child):
        return fnmatch.fnmatchcase(child, parent)
    return False
