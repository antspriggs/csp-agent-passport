"""Internal clock abstraction shared by the issuer and verifier.

Time is always injected (per CLAUDE.md coding conventions) so tests can pin
`now` without monkey-patching.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

NowCallable = Callable[[], datetime]


def default_now() -> datetime:
    """Tz-aware UTC `now`. Default for any component that takes a `now` callable."""
    return datetime.now(UTC)
