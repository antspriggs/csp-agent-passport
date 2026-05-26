"""Verifier policy: what a verifier requires of a Passport before it is accepted."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

_DEFAULT_ALLOWED_ALGORITHMS: frozenset[str] = frozenset({"RS256", "ES256", "EdDSA"})
_MAX_CLOCK_SKEW: timedelta = timedelta(seconds=120)


@dataclass(frozen=True)
class VerificationPolicy:
    """What a Verifier requires of a Passport before accepting it.

    The clock-skew default is 30 seconds. Values above 120 seconds are rejected
    by `__post_init__` because operator-set tolerances that wide tend to mask
    real clock-drift bugs and widen the window for replayed expired tokens.
    """

    issuers: frozenset[str]
    audience: str
    # IAL/AAL/FAL floors. `0` (default) means "don't check this dimension" —
    # scope-driven auth is acceptable and OIDC's `acr` claim is itself
    # optional, so identity assurance is not implicitly required. A verifier
    # that needs identity assurance sets the relevant `require_*` to 1, 2,
    # or 3, in which case the token MUST carry at least that level (a token
    # with no `ial`/`aal`/`fal` claim is rejected).
    require_ial: int = 0
    require_aal: int = 0
    require_fal: int = 0
    required_scope: str | None = None
    allow_wildcard_scope: bool = False
    clock_skew: timedelta = timedelta(seconds=30)
    allowed_algorithms: frozenset[str] = field(default_factory=lambda: _DEFAULT_ALLOWED_ALGORITHMS)

    def __post_init__(self) -> None:
        if self.clock_skew < timedelta(0):
            raise ValueError("clock_skew must be non-negative")
        if self.clock_skew > _MAX_CLOCK_SKEW:
            raise ValueError(
                f"clock_skew must be <= {int(_MAX_CLOCK_SKEW.total_seconds())} seconds"
            )
        for name, level in (
            ("require_ial", self.require_ial),
            ("require_aal", self.require_aal),
            ("require_fal", self.require_fal),
        ):
            if not 0 <= level <= 3:
                raise ValueError(f"{name} must be 0-3 (0 = unset), got {level}")
        if "none" in {a.lower() for a in self.allowed_algorithms}:
            raise ValueError("'none' is never a valid algorithm")
        if not self.allowed_algorithms:
            raise ValueError("allowed_algorithms must not be empty")
        if not self.issuers:
            raise ValueError("issuers allowlist must not be empty")
