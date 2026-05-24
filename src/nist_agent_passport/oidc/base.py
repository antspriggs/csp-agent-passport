"""Generic OIDC client interface and CSP-agnostic types.

`OIDCClient` is the seam where any OIDC + PKCE provider plugs in. The Issuer
depends on this Protocol — never on a concrete adapter — so adding a new CSP
is a configuration change, not a code change.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from nist_agent_passport.errors import UnsupportedAcr


@dataclass(frozen=True)
class AssuranceLevels:
    """NIST SP 800-63-3 IAL/AAL/FAL canonical levels (1-3 each)."""

    ial: int
    aal: int
    fal: int


@dataclass(frozen=True)
class OIDCAssertion:
    """Output of a successful OIDC ID-token validation.

    `acr` and the derived `ial`/`aal`/`fal` are all optional — OIDC's `acr`
    claim is itself optional, and scope-driven auth (authorization from
    OAuth scopes alone, no asserted identity assurance) is a supported
    deployment mode. When `acr` is absent, the `AcrMapping` is not invoked
    and all four fields are `None`.

    `raw_claims` is exposed so adapters can pull CSP-specific extras (e.g.
    `email_verified`) without re-decoding.
    """

    iss: str
    sub: str
    aud: str
    acr: str | None
    ial: int | None
    aal: int | None
    fal: int | None
    raw_claims: Mapping[str, Any]


AcrMapping = Callable[[str], AssuranceLevels]


class OIDCClient(Protocol):
    """Validates an OIDC ID token and returns canonical identity facts."""

    def validate(self, id_token: str) -> OIDCAssertion: ...


# Externally Agent Passport speaks NIST 800-63-3 IAL/AAL/FAL only. The CSP's
# emitted `acr` URI is whatever the CSP happens to send — typically the
# canonical NIST `…/ial/N` form, sometimes the legacy IAF `…/loa/N` URIs that
# some providers still emit for historical reasons. The translation table
# below collapses both into IAL semantics; the rest of the codebase only ever
# sees the AssuranceLevels output.
#
# DESIGN NOTE — conservative legacy-LOA translation
# --------------------------------------------------
# `…/loa/3` is the legacy IAF "identity verified" tier (documents proofed,
# MFA required). In NIST 800-63-3 vocabulary that's IAL-2 + AAL-2, *not*
# IAL-3 — IAL-3 requires in-person supervised proofing that legacy LOA-3
# tiers do not perform. We translate `…/loa/3` to IAL-2 so a downstream
# verifier with `require_ial=3` correctly rejects these tokens.
#
# To extend this for a CSP that emits other ACR URIs, write your own
# `AcrMapping` and pass it to `IDTokenValidator(acr_mapping=…)`. Do not edit
# the entries below in place; the conservative defaults must stay
# conservative or every other deployment's IAL-3 policy silently weakens.
_IAL_PREFIX = "http://idmanagement.gov/ns/assurance/ial/"
_LEGACY_LOA_TRANSLATIONS: dict[str, AssuranceLevels] = {
    # Legacy IAF URI → equivalent NIST 800-63-3 levels.
    "http://idmanagement.gov/ns/assurance/loa/1": AssuranceLevels(ial=1, aal=1, fal=1),
    "http://idmanagement.gov/ns/assurance/loa/3": AssuranceLevels(ial=2, aal=2, fal=2),
}


def ial_acr_mapping(acr: str) -> AssuranceLevels:
    """Default `acr` → NIST 800-63-3 `AssuranceLevels` mapping.

    Accepts two URI families:
      - `http://idmanagement.gov/ns/assurance/ial/N` for N in {1, 2, 3} —
        the canonical NIST form. Maps to `AssuranceLevels(ial=N, aal=N, fal=N)`.
        OIDC's `acr` is a single string but NIST split assurance into three
        independent dimensions; when the CSP only tells us IAL, we set aal
        and fal conservatively to the same level.
      - `http://idmanagement.gov/ns/assurance/loa/{1,3}` — legacy IAF URIs
        that several CSPs still emit. Translated to IAL semantics per the
        table above; see DESIGN NOTE for why LOA-3 → IAL-2 and not IAL-3.

    Any other URI raises `UnsupportedAcr`. Plug a custom `AcrMapping` into
    `IDTokenValidator` if your CSP emits something else (vendor URIs,
    `urn:` schemes, etc.).
    """
    if acr in _LEGACY_LOA_TRANSLATIONS:
        return _LEGACY_LOA_TRANSLATIONS[acr]
    if not acr.startswith(_IAL_PREFIX):
        raise UnsupportedAcr(acr)
    suffix = acr[len(_IAL_PREFIX) :]
    try:
        level = int(suffix)
    except ValueError:
        raise UnsupportedAcr(acr) from None
    if not 1 <= level <= 3:
        raise UnsupportedAcr(acr)
    return AssuranceLevels(ial=level, aal=level, fal=level)
