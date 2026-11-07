"""Typed exception hierarchy for Agent Passport.

Verifier callers can branch on error type to make policy decisions: e.g.,
treat `Expired` differently from `InvalidSignature`.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime


class AgentPassportError(Exception):
    """Base class for all Agent Passport exceptions."""


class VerificationError(AgentPassportError):
    """Base class for any failure raised by the verifier."""


class InvalidToken(VerificationError):
    """JWS could not be parsed (malformed structure, header, etc.)."""


class AlgorithmNotAllowed(VerificationError):
    """JWS `alg` header is not in the verifier's allowed-algorithm set."""

    def __init__(self, alg: str | None, allowed: Iterable[str]) -> None:
        self.alg = alg
        self.allowed = frozenset(allowed)
        super().__init__(f"algorithm {alg!r} not in allowed set {sorted(self.allowed)}")


class KeyNotFound(VerificationError):
    """No public key registered under the JWS header's `kid`."""

    def __init__(self, kid: str) -> None:
        self.kid = kid
        super().__init__(f"no key found for kid {kid!r}")


class InvalidSignature(VerificationError):
    """JWS signature did not verify against the resolved public key."""


class MalformedClaims(VerificationError):
    """JWT payload did not match the Passport claim schema."""


class UntrustedIssuer(VerificationError):
    """`iss` claim is not in the verifier's trusted-issuer allowlist."""

    def __init__(self, iss: str, allowed: Iterable[str]) -> None:
        self.iss = iss
        self.allowed = frozenset(allowed)
        super().__init__(f"issuer {iss!r} not in trusted set {sorted(self.allowed)}")


class AudienceMismatch(VerificationError):
    """`aud` claim does not exact-match the verifier's audience."""

    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"expected aud {expected!r}, got {actual!r}")


class Expired(VerificationError):
    """`exp` is before now (after applying clock-skew tolerance)."""

    def __init__(self, exp: datetime, now: datetime) -> None:
        self.exp = exp
        self.now = now
        super().__init__(f"token expired at {exp.isoformat()} (now {now.isoformat()})")


class NotYetValid(VerificationError):
    """`nbf` is after now (after applying clock-skew tolerance)."""

    def __init__(self, nbf: datetime, now: datetime) -> None:
        self.nbf = nbf
        self.now = now
        super().__init__(f"token not valid before {nbf.isoformat()} (now {now.isoformat()})")


class IALInsufficient(VerificationError):
    """Token's IAL is below policy's `require_ial`."""

    def __init__(self, required: int, actual: int) -> None:
        self.required = required
        self.actual = actual
        super().__init__(f"required IAL {required}, token has {actual}")


class AALInsufficient(VerificationError):
    """Token's AAL is below policy's `require_aal`."""

    def __init__(self, required: int, actual: int) -> None:
        self.required = required
        self.actual = actual
        super().__init__(f"required AAL {required}, token has {actual}")


class FALInsufficient(VerificationError):
    """Token's FAL is below policy's `require_fal`."""

    def __init__(self, required: int, actual: int) -> None:
        self.required = required
        self.actual = actual
        super().__init__(f"required FAL {required}, token has {actual}")


class ScopeViolation(VerificationError):
    """Required scope is not covered by the token's `tool_scope`."""

    def __init__(self, required: str, available: Iterable[str]) -> None:
        self.required = required
        self.available = list(available)
        super().__init__(f"required scope {required!r} not covered by {self.available}")


class WildcardScopeNotAllowed(VerificationError):
    """Token claims `*` (full wildcard) but policy does not opt in to wildcards."""


class ChainBroken(VerificationError):
    """Delegation-chain attenuation rule was violated (e.g., IAL increased)."""


class TokenTypeMismatch(InvalidToken):
    """JWS `typ` header names a different kind of JWT than the one expected.

    Explicit typing (RFC 8725 §3.11) is the defense against cross-JWT
    confusion: an access token, an ID-JAG, or an Agent Passport must never be
    accepted where an OIDC ID token is expected, and vice versa
    (draft-ietf-oauth-identity-assertion-authz-grant-06 §4.3.3).
    """

    def __init__(self, expected: str, actual: str | None) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"expected JWT typ {expected!r}, got {actual!r}")


class ClientMismatch(VerificationError):
    """ID-JAG `client_id` does not identify the authenticated client."""

    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"ID-JAG client_id {actual!r} does not match authenticated {expected!r}")


class ClientAuthenticationRequired(VerificationError):
    """ID-JAG presented without client authentication and without a usable
    sender constraint (draft-ietf-oauth-identity-assertion-authz-grant-06 §4.4).
    Maps to OAuth `invalid_client`.
    """


class SenderConstraintUnsupported(VerificationError):
    """Token carries a `cnf` (RFC 7800) confirmation this verifier cannot check.

    A verifier that does not support the confirmation method MUST reject
    (draft-ietf-oauth-identity-assertion-authz-grant-06 §9.11).
    """


class ResourceNotGoverned(VerificationError):
    """A `resource` (RFC 8707) in the grant is not governed by this server."""

    def __init__(self, resource: str) -> None:
        self.resource = resource
        super().__init__(f"resource {resource!r} is not governed by this authorization server")


class ReplayDetected(VerificationError):
    """A one-time assertion's `jti` has already been redeemed."""

    def __init__(self, jti: str) -> None:
        self.jti = jti
        super().__init__(f"assertion jti {jti!r} has already been used")


class LifetimeTooLong(VerificationError):
    """Assertion lifetime (`exp` - `iat`) exceeds the verifier's policy maximum."""


class IssuanceError(AgentPassportError):
    """Base class for any failure raised by the issuer or its OIDC client."""


class DiscoveryError(IssuanceError):
    """Could not fetch or parse the CSP's `.well-known/openid-configuration`."""


class JWKSError(IssuanceError):
    """Could not fetch the CSP's JWKS, or the expected key was not present."""


class UnsupportedAcr(IssuanceError):
    """The CSP's `acr` value is not in the configured ACR mapping."""

    def __init__(self, acr: str) -> None:
        self.acr = acr
        super().__init__(f"acr {acr!r} not in mapping")


class ScopeAttenuationError(IssuanceError):
    """Refused to mint a child: requested `tool_scope` is not a subset of parent's."""

    def __init__(self, child: Iterable[str], parent: Iterable[str]) -> None:
        self.child = list(child)
        self.parent = list(parent)
        super().__init__(
            f"requested child tool_scope {self.child} is not a subset of parent's {self.parent}"
        )
