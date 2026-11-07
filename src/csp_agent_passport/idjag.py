"""Identity Assertion JWT Authorization Grant (ID-JAG) validation.

Implements the Resource Authorization Server side of
draft-ietf-oauth-identity-assertion-authz-grant-06 ("ID-JAG"), the IETF spec
behind Cross App Access and MCP's Enterprise-Managed Authorization:

    Client ──ID token──▶ IdP (RFC 8693 token exchange)
           ◀──ID-JAG───
    Client ──ID-JAG────▶ Resource AS (RFC 7523 jwt-bearer)   ◀── this module
           ◀──access token (e.g. an Agent Passport, see Issuer.issue_from_id_jag)

ID-JAG lets an enterprise IdP vouch for a user to a third-party authorization
server. It carries the user's `acr` but defines no identity-assurance
semantics. This module adds what Agent Passport exists for: the IdP's `acr`
goes through the same `AcrMapping` the Passport issuer uses, so a Resource AS
can enforce NIST SP 800-63-3 IAL/AAL/FAL floors on an ID-JAG before it issues
an access token.

What this module does NOT do (v0):
  - Proof of possession. An ID-JAG carrying `cnf` (§9.11) is rejected with
    `SenderConstraintUnsupported`, as §9.11 requires of a server that cannot
    check the confirmation method. Consequently clients MUST authenticate.
  - `access_denied` business policy (licensing, user provisioning). That is
    the Resource AS's own decision, taken after this validator succeeds.
  - Issuing the ID-JAG. That is the IdP's job; see the README for why Agent
    Passport does not act as an ID-JAG issuer.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol

from joserfc import jwt as joserfc_jwt
from joserfc.errors import BadSignatureError, JoseError

from csp_agent_passport._clock import NowCallable, default_now
from csp_agent_passport._jose import ID_JAG_TYP, normalize_typ, parse_jws_header
from csp_agent_passport.errors import (
    AALInsufficient,
    AlgorithmNotAllowed,
    AudienceMismatch,
    ClientAuthenticationRequired,
    ClientMismatch,
    Expired,
    FALInsufficient,
    IALInsufficient,
    InvalidSignature,
    InvalidToken,
    LifetimeTooLong,
    MalformedClaims,
    NotYetValid,
    ReplayDetected,
    ResourceNotGoverned,
    SenderConstraintUnsupported,
    TokenTypeMismatch,
    UnsupportedAcr,
    UntrustedIssuer,
    VerificationError,
)
from csp_agent_passport.keys import KeyStore
from csp_agent_passport.oidc.base import AcrMapping, ial_acr_mapping

# urn:ietf:params:oauth:* identifiers from ID-JAG -06 §4 and §11.
ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag"
ID_JAG_GRANT_PROFILE = "urn:ietf:params:oauth:grant-profile:id-jag"
JWT_BEARER_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"

# §3.1: "RS256 is mandatory to implement"; Resource AS SHOULD support ES256.
DEFAULT_ID_JAG_ALGORITHMS: frozenset[str] = frozenset({"RS256", "ES256"})
_MAX_CLOCK_SKEW = timedelta(seconds=120)

OAuthErrorCode = Literal["invalid_grant", "invalid_client"]


class ReplayCache(Protocol):
    """One-time-use tracking for assertion `jti`s.

    `check_and_store` MUST be atomic: return True and remember the key if it
    has not been seen, return False if it has. Entries may be dropped after
    `expires_at`, since an expired assertion is rejected on `exp` anyway.
    Production deployments with more than one Resource AS replica need a
    shared implementation (Redis `SET NX EX`, a DB unique index, ...).
    """

    def check_and_store(self, key: str, expires_at: datetime) -> bool: ...


class InMemoryReplayCache:
    """Process-local `ReplayCache`. Correct for a single replica only."""

    def __init__(self, now: NowCallable = default_now) -> None:
        self._seen: dict[str, datetime] = {}
        self._now = now

    def check_and_store(self, key: str, expires_at: datetime) -> bool:
        now = self._now()
        self._seen = {k: v for k, v in self._seen.items() if v >= now}
        if key in self._seen:
            return False
        self._seen[key] = expires_at
        return True


@dataclass(frozen=True)
class TrustedIdP:
    """An IdP whose ID-JAGs this Resource AS accepts.

    `issuer`: the IdP's issuer identifier, exact-matched against `iss`.
    `key_store`: resolves the IdP's signing keys, typically a
        `DiscoveryKeyStore(issuer, http)`.
    `tenants`: for a multi-tenant issuer, the `tenant` values trusted for
        this Resource AS. When set, an ID-JAG without a `tenant` claim, or
        with one outside this set, is rejected (§4.4.1, §6.1). None means
        the issuer is single-tenant and `tenant` is not consulted.
    `acr_mapping`: maps this IdP's `acr` URIs to NIST IAL/AAL/FAL. Defaults
        to the conservative built-in `ial_acr_mapping`.
    `allowed_algorithms`: signature algorithms accepted from this IdP
        (RFC 8725 §3.1). Defaults to RS256 + ES256.
    """

    issuer: str
    key_store: KeyStore
    tenants: frozenset[str] | None = None
    acr_mapping: AcrMapping = ial_acr_mapping
    allowed_algorithms: frozenset[str] = DEFAULT_ID_JAG_ALGORITHMS

    def __post_init__(self) -> None:
        if not self.allowed_algorithms:
            raise ValueError("allowed_algorithms must not be empty")
        if "none" in {a.lower() for a in self.allowed_algorithms}:
            raise ValueError("'none' is never a valid algorithm")
        if self.tenants is not None and not self.tenants:
            raise ValueError("tenants must be None (single-tenant) or non-empty")


@dataclass(frozen=True)
class IdJagPolicy:
    """What a Resource AS requires of an ID-JAG before honoring it.

    `issuer`: this Resource AS's own issuer identifier; `aud` must equal it.
    `trusted_idps`: IdPs whose grants are accepted, keyed by issuer.
    `governed_resources`: RFC 8707 resource identifiers this AS issues tokens
        for. Every value in the grant's `resource` claim must be one of them
        (simple string comparison, §4.3.3). Required: an AS that cannot say
        what it governs cannot honor a resource-bound grant safely.
    `require_ial/aal/fal`: NIST SP 800-63-3 floors applied to the levels
        mapped from the grant's `acr`. 0 (default) = not checked. When >= 1,
        a grant with no `acr`, or one the mapping cannot translate, fails.
    `max_lifetime`: reject grants whose `exp - iat` exceeds this (§4.4.4).
        ID-JAGs are meant to be redeemed immediately; the -06 example uses
        300 seconds.
    `clock_skew`: tolerance on `exp`/`iat`/`nbf`. Default 30s, max 120s.
    """

    issuer: str
    trusted_idps: Mapping[str, TrustedIdP]
    governed_resources: frozenset[str]
    require_ial: int = 0
    require_aal: int = 0
    require_fal: int = 0
    max_lifetime: timedelta = timedelta(minutes=10)
    clock_skew: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if not self.trusted_idps:
            raise ValueError("trusted_idps must not be empty")
        for iss, idp in self.trusted_idps.items():
            if iss != idp.issuer:
                raise ValueError(f"trusted_idps key {iss!r} != TrustedIdP.issuer {idp.issuer!r}")
        if not self.governed_resources:
            raise ValueError("governed_resources must not be empty")
        if not timedelta(0) <= self.clock_skew <= _MAX_CLOCK_SKEW:
            raise ValueError("clock_skew must be between 0 and 120 seconds")
        if self.max_lifetime <= timedelta(0):
            raise ValueError("max_lifetime must be positive")
        for name, level in (
            ("require_ial", self.require_ial),
            ("require_aal", self.require_aal),
            ("require_fal", self.require_fal),
        ):
            if not 0 <= level <= 3:
                raise ValueError(f"{name} must be 0-3 (0 = unset), got {level}")


@dataclass(frozen=True)
class VerifiedIdJag:
    """An ID-JAG that passed every §4.4.1 check and the NIST floors.

    `ial`/`aal`/`fal` are mapped from `acr` by the IdP's `AcrMapping`; None
    when `acr` is absent or untranslatable. `act` is exposed verbatim. Per
    §9.10 it identifies an actor distinct from both `sub` (the user) and
    `client_id` (the OAuth client); this module assigns it no semantics.
    """

    iss: str
    sub: str
    aud: str
    client_id: str
    jti: str
    iat: datetime
    exp: datetime
    tenant: str | None
    resource: tuple[str, ...]
    scope: tuple[str, ...]
    authorization_details: tuple[Mapping[str, Any], ...]
    acr: str | None
    ial: int | None
    aal: int | None
    fal: int | None
    auth_time: datetime | None
    amr: tuple[str, ...]
    act: Mapping[str, Any] | None
    raw_claims: Mapping[str, Any] = field(repr=False)


def oauth_error_for(error: VerificationError) -> OAuthErrorCode:
    """Map a validation failure to the OAuth error code for the token response.

    ID-JAG -06 §4.4: missing client authentication → `invalid_client`.
    §4.4.3: every other ID-JAG validation failure → `invalid_grant`. §10:
    the `error_description` SHOULD NOT reveal more than the code, so callers
    should not echo `str(error)` to the client.
    """
    if isinstance(error, ClientAuthenticationRequired):
        return "invalid_client"
    return "invalid_grant"


class IdJagValidator:
    """Validates ID-JAGs presented to a Resource AS via the jwt-bearer grant."""

    def __init__(
        self,
        policy: IdJagPolicy,
        replay_cache: ReplayCache | None = None,
        now: NowCallable = default_now,
    ) -> None:
        self._policy = policy
        self._now = now
        self._replay = replay_cache if replay_cache is not None else InMemoryReplayCache(now)

    def validate(self, assertion: str, *, authenticated_client_id: str | None) -> VerifiedIdJag:
        """Validate one ID-JAG.

        `assertion`: the `assertion` parameter of the jwt-bearer token request.
        `authenticated_client_id`: the client the Resource AS authenticated
            on this request, or None if it did not authenticate. The grant's
            `client_id` MUST identify this client (§4.4.1). Without client
            authentication a sender-constrained grant is the only acceptable
            alternative, which v0 does not support, so None always fails with
            `ClientAuthenticationRequired`.

        Raises a `VerificationError` subclass; `oauth_error_for` maps it to
        the OAuth error code to return.
        """
        policy = self._policy

        # 1. Header: explicit type, then algorithm (both before key lookup).
        header = parse_jws_header(assertion)
        if normalize_typ(header.get("typ")) != ID_JAG_TYP:
            raise TokenTypeMismatch(ID_JAG_TYP, _opt_str(header.get("typ")))

        # 2. Pick the trusted IdP from the unverified `iss`, then verify the
        #    signature with that IdP's keys only. The verified `iss` is
        #    re-checked below, so a forged `iss` cannot select a key.
        unverified_iss = _unverified_claim(assertion, "iss")
        idp = policy.trusted_idps.get(unverified_iss) if unverified_iss else None
        if idp is None:
            raise UntrustedIssuer(unverified_iss or "<missing>", policy.trusted_idps)

        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in idp.allowed_algorithms:
            raise AlgorithmNotAllowed(_opt_str(alg), idp.allowed_algorithms)
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidToken("ID-JAG JWS header missing 'kid'")
        key = idp.key_store.get(kid)
        try:
            decoded = joserfc_jwt.decode(assertion, key, algorithms=sorted(idp.allowed_algorithms))
        except BadSignatureError as e:
            raise InvalidSignature(str(e)) from e
        except JoseError as e:
            raise InvalidToken(f"JOSE decode failed: {e}") from e
        claims: dict[str, Any] = dict(decoded.claims)

        # 3. Required claims (§3.1).
        iss = _req_str(claims, "iss")
        if iss != idp.issuer:
            raise UntrustedIssuer(iss, policy.trusted_idps)
        sub = _req_str(claims, "sub")
        client_id = _req_str(claims, "client_id")
        jti = _req_str(claims, "jti")
        iat = _req_time(claims, "iat")
        exp = _req_time(claims, "exp")

        # 4. Tenant (§4.4.1, §6.1).
        tenant = _opt_claim_str(claims, "tenant")
        if idp.tenants is not None and (tenant is None or tenant not in idp.tenants):
            raise UntrustedIssuer(f"{iss} (tenant {tenant!r})", policy.trusted_idps)

        # 5. Audience: string or single-element array equal to our issuer.
        aud_raw = claims.get("aud")
        if isinstance(aud_raw, list) and len(aud_raw) == 1:
            aud_raw = aud_raw[0]
        if not isinstance(aud_raw, str):
            raise AudienceMismatch(policy.issuer, repr(aud_raw))
        if aud_raw != policy.issuer:
            raise AudienceMismatch(policy.issuer, aud_raw)

        # 6. Sender constraint and client continuity.
        if "cnf" in claims:
            raise SenderConstraintUnsupported(
                "ID-JAG carries a cnf confirmation; proof of possession is not "
                "supported by this validator"
            )
        if authenticated_client_id is None:
            raise ClientAuthenticationRequired(
                "client authentication is required to redeem an ID-JAG"
            )
        if client_id != authenticated_client_id:
            raise ClientMismatch(authenticated_client_id, client_id)

        # 7. Time window and lifetime policy (§4.4.3, §4.4.4).
        now = self._now()
        if now > exp + policy.clock_skew:
            raise Expired(exp, now)
        if iat > now + policy.clock_skew:
            raise NotYetValid(iat, now)
        if "nbf" in claims:
            nbf = _req_time(claims, "nbf")
            if now < nbf - policy.clock_skew:
                raise NotYetValid(nbf, now)
        if exp - iat > policy.max_lifetime:
            raise LifetimeTooLong(
                f"ID-JAG lifetime {exp - iat} exceeds policy maximum {policy.max_lifetime}"
            )

        # 8. Resource indicators (§4.4.1). Absent → the AS applies defaults.
        resource = _str_or_list(claims, "resource")
        for r in resource:
            if r not in policy.governed_resources:
                raise ResourceNotGoverned(r)

        # 9. Scope and RAR are returned, not enforced. Their meaning is the
        #    Resource AS's (§4.3.1), which may grant a subset.
        scope_raw = claims.get("scope")
        if scope_raw is not None and not isinstance(scope_raw, str):
            raise MalformedClaims("ID-JAG 'scope' must be a space-delimited string")
        scope = tuple(scope_raw.split()) if scope_raw else ()
        authz_details = claims.get("authorization_details", [])
        if not isinstance(authz_details, list) or not all(
            isinstance(d, dict) for d in authz_details
        ):
            raise MalformedClaims("ID-JAG 'authorization_details' must be an array of objects")

        # 10. NIST SP 800-63-3 levels from `acr`.
        acr = _opt_claim_str(claims, "acr")
        ial = aal = fal = None
        if acr is not None:
            try:
                levels = idp.acr_mapping(acr)
            except UnsupportedAcr:
                levels = None  # untranslatable → no asserted assurance
            if levels is not None:
                ial, aal, fal = levels.ial, levels.aal, levels.fal
        for required, actual, exc in (
            (policy.require_ial, ial, IALInsufficient),
            (policy.require_aal, aal, AALInsufficient),
            (policy.require_fal, fal, FALInsufficient),
        ):
            if required > 0 and (actual is None or actual < required):
                raise exc(required, actual if actual is not None else 0)

        # 11. Replay, last, so a grant that fails any check above is not
        #     burned. §4.4.4 makes this optional; Agent Passport defaults on.
        #     The key is scoped by issuer because jti is unique per issuer only.
        if not self._replay.check_and_store(f"{iss}\x00{jti}", exp + policy.clock_skew):
            raise ReplayDetected(jti)

        auth_time = _req_time(claims, "auth_time") if claims.get("auth_time") is not None else None
        amr_raw = claims.get("amr", [])
        act = claims.get("act")
        return VerifiedIdJag(
            iss=iss,
            sub=sub,
            aud=aud_raw,
            client_id=client_id,
            jti=jti,
            iat=iat,
            exp=exp,
            tenant=tenant,
            resource=resource,
            scope=scope,
            authorization_details=tuple(authz_details),
            acr=acr,
            ial=ial,
            aal=aal,
            fal=fal,
            auth_time=auth_time,
            amr=tuple(str(a) for a in amr_raw) if isinstance(amr_raw, list) else (),
            act=act if isinstance(act, dict) else None,
            raw_claims=claims,
        )


# --------------------------------------------------------------------------- #
# Claim helpers
# --------------------------------------------------------------------------- #


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _unverified_claim(token: str, name: str) -> str | None:
    """Read one string claim from an UNVERIFIED payload, for key selection only."""
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except (IndexError, binascii.Error, ValueError):
        raise InvalidToken("could not decode JWS payload") from None
    if not isinstance(payload, dict):
        raise InvalidToken("JWS payload is not a JSON object")
    return _opt_str(payload.get(name))


def _req_str(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise MalformedClaims(f"ID-JAG missing or non-string {name!r}")
    return value


def _opt_claim_str(claims: Mapping[str, Any], name: str) -> str | None:
    value = claims.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise MalformedClaims(f"ID-JAG {name!r} must be a string")
    return value


def _req_time(claims: Mapping[str, Any], name: str) -> datetime:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise MalformedClaims(f"ID-JAG missing or non-numeric {name!r}")
    return datetime.fromtimestamp(value, tz=UTC)


def _str_or_list(claims: Mapping[str, Any], name: str) -> tuple[str, ...]:
    """`resource` is a string or a non-empty array of unique strings (§3.1)."""
    value = claims.get(name)
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if (
        isinstance(value, list)
        and value
        and all(isinstance(v, str) for v in value)
        and len(set(value)) == len(value)
    ):
        return tuple(value)
    raise MalformedClaims(f"ID-JAG {name!r} must be a string or non-empty array of unique strings")


def trusted_idps(idps: Iterable[TrustedIdP]) -> dict[str, TrustedIdP]:
    """Convenience: build the `IdJagPolicy.trusted_idps` mapping from a list."""
    return {idp.issuer: idp for idp in idps}


__all__ = [
    "DEFAULT_ID_JAG_ALGORITHMS",
    "ID_JAG_GRANT_PROFILE",
    "ID_JAG_TOKEN_TYPE",
    "JWT_BEARER_GRANT_TYPE",
    "IdJagPolicy",
    "IdJagValidator",
    "InMemoryReplayCache",
    "OAuthErrorCode",
    "ReplayCache",
    "TrustedIdP",
    "VerifiedIdJag",
    "oauth_error_for",
    "trusted_idps",
]
