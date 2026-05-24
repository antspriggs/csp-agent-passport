"""Verifier tests.

Per CLAUDE.md: every error path should have a test. Each `VerificationError`
subclass that the verifier can raise has at least one test that exercises it.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

import pytest
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import OctKey, RSAKey

from nist_agent_passport.claims import AgentClaims, Passport
from nist_agent_passport.errors import (
    AALInsufficient,
    AlgorithmNotAllowed,
    AudienceMismatch,
    Expired,
    FALInsufficient,
    IALInsufficient,
    InvalidSignature,
    InvalidToken,
    KeyNotFound,
    MalformedClaims,
    NotYetValid,
    ScopeViolation,
    UntrustedIssuer,
    WildcardScopeNotAllowed,
)
from nist_agent_passport.keys import InMemoryKeyStore
from nist_agent_passport.policy import VerificationPolicy
from nist_agent_passport.verifier import VerifiedPassport, Verifier

ISSUER = "https://issuer.example.com"
AUDIENCE = "https://mcp.example.com/"


def _policy(**overrides: Any) -> VerificationPolicy:
    defaults: dict[str, Any] = dict(
        issuers=frozenset({ISSUER}),
        audience=AUDIENCE,
    )
    defaults.update(overrides)
    return VerificationPolicy(**defaults)


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_happy_path_returns_verified_passport(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    verifier = Verifier(_policy(), key_store, now=now_fn)
    result = verifier.verify(make_token())
    assert isinstance(result, VerifiedPassport)
    assert result.passport.iss == ISSUER
    assert result.passport.aud == AUDIENCE


# --------------------------------------------------------------------------- #
# Header / algorithm checks
# --------------------------------------------------------------------------- #


def test_alg_none_rejected(
    make_passport: Callable[..., Passport],
    key_store: InMemoryKeyStore,
    kid: str,
    now_fn: Callable[[], datetime],
) -> None:
    """A hand-crafted alg:none token must be rejected before any signature work."""
    claims = make_passport().to_jwt_claims()
    header = {"alg": "none", "kid": kid, "typ": "JWT"}

    def b64(obj: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    token = f"{b64(header)}.{b64(claims)}."
    verifier = Verifier(_policy(), key_store, now=now_fn)
    with pytest.raises(AlgorithmNotAllowed) as ei:
        verifier.verify(token)
    assert ei.value.alg == "none"


def test_hs256_rejected_when_not_allowed(
    make_passport: Callable[..., Passport],
    key_store: InMemoryKeyStore,
    kid: str,
    now_fn: Callable[[], datetime],
) -> None:
    """Symmetric algorithms are not in the default allowed set."""
    claims = make_passport().to_jwt_claims()
    secret = OctKey.import_key("shared-secret-for-test-only")
    token = joserfc_jwt.encode({"alg": "HS256", "kid": kid}, claims, secret, algorithms=["HS256"])

    verifier = Verifier(_policy(), key_store, now=now_fn)
    with pytest.raises(AlgorithmNotAllowed):
        verifier.verify(token)


def test_kid_missing_rejected(
    make_passport: Callable[..., Passport],
    signing_key: RSAKey,
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    claims = make_passport().to_jwt_claims()
    token = joserfc_jwt.encode({"alg": "RS256"}, claims, signing_key, algorithms=["RS256"])

    verifier = Verifier(_policy(), key_store, now=now_fn)
    with pytest.raises(InvalidToken):
        verifier.verify(token)


def test_unknown_kid_raises_key_not_found(
    make_passport: Callable[..., Passport],
    signing_key: RSAKey,
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    claims = make_passport().to_jwt_claims()
    token = joserfc_jwt.encode(
        {"alg": "RS256", "kid": "unknown-kid"}, claims, signing_key, algorithms=["RS256"]
    )

    verifier = Verifier(_policy(), key_store, now=now_fn)
    with pytest.raises(KeyNotFound) as ei:
        verifier.verify(token)
    assert ei.value.kid == "unknown-kid"


def test_garbage_token_rejected(
    key_store: InMemoryKeyStore, now_fn: Callable[[], datetime]
) -> None:
    verifier = Verifier(_policy(), key_store, now=now_fn)
    for bad in ("", "not-a-jwt", "a.b", "...", "@@@.@@@.@@@"):
        with pytest.raises(InvalidToken):
            verifier.verify(bad)


# --------------------------------------------------------------------------- #
# Signature
# --------------------------------------------------------------------------- #


def test_signature_from_wrong_key_rejected(
    make_passport: Callable[..., Passport],
    kid: str,
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    """Token signed with a different private key must fail signature check."""
    other_key = RSAKey.generate_key(2048)
    claims = make_passport().to_jwt_claims()
    token = joserfc_jwt.encode(
        {"alg": "RS256", "kid": kid}, claims, other_key, algorithms=["RS256"]
    )

    verifier = Verifier(_policy(), key_store, now=now_fn)
    with pytest.raises(InvalidSignature):
        verifier.verify(token)


# --------------------------------------------------------------------------- #
# iss / aud
# --------------------------------------------------------------------------- #


def test_untrusted_issuer_rejected(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    token = make_token(iss="https://attacker.example.com")
    verifier = Verifier(_policy(), key_store, now=now_fn)
    with pytest.raises(UntrustedIssuer) as ei:
        verifier.verify(token)
    assert ei.value.iss == "https://attacker.example.com"


def test_audience_must_exact_match(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    token = make_token(aud="https://other.example.com/")
    verifier = Verifier(_policy(), key_store, now=now_fn)
    with pytest.raises(AudienceMismatch):
        verifier.verify(token)


def test_audience_substring_does_not_match(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    """`aud` is exact-match — a substring or path-prefix is not accepted."""
    token = make_token(aud="https://mcp.example.com/api")
    verifier = Verifier(_policy(audience="https://mcp.example.com/"), key_store, now=now_fn)
    with pytest.raises(AudienceMismatch):
        verifier.verify(token)


# --------------------------------------------------------------------------- #
# Time window
# --------------------------------------------------------------------------- #


def test_expired_token_rejected(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    fixed_now: datetime,
) -> None:
    token = make_token(
        iat=fixed_now - timedelta(hours=2),
        nbf=fixed_now - timedelta(hours=2),
        exp=fixed_now - timedelta(hours=1),
    )
    verifier = Verifier(_policy(), key_store, now=lambda: fixed_now)
    with pytest.raises(Expired):
        verifier.verify(token)


def test_expired_within_clock_skew_accepted(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    fixed_now: datetime,
) -> None:
    """Expired by 10s with 30s skew → still valid."""
    token = make_token(exp=fixed_now - timedelta(seconds=10))
    verifier = Verifier(_policy(clock_skew=timedelta(seconds=30)), key_store, now=lambda: fixed_now)
    assert verifier.verify(token).passport.exp < fixed_now


def test_not_yet_valid_rejected(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    fixed_now: datetime,
) -> None:
    token = make_token(
        iat=fixed_now + timedelta(hours=1),
        nbf=fixed_now + timedelta(hours=1),
        exp=fixed_now + timedelta(hours=2),
    )
    verifier = Verifier(_policy(), key_store, now=lambda: fixed_now)
    with pytest.raises(NotYetValid):
        verifier.verify(token)


def test_not_yet_valid_within_clock_skew_accepted(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    fixed_now: datetime,
) -> None:
    """nbf 10s in the future with 30s skew → valid."""
    token = make_token(
        nbf=fixed_now + timedelta(seconds=10),
        exp=fixed_now + timedelta(minutes=15),
    )
    verifier = Verifier(_policy(clock_skew=timedelta(seconds=30)), key_store, now=lambda: fixed_now)
    assert verifier.verify(token).passport.nbf > fixed_now


# --------------------------------------------------------------------------- #
# Identity assurance
# --------------------------------------------------------------------------- #


def test_ial_below_required_rejected(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    token = make_token(ial=1)
    verifier = Verifier(_policy(require_ial=2), key_store, now=now_fn)
    with pytest.raises(IALInsufficient) as ei:
        verifier.verify(token)
    assert ei.value.required == 2 and ei.value.actual == 1


def test_ial_meets_required_accepted(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    token = make_token(ial=3)
    verifier = Verifier(_policy(require_ial=2), key_store, now=now_fn)
    assert verifier.verify(token).passport.ial == 3


def test_aal_below_required_rejected(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    token = make_token(aal=1)
    verifier = Verifier(_policy(require_aal=3), key_store, now=now_fn)
    with pytest.raises(AALInsufficient):
        verifier.verify(token)


def test_fal_below_required_rejected(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    token = make_token(fal=1)
    verifier = Verifier(_policy(require_fal=2), key_store, now=now_fn)
    with pytest.raises(FALInsufficient):
        verifier.verify(token)


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #


def test_required_scope_present_in_token_accepted(
    make_passport: Callable[..., Passport],
    sign: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    p = make_passport(
        agent=AgentClaims(
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:search", "flights:book"],
        )
    )
    verifier = Verifier(_policy(required_scope="flights:book"), key_store, now=now_fn)
    assert verifier.verify(sign(p.to_jwt_claims())).passport.agent.tool_scope


def test_required_scope_matches_partial_wildcard(
    make_passport: Callable[..., Passport],
    sign: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    """A token pattern like `flights:*` covers `flights:book`."""
    p = make_passport(
        agent=AgentClaims(
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:*"],
        )
    )
    verifier = Verifier(_policy(required_scope="flights:book"), key_store, now=now_fn)
    verifier.verify(sign(p.to_jwt_claims()))


def test_required_scope_not_covered_rejected(
    make_passport: Callable[..., Passport],
    sign: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    p = make_passport(
        agent=AgentClaims(
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:search"],
        )
    )
    verifier = Verifier(_policy(required_scope="flights:book"), key_store, now=now_fn)
    with pytest.raises(ScopeViolation) as ei:
        verifier.verify(sign(p.to_jwt_claims()))
    assert ei.value.required == "flights:book"


def test_empty_tool_scope_rejects_required_scope(
    make_passport: Callable[..., Passport],
    sign: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    """Empty tool_scope = no authority. Any required_scope must fail."""
    p = make_passport(
        agent=AgentClaims(
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=[],
        )
    )
    verifier = Verifier(_policy(required_scope="anything"), key_store, now=now_fn)
    with pytest.raises(ScopeViolation):
        verifier.verify(sign(p.to_jwt_claims()))


def test_full_wildcard_rejected_by_default(
    make_passport: Callable[..., Passport],
    sign: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    p = make_passport(
        agent=AgentClaims(
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=["*"],
        )
    )
    verifier = Verifier(_policy(), key_store, now=now_fn)
    with pytest.raises(WildcardScopeNotAllowed):
        verifier.verify(sign(p.to_jwt_claims()))


def test_full_wildcard_accepted_when_policy_opts_in(
    make_passport: Callable[..., Passport],
    sign: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    p = make_passport(
        agent=AgentClaims(
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=["*"],
        )
    )
    verifier = Verifier(
        _policy(allow_wildcard_scope=True, required_scope="anything"),
        key_store,
        now=now_fn,
    )
    verifier.verify(sign(p.to_jwt_claims()))


# --------------------------------------------------------------------------- #
# Malformed claims
# --------------------------------------------------------------------------- #


def test_missing_required_claim_raises_malformed(
    sign: Callable[..., str],
    make_passport: Callable[..., Passport],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    """Drop `aud` from the payload — Pydantic must reject."""
    claims = make_passport().to_jwt_claims()
    del claims["aud"]
    token = sign(claims)
    verifier = Verifier(_policy(), key_store, now=now_fn)
    with pytest.raises(MalformedClaims):
        verifier.verify(token)


def test_invalid_assurance_level_raises_malformed(
    sign: Callable[..., str],
    make_passport: Callable[..., Passport],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    """IAL=4 in the payload is out of NIST range; Pydantic must reject."""
    claims = make_passport().to_jwt_claims()
    claims["ial"] = 4
    token = sign(claims)
    verifier = Verifier(_policy(), key_store, now=now_fn)
    with pytest.raises(MalformedClaims):
        verifier.verify(token)


# --------------------------------------------------------------------------- #
# Policy construction
# --------------------------------------------------------------------------- #


def test_policy_rejects_clock_skew_above_ceiling() -> None:
    with pytest.raises(ValueError, match="clock_skew"):
        VerificationPolicy(
            issuers=frozenset({ISSUER}),
            audience=AUDIENCE,
            clock_skew=timedelta(seconds=121),
        )


def test_policy_rejects_negative_clock_skew() -> None:
    with pytest.raises(ValueError, match="clock_skew"):
        VerificationPolicy(
            issuers=frozenset({ISSUER}),
            audience=AUDIENCE,
            clock_skew=timedelta(seconds=-1),
        )


def test_policy_rejects_alg_none_in_allowed_set() -> None:
    with pytest.raises(ValueError, match="none"):
        VerificationPolicy(
            issuers=frozenset({ISSUER}),
            audience=AUDIENCE,
            allowed_algorithms=frozenset({"RS256", "none"}),
        )


def test_policy_rejects_empty_issuers() -> None:
    with pytest.raises(ValueError, match="issuers"):
        VerificationPolicy(issuers=frozenset(), audience=AUDIENCE)


def test_policy_rejects_invalid_required_level() -> None:
    with pytest.raises(ValueError, match="require_ial"):
        VerificationPolicy(
            issuers=frozenset({ISSUER}),
            audience=AUDIENCE,
            require_ial=4,
        )


# --------------------------------------------------------------------------- #
# Time injection
# --------------------------------------------------------------------------- #


def test_now_callable_is_used(
    make_token: Callable[..., str],
    key_store: InMemoryKeyStore,
    fixed_now: datetime,
) -> None:
    """Same token, different `now` → different verdict."""
    token = make_token(exp=fixed_now + timedelta(minutes=5))
    policy = _policy()

    inside = Verifier(policy, key_store, now=lambda: fixed_now)
    outside = Verifier(policy, key_store, now=lambda: fixed_now + timedelta(hours=1))

    inside.verify(token)
    with pytest.raises(Expired):
        outside.verify(token)


def test_default_now_is_utc_aware() -> None:
    """Smoke check: shared `default_now` returns tz-aware UTC."""
    from nist_agent_passport._clock import default_now

    n = default_now()
    assert n.tzinfo is not None
    assert n.utcoffset() == timedelta(0)


# --------------------------------------------------------------------------- #
# Scope-driven auth (no IAL/AAL/FAL required by default)
# --------------------------------------------------------------------------- #


def test_default_policy_accepts_passport_with_no_assurance(
    make_passport: Callable[..., Passport],
    sign: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    """Default `require_ial=0` accepts a Passport with `acr`/`ial`/`aal`/`fal` all None.

    Pins: scope-driven auth is the supported default mode. Identity assurance
    is opt-in via `require_ial`/`require_aal`/`require_fal >= 1`.
    """
    p = make_passport(acr=None, ial=None, aal=None, fal=None)
    verifier = Verifier(_policy(), key_store, now=now_fn)
    result = verifier.verify(sign(p.to_jwt_claims()))
    assert result.passport.ial is None


def test_policy_with_ial_requirement_rejects_passport_without_ial(
    make_passport: Callable[..., Passport],
    sign: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    """`require_ial=1` rejects a Passport that asserts no IAL at all."""
    p = make_passport(acr=None, ial=None, aal=None, fal=None)
    verifier = Verifier(_policy(require_ial=1), key_store, now=now_fn)
    with pytest.raises(IALInsufficient):
        verifier.verify(sign(p.to_jwt_claims()))


def test_policy_require_ial_zero_is_valid_no_op() -> None:
    """`require_ial=0` (the default) is the documented "skip this check" sentinel."""
    p = VerificationPolicy(
        issuers=frozenset({ISSUER}),
        audience=AUDIENCE,
        require_ial=0,
        require_aal=0,
        require_fal=0,
    )
    assert p.require_ial == 0
