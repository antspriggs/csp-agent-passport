"""Chain delegation tests: child-token mint, scope attenuation, chain walking.

Per CLAUDE.md step 6: 'child-token minting, scope attenuation enforcement,
chain walking on verify.' These tests cover all three.

The structure mirrors the security model: every check is enforced at *both*
issuance and verification. Most tests use one or the other; the E2E test at
the bottom exercises the full path.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from joserfc.jwk import RSAKey
from mock_oidc import MockOIDCProvider

from nist_agent_passport._scope import scope_attenuates
from nist_agent_passport.errors import ChainBroken, ScopeAttenuationError
from nist_agent_passport.issuer import (
    DEFAULT_CHILD_TTL,
    DelegationRequest,
    IssuanceRequest,
    Issuer,
)
from nist_agent_passport.keys import InMemoryKeyStore
from nist_agent_passport.oidc import IDTokenValidator, ial_acr_mapping
from nist_agent_passport.policy import VerificationPolicy
from nist_agent_passport.verifier import VerifiedPassport, Verifier

ISSUER_URL = "https://issuer.example.com"
CLIENT_ID = "nist-agent-passport-issuer"
ACR_IAL2 = "http://idmanagement.gov/ns/assurance/ial/2"
SVC_A = "https://service-a.example.com/"
SVC_B = "https://service-b.example.com/"
SVC_C = "https://service-c.example.com/"
FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def issuer_key() -> RSAKey:
    return RSAKey.generate_key(2048)


@pytest.fixture
def validator(mock_oidc: MockOIDCProvider) -> Iterator[IDTokenValidator]:
    v = IDTokenValidator(
        discovery_url=mock_oidc.discovery_url,
        client_id=CLIENT_ID,
        acr_mapping=ial_acr_mapping,
        now=lambda: FIXED_NOW,
    )
    try:
        yield v
    finally:
        v.close()


@pytest.fixture
def issuer(issuer_key: RSAKey, validator: IDTokenValidator) -> Issuer:
    return Issuer(
        issuer_url=ISSUER_URL,
        signing_key=issuer_key,
        oidc_client=validator,
        now=lambda: FIXED_NOW,
    )


@pytest.fixture
def verifier_for(
    issuer: Issuer,
) -> Callable[..., Verifier]:
    """Returns a Verifier built for a given audience (defaults to SVC_A)."""

    def _make(audience: str = SVC_A, **policy_overrides: Any) -> Verifier:
        policy = VerificationPolicy(
            issuers=frozenset({ISSUER_URL}),
            audience=audience,
            **policy_overrides,
        )
        key_store = InMemoryKeyStore({issuer.kid: issuer.public_jwk})
        return Verifier(policy, key_store, now=lambda: FIXED_NOW)

    return _make


@pytest.fixture
def root_passport(
    mock_oidc: MockOIDCProvider, issuer: Issuer, verifier_for: Callable[..., Verifier]
) -> VerifiedPassport:
    """A verified root Passport for SVC_A with broad scope."""
    id_token = mock_oidc.mint_id_token(sub="user-alice", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
    root_jwt = issuer.issue(
        IssuanceRequest(
            id_token=id_token,
            audience=SVC_A,
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:*", "hotels:search"],
            task_purpose="plan a trip",
        )
    )
    return verifier_for(SVC_A).verify(root_jwt)


# --------------------------------------------------------------------------- #
# Issuer.delegate — happy path
# --------------------------------------------------------------------------- #


def test_delegate_creates_child_with_parent_jti(
    issuer: Issuer, root_passport: VerifiedPassport, verifier_for: Callable[..., Verifier]
) -> None:
    child_jwt = issuer.delegate(
        DelegationRequest(
            parent=root_passport,
            audience=SVC_B,
            agent_id="agent:bob",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:book"],
        )
    )
    parent_jwt = _resign_for_chain(issuer, root_passport)  # not needed here, kept for symmetry
    del parent_jwt
    # Verify with chain
    chain_root_jwt = issuer._sign(root_passport.passport)
    result = verifier_for(SVC_B).verify(child_jwt, chain=[chain_root_jwt])
    assert result.passport.agent.parent_jti == root_passport.passport.jti
    assert result.passport.act.sub == "agent:bob"
    assert result.passport.act.act is not None
    assert result.passport.act.act.sub == "agent:alice"
    assert result.passport.sub == root_passport.passport.sub  # principal preserved
    assert result.passport.acr == root_passport.passport.acr
    assert result.passport.ial == root_passport.passport.ial
    assert len(result.chain) == 1


def test_delegate_default_ttl_is_5_minutes(
    issuer: Issuer, root_passport: VerifiedPassport, verifier_for: Callable[..., Verifier]
) -> None:
    child_jwt = issuer.delegate(
        DelegationRequest(
            parent=root_passport,
            audience=SVC_B,
            agent_id="agent:bob",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:book"],
        )
    )
    chain_root = issuer._sign(root_passport.passport)
    result = verifier_for(SVC_B).verify(child_jwt, chain=[chain_root])
    assert result.passport.exp - result.passport.iat == DEFAULT_CHILD_TTL


def test_delegate_explicit_ttl_overrides_default(
    issuer: Issuer, root_passport: VerifiedPassport, verifier_for: Callable[..., Verifier]
) -> None:
    child_jwt = issuer.delegate(
        DelegationRequest(
            parent=root_passport,
            audience=SVC_B,
            agent_id="agent:bob",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:book"],
            ttl=timedelta(seconds=90),
        )
    )
    chain_root = issuer._sign(root_passport.passport)
    result = verifier_for(SVC_B).verify(child_jwt, chain=[chain_root])
    assert result.passport.exp - result.passport.iat == timedelta(seconds=90)


def test_delegate_can_change_audience(
    issuer: Issuer, root_passport: VerifiedPassport, verifier_for: Callable[..., Verifier]
) -> None:
    """Parent token was for SVC_A; child can target a different service."""
    assert root_passport.passport.aud == SVC_A
    child_jwt = issuer.delegate(
        DelegationRequest(
            parent=root_passport,
            audience=SVC_B,
            agent_id="agent:bob",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:book"],
        )
    )
    chain_root = issuer._sign(root_passport.passport)
    result = verifier_for(SVC_B).verify(child_jwt, chain=[chain_root])
    assert result.passport.aud == SVC_B


# --------------------------------------------------------------------------- #
# Issuer.delegate — scope attenuation enforcement
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "child_scope",
    [
        ["flights:book"],  # literal in parent's wildcard
        ["flights:search", "flights:cancel"],  # multiple literals in parent's wildcard
        ["hotels:search"],  # exact match with parent's literal
        ["flights:*"],  # equal to parent
        [],  # empty (no authority requested)
    ],
)
def test_delegate_subset_scope_accepted(
    issuer: Issuer,
    root_passport: VerifiedPassport,
    child_scope: list[str],
) -> None:
    """Parent: ['flights:*', 'hotels:search']. Each above is a valid subset."""
    issuer.delegate(
        DelegationRequest(
            parent=root_passport,
            audience=SVC_B,
            agent_id="agent:bob",
            agent_model="claude-opus-4-7",
            tool_scope=child_scope,
        )
    )


@pytest.mark.parametrize(
    "child_scope",
    [
        ["hotels:*"],  # broader than parent's "hotels:search"
        ["payments:charge"],  # not in parent at all
        ["*"],  # full wildcard (parent isn't *)
        ["flights:*", "hotels:*"],  # one bad item poisons the whole request
    ],
)
def test_delegate_overbroad_scope_rejected(
    issuer: Issuer,
    root_passport: VerifiedPassport,
    child_scope: list[str],
) -> None:
    with pytest.raises(ScopeAttenuationError):
        issuer.delegate(
            DelegationRequest(
                parent=root_passport,
                audience=SVC_B,
                agent_id="agent:bob",
                agent_model="claude-opus-4-7",
                tool_scope=child_scope,
            )
        )


# --------------------------------------------------------------------------- #
# scope_attenuates unit-level
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "child,parent,expected",
    [
        ([], [], True),
        ([], ["a"], True),
        (["a"], [], False),
        (["a"], ["a"], True),
        (["a"], ["a", "b"], True),
        (["a", "b"], ["a", "b"], True),
        (["a", "c"], ["a", "b"], False),
        (["flights:book"], ["flights:*"], True),
        (["flights:*"], ["flights:book"], False),
        (["flights:*"], ["flights:*"], True),
        (["flights:*"], ["*"], True),
        (["*"], ["flights:*"], False),
        (["a:b:c"], ["a:b:*"], True),
        (["a:b:*"], ["a:*"], False),  # conservative: child has wildcards, not equal
    ],
)
def test_scope_attenuates_rules(child: list[str], parent: list[str], expected: bool) -> None:
    assert scope_attenuates(child, parent) is expected


# --------------------------------------------------------------------------- #
# Verifier chain walking
# --------------------------------------------------------------------------- #


def test_verify_root_with_chain_raises(
    issuer: Issuer, root_passport: VerifiedPassport, verifier_for: Callable[..., Verifier]
) -> None:
    """Root tokens (no parent_jti) cannot have a chain."""
    root_jwt = issuer._sign(root_passport.passport)
    with pytest.raises(ChainBroken, match="root token"):
        verifier_for(SVC_A).verify(root_jwt, chain=[root_jwt])


def test_verify_child_without_chain_raises(
    issuer: Issuer, root_passport: VerifiedPassport, verifier_for: Callable[..., Verifier]
) -> None:
    """Child tokens (have parent_jti) require a chain."""
    child_jwt = issuer.delegate(
        DelegationRequest(
            parent=root_passport,
            audience=SVC_B,
            agent_id="agent:bob",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:book"],
        )
    )
    with pytest.raises(ChainBroken, match="no parent chain"):
        verifier_for(SVC_B).verify(child_jwt)


def test_verify_chain_with_wrong_parent_jti_raises(
    issuer: Issuer,
    mock_oidc: MockOIDCProvider,
    root_passport: VerifiedPassport,
    verifier_for: Callable[..., Verifier],
) -> None:
    """Substitute a different (valid) root token as the alleged parent."""
    child_jwt = issuer.delegate(
        DelegationRequest(
            parent=root_passport,
            audience=SVC_B,
            agent_id="agent:bob",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:book"],
        )
    )
    # Build a different root token (different jti) and pass it as the chain.
    other_id_token = mock_oidc.mint_id_token(
        sub="user-alice", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW
    )
    other_root_jwt = issuer.issue(
        IssuanceRequest(
            id_token=other_id_token,
            audience=SVC_A,
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:*"],
        )
    )
    with pytest.raises(ChainBroken, match="parent_jti mismatch"):
        verifier_for(SVC_B).verify(child_jwt, chain=[other_root_jwt])


def test_verify_chain_overbroad_child_scope_raises(
    issuer: Issuer,
    issuer_key: RSAKey,
    root_passport: VerifiedPassport,
    verifier_for: Callable[..., Verifier],
) -> None:
    """A hand-forged child with overbroad scope must be rejected at chain walk."""
    # Mint a 'child' Passport directly (bypassing Issuer.delegate) to simulate
    # a buggy or malicious issuer that didn't enforce attenuation.
    forged = _build_forged_child(
        parent=root_passport.passport,
        agent_id="agent:bob",
        audience=SVC_B,
        tool_scope=["payments:charge"],  # not in parent
        now=FIXED_NOW,
    )
    forged_jwt = _sign_passport(issuer, forged)
    chain_root = issuer._sign(root_passport.passport)
    with pytest.raises(ChainBroken, match="scope attenuation"):
        verifier_for(SVC_B).verify(forged_jwt, chain=[chain_root])


def test_verify_chain_increased_ial_raises(
    issuer: Issuer,
    issuer_key: RSAKey,
    root_passport: VerifiedPassport,
    verifier_for: Callable[..., Verifier],
) -> None:
    """A forged child claiming higher IAL than its parent must be rejected."""
    forged = _build_forged_child(
        parent=root_passport.passport,
        agent_id="agent:bob",
        audience=SVC_B,
        tool_scope=["flights:book"],
        now=FIXED_NOW,
        ial=3,  # parent has ial=2
        aal=3,
        fal=3,
    )
    forged_jwt = _sign_passport(issuer, forged)
    chain_root = issuer._sign(root_passport.passport)
    with pytest.raises(ChainBroken, match="IAL increased"):
        verifier_for(SVC_B).verify(forged_jwt, chain=[chain_root])


def test_verify_chain_root_with_parent_jti_raises(
    issuer: Issuer,
    issuer_key: RSAKey,
    root_passport: VerifiedPassport,
    verifier_for: Callable[..., Verifier],
) -> None:
    """The chain root must not itself claim a parent."""
    child_jwt = issuer.delegate(
        DelegationRequest(
            parent=root_passport,
            audience=SVC_B,
            agent_id="agent:bob",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:book"],
        )
    )
    # Build a fake root that itself claims a parent.
    bad_root = _build_forged_child(
        parent=root_passport.passport,
        agent_id="agent:alice",
        audience=SVC_A,
        tool_scope=["flights:*", "hotels:search"],
        now=FIXED_NOW,
        force_jti=root_passport.passport.jti,  # match leaf's parent_jti
        force_parent_jti="00000000-0000-0000-0000-000000000000",  # but I'm not a root!
    )
    bad_root_jwt = _sign_passport(issuer, bad_root)
    with pytest.raises(ChainBroken, match="root has parent_jti"):
        verifier_for(SVC_B).verify(child_jwt, chain=[bad_root_jwt])


def test_verify_chain_parent_with_invalid_signature_raises(
    issuer: Issuer,
    root_passport: VerifiedPassport,
    verifier_for: Callable[..., Verifier],
) -> None:
    """A parent token signed by an unknown key must fail verification."""
    from joserfc import jwt as joserfc_jwt

    other_key = RSAKey.generate_key(2048)
    child_jwt = issuer.delegate(
        DelegationRequest(
            parent=root_passport,
            audience=SVC_B,
            agent_id="agent:bob",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:book"],
        )
    )
    # Re-sign the parent passport with a different key but the issuer's kid.
    forged_parent_jwt = joserfc_jwt.encode(
        {"alg": "RS256", "kid": issuer.kid},
        root_passport.passport.to_jwt_claims(),
        other_key,
        algorithms=["RS256"],
    )
    from nist_agent_passport.errors import InvalidSignature

    with pytest.raises(InvalidSignature):
        verifier_for(SVC_B).verify(child_jwt, chain=[forged_parent_jwt])


# --------------------------------------------------------------------------- #
# E2E: 3-agent chain (alice → bob → carol)
# --------------------------------------------------------------------------- #


def test_three_agent_chain_end_to_end(
    mock_oidc: MockOIDCProvider,
    issuer: Issuer,
    verifier_for: Callable[..., Verifier],
) -> None:
    """Alice authenticates; delegates to Bob; Bob delegates to Carol; Carol calls SVC_C.

    SVC_C's verifier walks the full chain, re-checking attenuation, IAL
    monotonicity, parent_jti links, and root-ness of the chain root.
    """
    # Step 1: user logs in, gets a root Passport for Alice.
    id_token = mock_oidc.mint_id_token(sub="user-alice", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
    alice_jwt = issuer.issue(
        IssuanceRequest(
            id_token=id_token,
            audience=SVC_A,
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:*", "hotels:*"],
            task_purpose="plan a trip",
        )
    )
    alice_verified = verifier_for(SVC_A).verify(alice_jwt)

    # Step 2: Alice delegates a narrower scope to Bob, audience SVC_B.
    bob_jwt = issuer.delegate(
        DelegationRequest(
            parent=alice_verified,
            audience=SVC_B,
            agent_id="agent:bob",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:*"],
            task_purpose="search flights",
        )
    )
    bob_verified = verifier_for(SVC_B).verify(bob_jwt, chain=[alice_jwt])

    # Step 3: Bob delegates an even narrower scope to Carol, audience SVC_C.
    carol_jwt = issuer.delegate(
        DelegationRequest(
            parent=bob_verified,
            audience=SVC_C,
            agent_id="agent:carol",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:book"],
            task_purpose="actually book the flight",
        )
    )

    # Step 4: SVC_C verifies the leaf with the full chain (root-first).
    final = verifier_for(SVC_C, require_ial=2, required_scope="flights:book").verify(
        carol_jwt, chain=[alice_jwt, bob_jwt]
    )

    # Leaf carries Carol's identity but Alice's principal.
    assert final.passport.agent.agent_id == "agent:carol"
    assert final.passport.sub == "user-alice"
    assert final.passport.ial == 2

    # Nested act chain: carol → bob → alice
    assert final.passport.act.sub == "agent:carol"
    assert final.passport.act.act is not None
    assert final.passport.act.act.sub == "agent:bob"
    assert final.passport.act.act.act is not None
    assert final.passport.act.act.act.sub == "agent:alice"

    # Chain has the two parent passports root-first.
    assert len(final.chain) == 2
    assert final.chain[0].agent.agent_id == "agent:alice"
    assert final.chain[1].agent.agent_id == "agent:bob"
    assert final.chain[0].agent.parent_jti is None
    assert final.chain[1].agent.parent_jti == final.chain[0].jti


# --------------------------------------------------------------------------- #
# Scope-only chains (no IAL/AAL/FAL anywhere)
# --------------------------------------------------------------------------- #


def test_scope_only_chain_walks_with_no_assurance_anywhere(
    mock_oidc: MockOIDCProvider,
    issuer: Issuer,
    verifier_for: Callable[..., Verifier],
) -> None:
    """A 3-token chain where the CSP never asserted `acr` still verifies end-to-end."""
    import base64
    import json

    from joserfc import jwt as joserfc_jwt

    raw = mock_oidc.mint_id_token(sub="user-alice", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
    payload_b64 = raw.split(".")[1]
    payload: dict[str, Any] = json.loads(
        base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    )
    del payload["acr"]
    no_acr_token = joserfc_jwt.encode(
        {"alg": "RS256", "kid": mock_oidc.kid}, payload, mock_oidc._key, algorithms=["RS256"]
    )

    alice_jwt = issuer.issue(
        IssuanceRequest(
            id_token=no_acr_token,
            audience=SVC_A,
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:*", "hotels:*"],
        )
    )
    alice = verifier_for(SVC_A).verify(alice_jwt)
    assert alice.passport.ial is None  # no assurance asserted anywhere
    bob_jwt = issuer.delegate(
        DelegationRequest(
            parent=alice,
            audience=SVC_B,
            agent_id="agent:bob",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:*"],
        )
    )
    bob = verifier_for(SVC_B).verify(bob_jwt, chain=[alice_jwt])
    assert bob.passport.ial is None
    # Authorization came from `tool_scope` alone; no identity assurance was needed.


def test_chain_child_cannot_claim_ial_parent_lacks(
    issuer: Issuer,
    issuer_key: RSAKey,
    mock_oidc: MockOIDCProvider,
    verifier_for: Callable[..., Verifier],
) -> None:
    """A forged child claiming IAL that the (no-IAL) parent doesn't have → ChainBroken.

    Pins: assurance values only propagate downward; agents can never
    manufacture identity assurance the CSP never attested.
    """
    import base64
    import json

    from joserfc import jwt as joserfc_jwt

    # Build a no-acr parent the legit way.
    raw = mock_oidc.mint_id_token(sub="user-alice", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
    payload_b64 = raw.split(".")[1]
    payload: dict[str, Any] = json.loads(
        base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    )
    del payload["acr"]
    no_acr_token = joserfc_jwt.encode(
        {"alg": "RS256", "kid": mock_oidc.kid}, payload, mock_oidc._key, algorithms=["RS256"]
    )
    parent_root_jwt = issuer.issue(
        IssuanceRequest(
            id_token=no_acr_token,
            audience=SVC_A,
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:*"],
        )
    )
    parent = verifier_for(SVC_A).verify(parent_root_jwt).passport
    # Forge a child that claims ial=2 — parent has None.
    forged = _build_forged_child(
        parent=parent,
        agent_id="agent:bob",
        audience=SVC_B,
        tool_scope=["flights:book"],
        now=FIXED_NOW,
        ial=2,
        aal=2,
        fal=2,
    )
    forged_jwt = _sign_passport(issuer, forged)
    with pytest.raises(ChainBroken, match="IAL appeared in chain"):
        verifier_for(SVC_B).verify(forged_jwt, chain=[parent_root_jwt])


# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #


def _resign_for_chain(issuer: Issuer, vp: VerifiedPassport) -> str:
    """Re-sign a verified Passport to use as a chain element. (Deterministic helper.)"""
    return issuer._sign(vp.passport)


def _sign_passport(issuer: Issuer, passport: Any) -> str:
    return issuer._sign(passport)


def _build_forged_child(
    parent: Any,
    agent_id: str,
    audience: str,
    tool_scope: list[str],
    now: datetime,
    ial: int | None = None,
    aal: int | None = None,
    fal: int | None = None,
    force_jti: str | None = None,
    force_parent_jti: str | None = None,
) -> Any:
    """Build a Passport directly, bypassing Issuer.delegate's attenuation check.

    Used to simulate a buggy/malicious issuer in chain-walk tests. Intentionally
    skips the validation Issuer.delegate would otherwise enforce — that's the
    whole point: the verifier must still reject it.
    """
    from uuid import uuid4

    from nist_agent_passport.claims import ActClaim, AgentClaims, Passport

    return Passport(
        iss=parent.iss,
        sub=parent.sub,
        aud=audience,
        iat=now,
        nbf=now,
        exp=now + timedelta(minutes=5),
        jti=force_jti if force_jti is not None else str(uuid4()),
        acr=parent.acr,
        ial=ial if ial is not None else parent.ial,
        aal=aal if aal is not None else parent.aal,
        fal=fal if fal is not None else parent.fal,
        act=ActClaim(sub=agent_id, act=parent.act),
        agent=AgentClaims(
            agent_id=agent_id,
            agent_model="claude-opus-4-7",
            tool_scope=list(tool_scope),
            task_purpose=None,
            parent_jti=force_parent_jti if force_parent_jti is not None else parent.jti,
        ),
    )
