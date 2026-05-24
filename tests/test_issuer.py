"""Issuer end-to-end tests.

Per CLAUDE.md step 5: 'Test the whole loop: ID token in → delegation token
out → verifier accepts.' These tests use the mock OIDC provider as the CSP
and the production verifier — no shortcuts.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from joserfc.jwk import RSAKey
from mock_oidc import MockOIDCProvider

from nist_agent_passport.errors import (
    AudienceMismatch,
    Expired,
    JWKSError,
    UnsupportedAcr,
    UntrustedIssuer,
)
from nist_agent_passport.issuer import DEFAULT_TTL, IssuanceRequest, Issuer
from nist_agent_passport.keys import InMemoryKeyStore
from nist_agent_passport.oidc import IDTokenValidator, ial_acr_mapping
from nist_agent_passport.policy import VerificationPolicy
from nist_agent_passport.verifier import Verifier

ISSUER_URL = "https://issuer.example.com"
CLIENT_ID = "nist-agent-passport-issuer"
ACR_IAL2 = "http://idmanagement.gov/ns/assurance/ial/2"
ACR_IAL3 = "http://idmanagement.gov/ns/assurance/ial/3"
MCP_AUDIENCE = "https://mcp.example.com/"
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


def _verifier(issuer: Issuer, **policy_overrides: Any) -> Verifier:
    policy = VerificationPolicy(
        issuers=frozenset({ISSUER_URL}),
        audience=MCP_AUDIENCE,
        **policy_overrides,
    )
    key_store = InMemoryKeyStore({issuer.kid: issuer.public_jwk})
    return Verifier(policy, key_store, now=lambda: FIXED_NOW)


def _id_token(provider: MockOIDCProvider, **overrides: Any) -> str:
    defaults: dict[str, Any] = dict(sub="user-123", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
    defaults.update(overrides)
    return provider.mint_id_token(**defaults)


def _request(**overrides: Any) -> IssuanceRequest:
    defaults: dict[str, Any] = dict(
        id_token="<set me>",
        audience=MCP_AUDIENCE,
        agent_id="agent:alice",
        agent_model="claude-opus-4-7",
        tool_scope=["flights:*"],
        task_purpose="book a flight from SFO to JFK",
    )
    defaults.update(overrides)
    return IssuanceRequest(**defaults)


# --------------------------------------------------------------------------- #
# Happy path: ID token → Passport → verifier accepts
# --------------------------------------------------------------------------- #


def test_root_passport_round_trip(mock_oidc: MockOIDCProvider, issuer: Issuer) -> None:
    """The whole loop end-to-end."""
    id_token = _id_token(mock_oidc)
    passport_jwt = issuer.issue(_request(id_token=id_token))

    result = _verifier(issuer, require_ial=2, required_scope="flights:book").verify(passport_jwt)
    p = result.passport

    assert p.iss == ISSUER_URL
    assert p.sub == "user-123"
    assert p.aud == MCP_AUDIENCE
    assert p.acr == ACR_IAL2
    assert (p.ial, p.aal, p.fal) == (2, 2, 2)
    assert p.agent.agent_id == "agent:alice"
    assert p.agent.agent_model == "claude-opus-4-7"
    assert p.agent.tool_scope == ["flights:*"]
    assert p.agent.task_purpose == "book a flight from SFO to JFK"
    assert p.agent.parent_jti is None
    assert p.act.sub == "agent:alice"
    assert p.act.act is None
    assert p.exp - p.iat == DEFAULT_TTL


def test_higher_acr_propagates_to_passport(mock_oidc: MockOIDCProvider, issuer: Issuer) -> None:
    """IAL-3 ID token → Passport with ial=3 satisfies require_ial=3 policy."""
    passport_jwt = issuer.issue(_request(id_token=_id_token(mock_oidc, acr=ACR_IAL3)))
    result = _verifier(issuer, require_ial=3).verify(passport_jwt)
    assert result.passport.ial == 3
    assert result.passport.acr == ACR_IAL3


def test_two_issuances_have_distinct_jti(mock_oidc: MockOIDCProvider, issuer: Issuer) -> None:
    id_token = _id_token(mock_oidc)
    a = issuer.issue(_request(id_token=id_token))
    b = issuer.issue(_request(id_token=id_token))
    pa = _verifier(issuer, require_ial=2).verify(a).passport
    pb = _verifier(issuer, require_ial=2).verify(b).passport
    assert pa.jti != pb.jti


def test_explicit_ttl_overrides_default(mock_oidc: MockOIDCProvider, issuer: Issuer) -> None:
    passport_jwt = issuer.issue(_request(id_token=_id_token(mock_oidc), ttl=timedelta(minutes=3)))
    p = _verifier(issuer, require_ial=2).verify(passport_jwt).passport
    assert p.exp - p.iat == timedelta(minutes=3)


def test_default_ttl_is_15_minutes(mock_oidc: MockOIDCProvider, issuer: Issuer) -> None:
    passport_jwt = issuer.issue(_request(id_token=_id_token(mock_oidc)))
    p = _verifier(issuer, require_ial=2).verify(passport_jwt).passport
    assert p.exp - p.iat == timedelta(minutes=15)


# --------------------------------------------------------------------------- #
# Scope-only auth (CSP emits no `acr`)
# --------------------------------------------------------------------------- #


def test_id_token_without_acr_mints_passport_with_no_assurance(
    mock_oidc: MockOIDCProvider, issuer: Issuer
) -> None:
    """OIDC `acr` is optional. A token without it mints a Passport with no
    `acr`/`ial`/`aal`/`fal`; scope-only auth carries the authorization story.
    """
    import base64
    import json

    from joserfc import jwt as joserfc_jwt

    # Mint a token, strip `acr`, re-sign with the mock CSP's key.
    raw = mock_oidc.mint_id_token(sub="user-x", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
    payload_b64 = raw.split(".")[1]
    payload: dict[str, Any] = json.loads(
        base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    )
    del payload["acr"]
    no_acr_token = joserfc_jwt.encode(
        {"alg": "RS256", "kid": mock_oidc.kid},
        payload,
        mock_oidc._key,
        algorithms=["RS256"],
    )

    passport_jwt = issuer.issue(_request(id_token=no_acr_token))
    # Default policy doesn't require IAL — verifier accepts.
    p = _verifier(issuer).verify(passport_jwt).passport
    assert p.acr is None
    assert p.ial is None
    assert p.aal is None
    assert p.fal is None
    # But a verifier that requires IAL=1 rejects the same token.
    from nist_agent_passport.errors import IALInsufficient

    with pytest.raises(IALInsufficient):
        _verifier(issuer, require_ial=1).verify(passport_jwt)


# --------------------------------------------------------------------------- #
# Failure modes (CSP-side)
# --------------------------------------------------------------------------- #


def test_id_token_with_unsupported_acr_rejected(
    mock_oidc: MockOIDCProvider, issuer: Issuer
) -> None:
    bad = _id_token(mock_oidc, acr="urn:something-the-mapping-does-not-know")
    with pytest.raises(UnsupportedAcr):
        issuer.issue(_request(id_token=bad))


def test_id_token_with_wrong_audience_rejected(mock_oidc: MockOIDCProvider, issuer: Issuer) -> None:
    """ID token aud must equal the validator's client_id."""
    bad = _id_token(mock_oidc, aud="some-other-client")
    with pytest.raises(AudienceMismatch):
        issuer.issue(_request(id_token=bad))


def test_expired_id_token_rejected(mock_oidc: MockOIDCProvider, issuer: Issuer) -> None:
    """Token issued an hour ago with default 15-min TTL is expired at FIXED_NOW."""
    long_ago = FIXED_NOW - timedelta(hours=1)
    bad = _id_token(mock_oidc, now=long_ago)
    with pytest.raises(Expired):
        issuer.issue(_request(id_token=bad))


def test_id_token_from_other_csp_rejected(issuer_key: RSAKey) -> None:
    """ID token signed by a different mock provider has an unknown kid."""
    with MockOIDCProvider() as csp_a, MockOIDCProvider() as csp_b:
        validator = IDTokenValidator(
            discovery_url=csp_a.discovery_url,
            client_id=CLIENT_ID,
            acr_mapping=ial_acr_mapping,
            now=lambda: FIXED_NOW,
        )
        try:
            iss = Issuer(
                issuer_url=ISSUER_URL,
                signing_key=issuer_key,
                oidc_client=validator,
                now=lambda: FIXED_NOW,
            )
            rogue = csp_b.mint_id_token(sub="user-123", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
            with pytest.raises(JWKSError):
                iss.issue(_request(id_token=rogue))
        finally:
            validator.close()


def test_id_token_with_forged_iss_rejected(mock_oidc: MockOIDCProvider, issuer: Issuer) -> None:
    """Token signed by the right CSP but claiming a different `iss` is rejected."""
    bad = _id_token(mock_oidc, iss="https://attacker.example.com")
    with pytest.raises(UntrustedIssuer):
        issuer.issue(_request(id_token=bad))


# --------------------------------------------------------------------------- #
# Issuer signing-side correctness
# --------------------------------------------------------------------------- #


def test_passport_signed_with_issuer_key_and_advertised_kid(
    mock_oidc: MockOIDCProvider, issuer: Issuer, issuer_key: RSAKey
) -> None:
    """The kid in the issued JWS header matches issuer.kid (RFC 7638 thumbprint)."""
    passport_jwt = issuer.issue(_request(id_token=_id_token(mock_oidc)))
    from nist_agent_passport._jose import parse_jws_header

    header = parse_jws_header(passport_jwt)
    assert header["alg"] == "RS256"
    assert header["kid"] == issuer.kid
    assert issuer.kid == issuer_key.thumbprint()


def test_public_jwk_does_not_leak_private_material(issuer: Issuer) -> None:
    pub = issuer.public_jwk.as_dict(private=False)
    for private_param in ("d", "p", "q", "dp", "dq", "qi"):
        assert private_param not in pub


# --------------------------------------------------------------------------- #
# OIDCClient seam
# --------------------------------------------------------------------------- #


def test_issuer_uses_oidc_client_protocol(issuer_key: RSAKey) -> None:
    """A tiny in-memory OIDCClient also works — the seam is honored."""
    from nist_agent_passport.oidc.base import OIDCAssertion

    class StubClient:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def validate(self, id_token: str) -> OIDCAssertion:
            self.calls.append(id_token)
            return OIDCAssertion(
                iss="https://stub-csp.example.com",
                sub="stub-sub",
                aud=CLIENT_ID,
                acr=ACR_IAL2,
                ial=2,
                aal=2,
                fal=2,
                raw_claims={"sub": "stub-sub"},
            )

    stub = StubClient()
    iss = Issuer(
        issuer_url=ISSUER_URL,
        signing_key=issuer_key,
        oidc_client=stub,
        now=lambda: FIXED_NOW,
    )
    passport_jwt = iss.issue(_request(id_token="opaque-csp-token"))
    assert stub.calls == ["opaque-csp-token"]
    p = _verifier(iss, require_ial=2).verify(passport_jwt).passport
    assert p.sub == "stub-sub"


# --------------------------------------------------------------------------- #
# ial_acr_mapping unit-level
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("level,expected", [(1, (1, 1, 1)), (2, (2, 2, 2)), (3, (3, 3, 3))])
def test_ial_mapping_known_levels(level: int, expected: tuple[int, int, int]) -> None:
    levels = ial_acr_mapping(f"http://idmanagement.gov/ns/assurance/ial/{level}")
    assert (levels.ial, levels.aal, levels.fal) == expected


@pytest.mark.parametrize(
    "acr",
    [
        "http://idmanagement.gov/ns/assurance/ial/0",
        "http://idmanagement.gov/ns/assurance/ial/4",
        "http://idmanagement.gov/ns/assurance/ial/abc",
        # `…/loa/2` isn't in the legacy-LOA translation table (which only
        # has loa/1 and loa/3 — what CSPs actually emit).
        "http://idmanagement.gov/ns/assurance/loa/2",
        "urn:something-else",
        "",
    ],
)
def test_ial_mapping_rejects_unknown(acr: str) -> None:
    with pytest.raises(UnsupportedAcr):
        ial_acr_mapping(acr)
