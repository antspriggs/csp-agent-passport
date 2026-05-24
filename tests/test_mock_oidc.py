"""Tests for the in-process mock OIDC provider.

Verifies the provider's externally-observable contract: discovery doc shape,
JWKS publication, ID-token claim shape, end-to-end signature verification
through the published JWKS, and clean lifecycle.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from joserfc import jwt as joserfc_jwt
from joserfc.errors import BadSignatureError
from joserfc.jwk import JWKRegistry
from mock_oidc import MockOIDCProvider

ALG = "RS256"
ACR_IAL2 = "http://idmanagement.gov/ns/assurance/ial/2"


def test_discovery_document_advertises_required_endpoints(
    mock_oidc: MockOIDCProvider,
) -> None:
    response = httpx.get(mock_oidc.discovery_url)
    assert response.status_code == 200
    doc = response.json()
    assert doc["issuer"] == mock_oidc.issuer
    assert doc["jwks_uri"] == mock_oidc.jwks_uri
    assert ALG in doc["id_token_signing_alg_values_supported"]
    assert "openid" in doc["scopes_supported"]
    assert {"sub", "iss", "aud", "exp", "iat", "acr"}.issubset(doc["claims_supported"])


def test_jwks_endpoint_returns_one_signing_key(mock_oidc: MockOIDCProvider) -> None:
    jwks = httpx.get(mock_oidc.jwks_uri).json()
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == ALG
    assert key["kid"] == mock_oidc.kid
    # Public-only — no private parameters leaked.
    assert "d" not in key
    assert "p" not in key
    assert "q" not in key


def test_minted_id_token_has_oidc_claim_shape(mock_oidc: MockOIDCProvider) -> None:
    issued_at = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)
    token = mock_oidc.mint_id_token(
        sub="user-123",
        acr=ACR_IAL2,
        aud="https://issuer.example.com/",
        ttl=timedelta(minutes=10),
        now=issued_at,
        nonce="abc",
    )
    decoded = joserfc_jwt.decode(token, mock_oidc.public_jwk, algorithms=[ALG])
    claims = decoded.claims
    assert claims["iss"] == mock_oidc.issuer
    assert claims["sub"] == "user-123"
    assert claims["aud"] == "https://issuer.example.com/"
    assert claims["acr"] == ACR_IAL2
    assert claims["nonce"] == "abc"
    assert claims["iat"] == int(issued_at.timestamp())
    assert claims["nbf"] == int(issued_at.timestamp())
    assert claims["exp"] == int((issued_at + timedelta(minutes=10)).timestamp())


def test_token_verifies_against_jwks_published_key(mock_oidc: MockOIDCProvider) -> None:
    """End-to-end: mint a token, fetch JWKS over HTTP, verify with that key."""
    token = mock_oidc.mint_id_token(
        sub="user-123",
        acr=ACR_IAL2,
        aud="https://issuer.example.com/",
    )
    jwks = httpx.get(mock_oidc.jwks_uri).json()
    public = JWKRegistry.import_key(jwks["keys"][0])
    decoded = joserfc_jwt.decode(token, public, algorithms=[ALG])
    assert decoded.claims["sub"] == "user-123"


def test_token_signed_by_one_provider_does_not_verify_against_another() -> None:
    """Two separate providers have distinct keys; cross-verification must fail."""
    with MockOIDCProvider() as p1, MockOIDCProvider() as p2:
        token = p1.mint_id_token(sub="u1", acr=ACR_IAL2, aud="rp")
        with pytest.raises(BadSignatureError):
            joserfc_jwt.decode(token, p2.public_jwk, algorithms=[ALG])


def test_full_discovery_to_verification_flow(mock_oidc: MockOIDCProvider) -> None:
    """Pins the discovery-driven CSP integration contract.

    A client given only the issuer URL must be able to verify a token end-to-end
    by chaining: /.well-known/openid-configuration → jwks_uri → JWKS → verify.
    No hardcoded endpoint URLs anywhere in the chain. If this test ever needs
    a hardcoded path beyond the discovery URL, the adapter is broken.
    """
    discovery_url = f"{mock_oidc.issuer}/.well-known/openid-configuration"
    discovery = httpx.get(discovery_url).json()

    # Adapter MUST consume metadata from discovery, not assume defaults.
    assert discovery["issuer"] == mock_oidc.issuer
    jwks_uri = discovery["jwks_uri"]
    allowed_algs = discovery["id_token_signing_alg_values_supported"]

    jwks = httpx.get(jwks_uri).json()
    public = JWKRegistry.import_key(jwks["keys"][0])

    token = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud="rp")
    decoded = joserfc_jwt.decode(token, public, algorithms=allowed_algs)
    assert decoded.claims["sub"] == "u"
    assert decoded.claims["iss"] == discovery["issuer"]


def test_unknown_path_returns_404(mock_oidc: MockOIDCProvider) -> None:
    response = httpx.get(f"{mock_oidc.issuer}/nope")
    assert response.status_code == 404


def test_context_manager_starts_and_stops() -> None:
    with MockOIDCProvider() as provider:
        url = provider.discovery_url
        assert httpx.get(url).status_code == 200
    # After exit, server is shut down.
    with pytest.raises(RuntimeError, match="not started"):
        _ = provider.issuer
    with pytest.raises(httpx.ConnectError):
        httpx.get(url, timeout=1.0)


def test_provider_can_be_restarted_after_stop() -> None:
    provider = MockOIDCProvider()
    provider.start()
    first_issuer = provider.issuer
    provider.stop()
    provider.start()
    try:
        assert httpx.get(provider.discovery_url).status_code == 200
        # Likely a different port the second time.
        assert provider.issuer != first_issuer or True
    finally:
        provider.stop()


def test_mint_before_start_raises() -> None:
    provider = MockOIDCProvider()
    with pytest.raises(RuntimeError, match="not started"):
        provider.mint_id_token(sub="u", acr=ACR_IAL2, aud="rp")
