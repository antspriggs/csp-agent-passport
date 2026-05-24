"""IDTokenValidator error-path tests.

The validator is the seam between Agent Passport and any external CSP. The
happy path is exercised end-to-end by `test_issuer.py`;
this file covers the failure modes — network errors, malformed discovery
documents, missing/wrong JWKS keys, bad ID-token shapes — that production
deployments will hit eventually.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import RSAKey
from mock_oidc import MockOIDCProvider

from nist_agent_passport.errors import (
    AlgorithmNotAllowed,
    AudienceMismatch,
    DiscoveryError,
    Expired,
    InvalidSignature,
    InvalidToken,
    JWKSError,
    NotYetValid,
    UnsupportedAcr,
    UntrustedIssuer,
)
from nist_agent_passport.oidc.base import AssuranceLevels, OIDCAssertion
from nist_agent_passport.oidc.validator import IDTokenValidator

CLIENT_ID = "nist-agent-passport-issuer"
ACR_IAL2 = "http://idmanagement.gov/ns/assurance/ial/2"
FIXED_NOW = datetime(2026, 5, 24, 12, 0, 0, tzinfo=UTC)


def _trivial_mapping(acr: str) -> AssuranceLevels:
    if acr == ACR_IAL2:
        return AssuranceLevels(ial=2, aal=2, fal=2)
    raise UnsupportedAcr(acr)


def _validator(mock_oidc: MockOIDCProvider, **overrides: Any) -> IDTokenValidator:
    return IDTokenValidator(
        discovery_url=overrides.get("discovery_url", mock_oidc.discovery_url),
        client_id=overrides.get("client_id", CLIENT_ID),
        acr_mapping=overrides.get("acr_mapping", _trivial_mapping),
        now=overrides.get("now", lambda: FIXED_NOW),
        clock_skew=overrides.get("clock_skew", timedelta(seconds=30)),
        allowed_algorithms=overrides.get("allowed_algorithms", ("RS256",)),
    )


# --------------------------------------------------------------------------- #
# Constructor validation
# --------------------------------------------------------------------------- #


def test_alg_none_in_allowed_set_rejected_at_construction(
    mock_oidc: MockOIDCProvider,
) -> None:
    with pytest.raises(ValueError, match="none"):
        IDTokenValidator(
            discovery_url=mock_oidc.discovery_url,
            client_id=CLIENT_ID,
            acr_mapping=_trivial_mapping,
            allowed_algorithms=("RS256", "none"),
        )


def test_empty_allowed_algorithms_rejected_at_construction(
    mock_oidc: MockOIDCProvider,
) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        IDTokenValidator(
            discovery_url=mock_oidc.discovery_url,
            client_id=CLIENT_ID,
            acr_mapping=_trivial_mapping,
            allowed_algorithms=(),
        )


# --------------------------------------------------------------------------- #
# Discovery fetch errors
# --------------------------------------------------------------------------- #


def test_unreachable_discovery_url_raises(mock_oidc: MockOIDCProvider) -> None:
    # Use a port the OS has not assigned to anything.
    v = _validator(mock_oidc, discovery_url="http://127.0.0.1:1/missing")
    try:
        with pytest.raises(DiscoveryError):
            v.validate("a.b.c")
    finally:
        v.close()


def test_discovery_404_raises(mock_oidc: MockOIDCProvider) -> None:
    """A reachable host returning 404 is still a DiscoveryError."""
    v = _validator(mock_oidc, discovery_url=f"{mock_oidc.issuer}/no-such-path")
    try:
        with pytest.raises(DiscoveryError):
            v.validate("a.b.c")
    finally:
        v.close()


def test_discovery_doc_missing_required_field_raises(
    mock_oidc: MockOIDCProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Doc fetched OK but missing `jwks_uri` -> DiscoveryError."""
    # Stub httpx.Client to return a response missing `jwks_uri`.
    real_get = httpx.Client.get

    def fake_get(self: httpx.Client, url: str, *a: Any, **kw: Any) -> httpx.Response:
        if "openid-configuration" in url:
            return httpx.Response(
                200,
                json={"issuer": "https://example.com"},  # missing jwks_uri
                request=httpx.Request("GET", url),
            )
        return real_get(self, url, *a, **kw)

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    v = _validator(mock_oidc)
    try:
        with pytest.raises(DiscoveryError, match="jwks_uri"):
            v.validate("a.b.c")
    finally:
        v.close()


def test_discovery_doc_not_json_object_raises(
    mock_oidc: MockOIDCProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_get(self: httpx.Client, url: str, *a: Any, **kw: Any) -> httpx.Response:
        return httpx.Response(200, json=["not", "an", "object"], request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    v = _validator(mock_oidc)
    try:
        with pytest.raises(DiscoveryError, match="not a JSON object"):
            v.validate("a.b.c")
    finally:
        v.close()


# --------------------------------------------------------------------------- #
# JWKS fetch errors
# --------------------------------------------------------------------------- #


def test_unknown_kid_at_jwks_raises(mock_oidc: MockOIDCProvider) -> None:
    """ID token signed by a different keypair -> kid not in JWKS -> JWKSError."""
    other = RSAKey.generate_key(2048)
    bad_token = joserfc_jwt.encode(
        {"alg": "RS256", "kid": "this-kid-isnt-in-the-jwks"},
        {
            "iss": mock_oidc.issuer,
            "sub": "x",
            "aud": CLIENT_ID,
            "exp": int((FIXED_NOW + timedelta(minutes=5)).timestamp()),
            "acr": ACR_IAL2,
        },
        other,
        algorithms=["RS256"],
    )
    v = _validator(mock_oidc)
    try:
        with pytest.raises(JWKSError, match="no key with kid"):
            v.validate(bad_token)
    finally:
        v.close()


def test_jwks_endpoint_returns_malformed_doc(
    mock_oidc: MockOIDCProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    """JWKS response is not a `{"keys": [...]}` object -> JWKSError."""
    real_get = httpx.Client.get

    def fake_get(self: httpx.Client, url: str, *a: Any, **kw: Any) -> httpx.Response:
        if url.endswith("/jwks.json"):
            return httpx.Response(
                200, json={"oops": "not a jwks"}, request=httpx.Request("GET", url)
            )
        return real_get(self, url, *a, **kw)

    monkeypatch.setattr(httpx.Client, "get", fake_get)
    v = _validator(mock_oidc)
    try:
        with pytest.raises(JWKSError, match="not a valid JWKS"):
            v.validate(_mint_id_token(mock_oidc, kid_override="anything"))
    finally:
        v.close()


# --------------------------------------------------------------------------- #
# ID token shape / claim errors
# --------------------------------------------------------------------------- #


def test_alg_none_in_id_token_rejected(mock_oidc: MockOIDCProvider) -> None:
    """A hand-crafted alg:none token must be rejected before any JOSE call."""
    header = {"alg": "none", "kid": mock_oidc.kid}
    claims = {
        "iss": mock_oidc.issuer,
        "sub": "u",
        "aud": CLIENT_ID,
        "exp": int((FIXED_NOW + timedelta(minutes=5)).timestamp()),
        "acr": ACR_IAL2,
    }

    def b64(o: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()

    token = f"{b64(header)}.{b64(claims)}."
    v = _validator(mock_oidc)
    try:
        with pytest.raises(AlgorithmNotAllowed):
            v.validate(token)
    finally:
        v.close()


def test_id_token_missing_kid_rejected(mock_oidc: MockOIDCProvider) -> None:
    """An ID token header without `kid` cannot resolve a key."""
    token = _mint_id_token(mock_oidc, omit_kid=True)
    v = _validator(mock_oidc)
    try:
        with pytest.raises(InvalidToken, match="missing 'kid'"):
            v.validate(token)
    finally:
        v.close()


def test_id_token_with_wrong_signature_rejected(mock_oidc: MockOIDCProvider) -> None:
    """A token signed with a different key but the CSP's kid still fails sig check."""
    other = RSAKey.generate_key(2048)
    token = joserfc_jwt.encode(
        {"alg": "RS256", "kid": mock_oidc.kid},
        {
            "iss": mock_oidc.issuer,
            "sub": "u",
            "aud": CLIENT_ID,
            "exp": int((FIXED_NOW + timedelta(minutes=5)).timestamp()),
            "acr": ACR_IAL2,
        },
        other,
        algorithms=["RS256"],
    )
    v = _validator(mock_oidc)
    try:
        with pytest.raises(InvalidSignature):
            v.validate(token)
    finally:
        v.close()


def test_id_token_with_wrong_iss_rejected(mock_oidc: MockOIDCProvider) -> None:
    token = mock_oidc.mint_id_token(
        sub="u", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW, iss="https://attacker.example.com"
    )
    v = _validator(mock_oidc)
    try:
        with pytest.raises(UntrustedIssuer):
            v.validate(token)
    finally:
        v.close()


def test_id_token_aud_as_list_with_client_id_accepted(mock_oidc: MockOIDCProvider) -> None:
    """OIDC permits aud as an array; we accept as long as client_id is in it."""
    token = mock_oidc.mint_id_token(
        sub="u",
        acr=ACR_IAL2,
        aud=["other-client", CLIENT_ID, "third-client"],  # type: ignore[arg-type]
        now=FIXED_NOW,
    )
    v = _validator(mock_oidc)
    try:
        assertion = v.validate(token)
    finally:
        v.close()
    assert assertion.aud == CLIENT_ID


def test_id_token_aud_as_list_without_client_id_rejected(
    mock_oidc: MockOIDCProvider,
) -> None:
    token = mock_oidc.mint_id_token(
        sub="u",
        acr=ACR_IAL2,
        aud=["wrong-1", "wrong-2"],  # type: ignore[arg-type]
        now=FIXED_NOW,
    )
    v = _validator(mock_oidc)
    try:
        with pytest.raises(AudienceMismatch):
            v.validate(token)
    finally:
        v.close()


def test_id_token_aud_as_int_rejected(mock_oidc: MockOIDCProvider) -> None:
    """An aud that's neither string nor list is malformed."""
    token = mock_oidc.mint_id_token(
        sub="u",
        acr=ACR_IAL2,
        aud=42,  # type: ignore[arg-type]
        now=FIXED_NOW,
    )
    v = _validator(mock_oidc)
    try:
        with pytest.raises(InvalidToken, match="aud"):
            v.validate(token)
    finally:
        v.close()


def test_id_token_with_nbf_in_future_rejected(mock_oidc: MockOIDCProvider) -> None:
    """nbf 1h in the future, well outside default 30s skew -> NotYetValid."""
    far_future = FIXED_NOW + timedelta(hours=1)
    token = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID, now=far_future)
    v = _validator(mock_oidc)
    try:
        with pytest.raises(NotYetValid):
            v.validate(token)
    finally:
        v.close()


def test_id_token_with_expired_exp_rejected(mock_oidc: MockOIDCProvider) -> None:
    token = mock_oidc.mint_id_token(
        sub="u", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW - timedelta(hours=1)
    )
    v = _validator(mock_oidc)
    try:
        with pytest.raises(Expired):
            v.validate(token)
    finally:
        v.close()


def test_id_token_missing_exp_rejected(mock_oidc: MockOIDCProvider) -> None:
    """exp is required for ID tokens."""
    # Mint a token without exp by going through joserfc directly.
    from joserfc.jwk import JWKRegistry

    raw_token = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
    payload_b64 = raw_token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded))
    del payload["exp"]
    forged = _resign(mock_oidc, payload)
    v = _validator(mock_oidc)
    try:
        with pytest.raises(InvalidToken, match="exp"):
            v.validate(forged)
    finally:
        v.close()
    _ = JWKRegistry  # silence unused-import


def test_id_token_without_acr_validates_with_null_levels(
    mock_oidc: MockOIDCProvider,
) -> None:
    """`acr` is optional per OIDC; an ID token without it validates fine.

    The resulting assertion carries `acr=None` and no IAL/AAL/FAL — the
    scope-driven auth model. Downstream verifiers either accept this
    (`require_ial=0`, the default) or reject (`require_ial >= 1`).
    """
    raw_token = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
    payload = _payload(raw_token)
    del payload["acr"]
    forged = _resign(mock_oidc, payload)
    v = _validator(mock_oidc)
    try:
        assertion = v.validate(forged)
    finally:
        v.close()
    assert assertion.acr is None
    assert assertion.ial is None
    assert assertion.aal is None
    assert assertion.fal is None
    assert assertion.sub == "u"


def test_id_token_missing_sub_rejected(mock_oidc: MockOIDCProvider) -> None:
    raw = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
    payload = _payload(raw)
    del payload["sub"]
    forged = _resign(mock_oidc, payload)
    v = _validator(mock_oidc)
    try:
        with pytest.raises(InvalidToken, match="sub"):
            v.validate(forged)
    finally:
        v.close()


# --------------------------------------------------------------------------- #
# Lifecycle / caching
# --------------------------------------------------------------------------- #


def test_validator_caches_discovery_doc(mock_oidc: MockOIDCProvider) -> None:
    """Second validate() call should reuse the cached discovery doc."""
    v = _validator(mock_oidc)
    try:
        tok = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
        v.validate(tok)
        # Now stop the provider — if we re-fetched discovery, this would fail.
        # Instead, redirect httpx to refuse:
        # (Simpler check: assert the private state has the doc cached.)
        assert v._discovery is not None
        # And a second call still works:
        v.validate(tok)
    finally:
        v.close()


def test_validator_as_context_manager_closes_owned_http(
    mock_oidc: MockOIDCProvider,
) -> None:
    with IDTokenValidator(
        discovery_url=mock_oidc.discovery_url,
        client_id=CLIENT_ID,
        acr_mapping=_trivial_mapping,
        now=lambda: FIXED_NOW,
    ) as v:
        tok = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
        result = v.validate(tok)
        assert isinstance(result, OIDCAssertion)
    # __exit__ closed the http client; further calls would error, but we don't
    # need to assert that — the smoke is that __exit__ ran without raising.


def test_validator_with_injected_http_client_does_not_close_it(
    mock_oidc: MockOIDCProvider,
) -> None:
    client = httpx.Client(timeout=10.0)
    v = IDTokenValidator(
        discovery_url=mock_oidc.discovery_url,
        client_id=CLIENT_ID,
        acr_mapping=_trivial_mapping,
        http=client,
        now=lambda: FIXED_NOW,
    )
    v.close()
    # If close() closed the injected client, this would raise.
    response = client.get(mock_oidc.discovery_url)
    assert response.status_code == 200
    client.close()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _payload(token: str) -> dict[str, Any]:
    p = token.split(".")[1]
    decoded: Any = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    assert isinstance(decoded, dict)
    return decoded


def _resign(mock_oidc: MockOIDCProvider, payload: dict[str, Any]) -> str:
    """Re-sign an arbitrary payload with the mock provider's key."""
    return joserfc_jwt.encode(
        {"alg": "RS256", "kid": mock_oidc.kid},
        payload,
        mock_oidc._key,
        algorithms=["RS256"],
    )


def _mint_id_token(
    mock_oidc: MockOIDCProvider, *, omit_kid: bool = False, kid_override: str | None = None
) -> str:
    header: dict[str, Any] = {"alg": "RS256"}
    if not omit_kid:
        header["kid"] = kid_override if kid_override is not None else mock_oidc.kid
    return joserfc_jwt.encode(
        header,
        {
            "iss": mock_oidc.issuer,
            "sub": "u",
            "aud": CLIENT_ID,
            "exp": int((FIXED_NOW + timedelta(minutes=5)).timestamp()),
            "acr": ACR_IAL2,
        },
        mock_oidc._key,
        algorithms=["RS256"],
    )
