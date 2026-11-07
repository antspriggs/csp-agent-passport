"""Explicit-typing (RFC 8725 §3.11) tests.

Cross-JWT confusion is the attack: a CSP signs ID tokens, access tokens, and
ID-JAGs with the same key, so signature + `iss` + `aud` alone cannot tell
them apart. draft-ietf-oauth-identity-assertion-authz-grant-06 §4.3.3
requires a token-exchange server to reject a subject token whose `typ`
names another token type. The same discipline applies to Passports.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from joserfc import jws
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import RSAKey
from mock_oidc import MockOIDCProvider

from csp_agent_passport import PASSPORT_TYP
from csp_agent_passport._jose import parse_jws_header
from csp_agent_passport.claims import Passport
from csp_agent_passport.errors import TokenTypeMismatch
from csp_agent_passport.issuer import IssuanceRequest, Issuer
from csp_agent_passport.keys import InMemoryKeyStore
from csp_agent_passport.oidc import IDTokenValidator, ial_acr_mapping
from csp_agent_passport.policy import VerificationPolicy
from csp_agent_passport.verifier import Verifier

ISSUER = "https://issuer.example.com"
AUDIENCE = "https://mcp.example.com/"
CLIENT_ID = "csp-agent-passport-issuer"
ACR_IAL2 = "http://idmanagement.gov/ns/assurance/ial/2"
FIXED_NOW = datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


def _policy(**overrides: Any) -> VerificationPolicy:
    defaults: dict[str, Any] = dict(issuers=frozenset({ISSUER}), audience=AUDIENCE)
    defaults.update(overrides)
    return VerificationPolicy(**defaults)


# --------------------------------------------------------------------------- #
# Passport verifier
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "typ", [PASSPORT_TYP, "application/agent-passport+jwt", "Agent-Passport+JWT"]
)
def test_passport_typ_accepted_case_insensitively(
    typ: str,
    make_passport: Callable[..., Passport],
    sign: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    token = sign(make_passport().to_jwt_claims(), header_overrides={"typ": typ})
    Verifier(_policy(require_typ=True), key_store, now=now_fn).verify(token)


@pytest.mark.parametrize(
    "typ", ["at+jwt", "oauth-id-jag+jwt", "application/at+jwt", "logout+jwt", ""]
)
def test_other_jwt_types_always_rejected(
    typ: Any,
    make_passport: Callable[..., Passport],
    sign: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    """Even with require_typ=False, a token that says it is something else is."""
    token = sign(make_passport().to_jwt_claims(), header_overrides={"typ": typ})
    with pytest.raises(TokenTypeMismatch):
        Verifier(_policy(require_typ=False), key_store, now=now_fn).verify(token)


def test_generic_jwt_typ_accepted_by_default_for_pre_v030_issuers(
    make_passport: Callable[..., Passport],
    sign: Callable[..., str],
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    token = sign(make_passport().to_jwt_claims(), header_overrides={"typ": "JWT"})
    Verifier(_policy(), key_store, now=now_fn).verify(token)


@pytest.mark.parametrize("typ", ["JWT", None])
def test_untyped_rejected_when_policy_requires_typ(
    typ: str | None,
    make_passport: Callable[..., Passport],
    signing_key: RSAKey,
    kid: str,
    key_store: InMemoryKeyStore,
    now_fn: Callable[[], datetime],
) -> None:
    # joserfc's JWT encoder always stamps typ=JWT, so build the raw JWS to
    # exercise the truly-absent case too.
    header: dict[str, Any] = {"alg": "RS256", "kid": kid}
    if typ is not None:
        header["typ"] = typ
    payload = json.dumps(make_passport().to_jwt_claims()).encode()
    token = jws.serialize_compact(header, payload, signing_key, algorithms=["RS256"])
    assert ("typ" in parse_jws_header(token)) == (typ is not None)
    with pytest.raises(TokenTypeMismatch):
        Verifier(_policy(require_typ=True), key_store, now=now_fn).verify(token)
    # ...and accepted under the transitional default.
    Verifier(_policy(), key_store, now=now_fn).verify(token)


def test_issuer_emits_passport_typ(mock_oidc: MockOIDCProvider) -> None:
    key = RSAKey.generate_key(2048)
    validator = IDTokenValidator(
        discovery_url=mock_oidc.discovery_url,
        client_id=CLIENT_ID,
        acr_mapping=ial_acr_mapping,
        now=lambda: FIXED_NOW,
    )
    try:
        issuer = Issuer(ISSUER, key, validator, now=lambda: FIXED_NOW)
        id_token = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID, now=FIXED_NOW)
        token = issuer.issue(
            IssuanceRequest(id_token=id_token, audience=AUDIENCE, agent_id="a", agent_model="m")
        )
    finally:
        validator.close()
    assert parse_jws_header(token)["typ"] == PASSPORT_TYP
    store = InMemoryKeyStore({issuer.kid: issuer.public_jwk})
    Verifier(_policy(require_typ=True), store, now=lambda: FIXED_NOW).verify(token)


# --------------------------------------------------------------------------- #
# ID-token validator (the Issuer's subject-token check)
# --------------------------------------------------------------------------- #


def _id_token_with_typ(mock_oidc: MockOIDCProvider, typ: Any) -> str:
    return joserfc_jwt.encode(
        {"alg": "RS256", "kid": mock_oidc.kid, "typ": typ},
        {
            "iss": mock_oidc.issuer,
            "sub": "u",
            "aud": CLIENT_ID,
            "iat": int(FIXED_NOW.timestamp()),
            "exp": int((FIXED_NOW + timedelta(minutes=5)).timestamp()),
            "acr": ACR_IAL2,
        },
        mock_oidc._key,
        algorithms=["RS256"],
    )


@pytest.fixture
def id_validator(mock_oidc: MockOIDCProvider) -> Iterator[IDTokenValidator]:
    v = IDTokenValidator(
        discovery_url=mock_oidc.discovery_url,
        client_id=CLIENT_ID,
        acr_mapping=ial_acr_mapping,
        now=lambda: FIXED_NOW,
    )
    yield v
    v.close()


@pytest.mark.parametrize(
    "typ",
    ["at+jwt", "application/at+jwt", "oauth-id-jag+jwt", PASSPORT_TYP, "logout+jwt"],
)
def test_id_token_validator_rejects_non_id_token_types(
    typ: Any, mock_oidc: MockOIDCProvider, id_validator: IDTokenValidator
) -> None:
    """An access token or ID-JAG with aud=client_id must not mint a Passport."""
    with pytest.raises(TokenTypeMismatch):
        id_validator.validate(_id_token_with_typ(mock_oidc, typ))


@pytest.mark.parametrize("typ", ["JWT", "jwt", "id_token+jwt"])
def test_id_token_validator_accepts_id_token_types(
    typ: str, mock_oidc: MockOIDCProvider, id_validator: IDTokenValidator
) -> None:
    assertion = id_validator.validate(_id_token_with_typ(mock_oidc, typ))
    assert assertion.ial == 2
