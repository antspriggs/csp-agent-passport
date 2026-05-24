"""Shared fixtures for the test suite.

Notable choices:
- The signing key is generated once per session (RSA-2048 via authlib) so
  tests don't pay key-gen cost per case.
- `make_passport` and `make_token` are factory fixtures with sensible defaults
  that individual tests can override per kwarg.
- `now_fn` is a fixed-time clock so verifier time logic is deterministic.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import RSAKey
from mock_oidc import MockOIDCProvider

from nist_agent_passport.claims import ActClaim, AgentClaims, Passport
from nist_agent_passport.keys import InMemoryKeyStore


@pytest.fixture(scope="session")
def signing_key() -> RSAKey:
    return RSAKey.generate_key(2048)


@pytest.fixture(scope="session")
def kid(signing_key: RSAKey) -> str:
    return signing_key.thumbprint()


@pytest.fixture(scope="session")
def public_jwk(signing_key: RSAKey) -> RSAKey:
    return RSAKey.import_key(signing_key.as_dict(private=False))


@pytest.fixture
def key_store(kid: str, public_jwk: RSAKey) -> InMemoryKeyStore:
    return InMemoryKeyStore({kid: public_jwk})


@pytest.fixture
def fixed_now() -> datetime:
    return datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def now_fn(fixed_now: datetime) -> Callable[[], datetime]:
    return lambda: fixed_now


@pytest.fixture
def make_passport(fixed_now: datetime) -> Callable[..., Passport]:
    def _factory(**overrides: Any) -> Passport:
        defaults: dict[str, Any] = dict(
            iss="https://issuer.example.com",
            sub="psa-abc123",
            aud="https://mcp.example.com/",
            iat=fixed_now,
            exp=fixed_now + timedelta(minutes=15),
            nbf=fixed_now,
            jti="01J9ZK7XQF3D2P9R8MNX5T6V",
            acr="http://idmanagement.gov/ns/assurance/ial/2",
            ial=2,
            aal=2,
            fal=2,
            act=ActClaim(sub="agent:alice"),
            agent=AgentClaims(
                agent_id="agent:alice",
                agent_model="claude-opus-4-7",
                tool_scope=["flights:search", "flights:book"],
                task_purpose="book a flight",
            ),
        )
        defaults.update(overrides)
        return Passport(**defaults)

    return _factory


@pytest.fixture
def sign(signing_key: RSAKey, kid: str) -> Callable[..., str]:
    def _sign(
        claims: dict[str, Any],
        alg: str = "RS256",
        header_overrides: dict[str, Any] | None = None,
    ) -> str:
        header: dict[str, Any] = {"alg": alg, "kid": kid}
        if header_overrides is not None:
            header.update(header_overrides)
        return joserfc_jwt.encode(header, claims, signing_key, algorithms=[alg])

    return _sign


@pytest.fixture
def make_token(
    make_passport: Callable[..., Passport], sign: Callable[..., str]
) -> Callable[..., str]:
    def _make(passport: Passport | None = None, **passport_overrides: Any) -> str:
        if passport is None:
            passport = make_passport(**passport_overrides)
        return sign(passport.to_jwt_claims())

    return _make


@pytest.fixture(scope="session")
def mock_oidc() -> Iterator[MockOIDCProvider]:
    """Session-scoped in-process OIDC provider on a random localhost port."""
    provider = MockOIDCProvider().start()
    try:
        yield provider
    finally:
        provider.stop()
