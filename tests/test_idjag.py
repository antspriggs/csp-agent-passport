"""ID-JAG (draft-ietf-oauth-identity-assertion-authz-grant-06) validator tests.

Per CLAUDE.md, every error path has a test. Section references are to -06.
The end-to-end tests at the bottom cover the composition Agent Passport adds
on top of the spec: IdP `acr` → NIST IAL floor at the Resource AS → a
Passport access token whose audience is bound to the granted `resource`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import ECKey, OctKey, RSAKey
from mock_oidc import MockOIDCProvider

from csp_agent_passport import (
    ClientAuthenticationRequired,
    ClientMismatch,
    DiscoveryKeyStore,
    IdJagIssuanceRequest,
    IdJagPolicy,
    IdJagValidator,
    InMemoryReplayCache,
    Issuer,
    LifetimeTooLong,
    ReplayDetected,
    ResourceNotGoverned,
    SenderConstraintUnsupported,
    TokenTypeMismatch,
    TrustedIdP,
    VerificationPolicy,
    Verifier,
    oauth_error_for,
)
from csp_agent_passport.errors import (
    AlgorithmNotAllowed,
    AudienceMismatch,
    DiscoveryError,
    Expired,
    IALInsufficient,
    InvalidSignature,
    InvalidToken,
    IssuanceError,
    KeyNotFound,
    MalformedClaims,
    NotYetValid,
    UntrustedIssuer,
)
from csp_agent_passport.idjag import ID_JAG_TOKEN_TYPE
from csp_agent_passport.keys import InMemoryKeyStore
from csp_agent_passport.oidc.base import AssuranceLevels

IDP = "https://idp.example.com"
RAS = "https://authorization-server.saas-tool.example/"
RESOURCE = "https://api.saas-tool.example/"
CLIENT = "https://ai-agent-app.example/"
ACR_IAL2 = "http://idmanagement.gov/ns/assurance/ial/2"
NOW = datetime(2026, 11, 1, 12, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def idp_key() -> RSAKey:
    return RSAKey.generate_key(2048)


@pytest.fixture
def idp_store(idp_key: RSAKey) -> InMemoryKeyStore:
    return InMemoryKeyStore(
        {idp_key.thumbprint(): RSAKey.import_key(idp_key.as_dict(private=False))}
    )


def _base_claims(**overrides: Any) -> dict[str, Any]:
    """The -06 Appendix A.4 example payload, plus `acr`."""
    claims: dict[str, Any] = {
        "jti": "9e43f81b64a33f20116179",
        "iss": IDP,
        "sub": "U019488227",
        "aud": RAS,
        "client_id": CLIENT,
        "resource": RESOURCE,
        "scope": "agent.read agent.write",
        "iat": int(NOW.timestamp()),
        "exp": int((NOW + timedelta(minutes=5)).timestamp()),
        "acr": ACR_IAL2,
        "amr": ["pwd", "mfa"],
        "auth_time": int((NOW - timedelta(minutes=1)).timestamp()),
    }
    for k, v in overrides.items():
        if v is _DROP:
            claims.pop(k, None)
        else:
            claims[k] = v
    return claims


_DROP = object()


@pytest.fixture
def mint(idp_key: RSAKey) -> Callable[..., str]:
    def _mint(
        header: dict[str, Any] | None = None,
        key: Any = None,
        alg: str = "RS256",
        **claim_overrides: Any,
    ) -> str:
        signing_key = key if key is not None else idp_key
        h: dict[str, Any] = {"alg": alg, "kid": idp_key.thumbprint(), "typ": "oauth-id-jag+jwt"}
        if header:
            h.update(header)
        return joserfc_jwt.encode(h, _base_claims(**claim_overrides), signing_key, algorithms=[alg])

    return _mint


def _policy(store: Any, **overrides: Any) -> IdJagPolicy:
    idp_overrides = overrides.pop("idp", {})
    idp = TrustedIdP(issuer=IDP, key_store=store, **idp_overrides)
    defaults: dict[str, Any] = dict(
        issuer=RAS,
        trusted_idps={IDP: idp},
        governed_resources=frozenset({RESOURCE}),
    )
    defaults.update(overrides)
    return IdJagPolicy(**defaults)


@pytest.fixture
def validator(idp_store: InMemoryKeyStore) -> IdJagValidator:
    return IdJagValidator(_policy(idp_store), now=lambda: NOW)


def _validate(v: IdJagValidator, token: str, client: str | None = CLIENT) -> Any:
    return v.validate(token, authenticated_client_id=client)


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_appendix_a4_example_validates(validator: IdJagValidator, mint: Callable[..., str]) -> None:
    grant = _validate(validator, mint())
    assert grant.iss == IDP
    assert grant.sub == "U019488227"
    assert grant.client_id == CLIENT
    assert grant.resource == (RESOURCE,)
    assert grant.scope == ("agent.read", "agent.write")
    assert (grant.ial, grant.aal, grant.fal) == (2, 2, 2)
    assert grant.amr == ("pwd", "mfa")
    assert grant.auth_time == NOW - timedelta(minutes=1)
    assert grant.act is None


def test_single_element_aud_array_accepted(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    assert _validate(validator, mint(aud=[RAS])).aud == RAS


def test_resource_array_and_absent_resource_accepted(
    idp_store: InMemoryKeyStore, mint: Callable[..., str]
) -> None:
    other = "https://api2.saas-tool.example/"
    v = IdJagValidator(
        _policy(idp_store, governed_resources=frozenset({RESOURCE, other})), now=lambda: NOW
    )
    assert _validate(v, mint(resource=[RESOURCE, other])).resource == (RESOURCE, other)
    assert _validate(v, mint(resource=_DROP, jti="j2")).resource == ()


def test_es256_accepted(idp_store: InMemoryKeyStore) -> None:
    ec = ECKey.generate_key("P-256")
    store = InMemoryKeyStore({"ec": ECKey.import_key(ec.as_dict(private=False))})
    v = IdJagValidator(_policy(store), now=lambda: NOW)
    token = joserfc_jwt.encode(
        {"alg": "ES256", "kid": "ec", "typ": "oauth-id-jag+jwt"},
        _base_claims(),
        ec,
        algorithms=["ES256"],
    )
    assert _validate(v, token).sub == "U019488227"


def test_act_exposed_verbatim(validator: IdJagValidator, mint: Callable[..., str]) -> None:
    act = {"sub": "agent:planner", "act": {"sub": "agent:root"}}
    assert _validate(validator, mint(act=act)).act == act


def test_typ_compared_case_insensitively_with_application_prefix(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    _validate(validator, mint(header={"typ": "application/OAUTH-ID-JAG+JWT"}))


# --------------------------------------------------------------------------- #
# Header checks (§3, §4.4.1)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("typ", ["JWT", "at+jwt", "agent-passport+jwt"])
def test_wrong_typ_rejected(typ: str, validator: IdJagValidator, mint: Callable[..., str]) -> None:
    """An ID token or access token from the same IdP is not an ID-JAG."""
    with pytest.raises(TokenTypeMismatch):
        _validate(validator, mint(header={"typ": typ}))


def test_hs256_rejected(validator: IdJagValidator, idp_key: RSAKey) -> None:
    token = joserfc_jwt.encode(
        {"alg": "HS256", "kid": idp_key.thumbprint(), "typ": "oauth-id-jag+jwt"},
        _base_claims(),
        OctKey.generate_key(256),
        algorithms=["HS256"],
    )
    with pytest.raises(AlgorithmNotAllowed):
        _validate(validator, token)


def test_missing_kid_rejected(validator: IdJagValidator, mint: Callable[..., str]) -> None:
    with pytest.raises(InvalidToken):
        _validate(validator, mint(header={"kid": ""}))


def test_signature_from_wrong_key_rejected(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    """A forged `iss` selects the trusted IdP's key, which then fails to verify."""
    with pytest.raises(InvalidSignature):
        _validate(validator, mint(key=RSAKey.generate_key(2048)))


def test_unknown_kid_raises_key_not_found(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    with pytest.raises(KeyNotFound):
        _validate(validator, mint(header={"kid": "nope"}))


def test_garbage_rejected(validator: IdJagValidator) -> None:
    with pytest.raises(InvalidToken):
        _validate(validator, "not.a.jwt")


# --------------------------------------------------------------------------- #
# Issuer and tenant (§4.4.1, §6.1)
# --------------------------------------------------------------------------- #


def test_untrusted_issuer_rejected(validator: IdJagValidator, mint: Callable[..., str]) -> None:
    with pytest.raises(UntrustedIssuer):
        _validate(validator, mint(iss="https://evil.example"))


def test_missing_issuer_rejected(validator: IdJagValidator, mint: Callable[..., str]) -> None:
    with pytest.raises(UntrustedIssuer):
        _validate(validator, mint(iss=_DROP))


@pytest.mark.parametrize("tenant", [_DROP, "other-tenant"])
def test_multi_tenant_issuer_requires_trusted_tenant(
    tenant: Any, idp_store: InMemoryKeyStore, mint: Callable[..., str]
) -> None:
    v = IdJagValidator(_policy(idp_store, idp={"tenants": frozenset({"acme"})}), now=lambda: NOW)
    with pytest.raises(UntrustedIssuer):
        _validate(v, mint(tenant=tenant))
    assert _validate(v, mint(tenant="acme", jti="t2")).tenant == "acme"


# --------------------------------------------------------------------------- #
# Required claims (§3.1)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("claim", ["sub", "client_id", "jti", "exp", "iat"])
def test_missing_required_claim_rejected(
    claim: str, validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    with pytest.raises(MalformedClaims):
        _validate(validator, mint(**{claim: _DROP}))


@pytest.mark.parametrize(
    "overrides",
    [
        {"scope": ["agent.read"]},
        {"resource": []},
        {"resource": [RESOURCE, RESOURCE]},
        {"resource": [1]},
        {"authorization_details": {"type": "x"}},
        {"authorization_details": ["x"]},
        {"tenant": 7},
        {"acr": 2},
    ],
)
def test_malformed_optional_claims_rejected(
    overrides: dict[str, Any], validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    with pytest.raises(MalformedClaims):
        _validate(validator, mint(**overrides))


# --------------------------------------------------------------------------- #
# Audience (§4.4.1)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "aud", ["https://other-as.example/", RESOURCE, [RAS, "https://x/"], [], _DROP]
)
def test_audience_must_be_this_authorization_server(
    aud: Any, validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    """The resource server's URL is not the AS issuer; multi-valued aud is refused."""
    with pytest.raises(AudienceMismatch):
        _validate(validator, mint(aud=aud))


# --------------------------------------------------------------------------- #
# Client continuity and sender constraint (§4.4, §4.4.1, §9.11)
# --------------------------------------------------------------------------- #


def test_client_id_must_match_authenticated_client(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    with pytest.raises(ClientMismatch):
        _validate(validator, mint(), client="https://other-client.example/")


def test_unauthenticated_client_rejected_as_invalid_client(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    with pytest.raises(ClientAuthenticationRequired) as exc:
        _validate(validator, mint(), client=None)
    assert oauth_error_for(exc.value) == "invalid_client"


def test_cnf_bound_grant_rejected_because_pop_unsupported(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    with pytest.raises(SenderConstraintUnsupported) as exc:
        _validate(validator, mint(cnf={"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}))
    assert oauth_error_for(exc.value) == "invalid_grant"


# --------------------------------------------------------------------------- #
# Time (§4.4.3, §4.4.4)
# --------------------------------------------------------------------------- #


def test_expired_rejected(validator: IdJagValidator, mint: Callable[..., str]) -> None:
    with pytest.raises(Expired):
        _validate(
            validator,
            mint(
                iat=int((NOW - timedelta(minutes=10)).timestamp()),
                exp=int((NOW - timedelta(minutes=5)).timestamp()),
            ),
        )


def test_expired_within_skew_accepted(validator: IdJagValidator, mint: Callable[..., str]) -> None:
    _validate(
        validator,
        mint(
            iat=int((NOW - timedelta(minutes=5)).timestamp()),
            exp=int((NOW - timedelta(seconds=20)).timestamp()),
        ),
    )


def test_iat_in_future_rejected(validator: IdJagValidator, mint: Callable[..., str]) -> None:
    with pytest.raises(NotYetValid):
        _validate(validator, mint(iat=int((NOW + timedelta(minutes=2)).timestamp())))


def test_nbf_in_future_rejected(validator: IdJagValidator, mint: Callable[..., str]) -> None:
    with pytest.raises(NotYetValid):
        _validate(validator, mint(nbf=int((NOW + timedelta(minutes=2)).timestamp())))


def test_lifetime_over_policy_maximum_rejected(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    with pytest.raises(LifetimeTooLong):
        _validate(validator, mint(exp=int((NOW + timedelta(hours=1)).timestamp())))


# --------------------------------------------------------------------------- #
# Resource (§4.4.1)
# --------------------------------------------------------------------------- #


def test_resource_not_governed_rejected(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    with pytest.raises(ResourceNotGoverned):
        _validate(validator, mint(resource=[RESOURCE, "https://elsewhere.example/"]))


def test_resource_compared_by_simple_string_comparison(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    """RFC 3986 §6.2.1: no normalization. A missing trailing slash is a different URI."""
    with pytest.raises(ResourceNotGoverned):
        _validate(validator, mint(resource=RESOURCE.rstrip("/")))


# --------------------------------------------------------------------------- #
# NIST SP 800-63-3 floors on the IdP's acr
# --------------------------------------------------------------------------- #


def test_ial_floor_met(idp_store: InMemoryKeyStore, mint: Callable[..., str]) -> None:
    v = IdJagValidator(_policy(idp_store, require_ial=2), now=lambda: NOW)
    assert _validate(v, mint()).ial == 2


@pytest.mark.parametrize(
    "acr",
    [
        "http://idmanagement.gov/ns/assurance/ial/1",
        # Legacy LOA-3 is IAL-2 under the conservative default mapping.
        "http://idmanagement.gov/ns/assurance/loa/3",
        "urn:vendor:mfa",  # untranslatable → no asserted assurance
        _DROP,
    ],
)
def test_ial_floor_rejects_insufficient_or_unknown_acr(
    acr: Any, idp_store: InMemoryKeyStore, mint: Callable[..., str]
) -> None:
    v = IdJagValidator(_policy(idp_store, require_ial=3), now=lambda: NOW)
    with pytest.raises(IALInsufficient) as exc:
        _validate(v, mint(acr=acr))
    assert oauth_error_for(exc.value) == "invalid_grant"


def test_unknown_acr_without_floor_yields_no_levels(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    grant = _validate(validator, mint(acr="urn:vendor:mfa"))
    assert grant.acr == "urn:vendor:mfa"
    assert grant.ial is None


def test_per_idp_acr_mapping(idp_store: InMemoryKeyStore, mint: Callable[..., str]) -> None:
    def vendor(acr: str) -> AssuranceLevels:
        return AssuranceLevels(ial=2, aal=3, fal=2)

    v = IdJagValidator(
        _policy(idp_store, require_aal=3, idp={"acr_mapping": vendor}), now=lambda: NOW
    )
    assert _validate(v, mint(acr="urn:vendor:phr")).aal == 3


# --------------------------------------------------------------------------- #
# Replay (§4.4.4)
# --------------------------------------------------------------------------- #


def test_replay_rejected(validator: IdJagValidator, mint: Callable[..., str]) -> None:
    token = mint()
    _validate(validator, token)
    with pytest.raises(ReplayDetected):
        _validate(validator, token)


def test_failed_validation_does_not_burn_jti(
    validator: IdJagValidator, mint: Callable[..., str]
) -> None:
    token = mint()
    with pytest.raises(ClientMismatch):
        _validate(validator, token, client="https://other.example/")
    _validate(validator, token)  # the legitimate client can still redeem it


def test_replay_cache_scoped_by_issuer() -> None:
    cache = InMemoryReplayCache(now=lambda: NOW)
    exp = NOW + timedelta(minutes=5)
    assert cache.check_and_store("a\x00j", exp)
    assert cache.check_and_store("b\x00j", exp)
    assert not cache.check_and_store("a\x00j", exp)


def test_replay_cache_evicts_expired_entries() -> None:
    clock = [NOW]
    cache = InMemoryReplayCache(now=lambda: clock[0])
    assert cache.check_and_store("k", NOW + timedelta(seconds=10))
    clock[0] = NOW + timedelta(seconds=11)
    assert cache.check_and_store("k", NOW + timedelta(minutes=5))


# --------------------------------------------------------------------------- #
# Policy construction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "overrides",
    [
        {"trusted_idps": {}},
        {"governed_resources": frozenset()},
        {"clock_skew": timedelta(seconds=121)},
        {"max_lifetime": timedelta(0)},
        {"require_ial": 4},
    ],
)
def test_policy_rejects_unsafe_configuration(
    overrides: dict[str, Any], idp_store: InMemoryKeyStore
) -> None:
    with pytest.raises(ValueError):
        _policy(idp_store, **overrides)


def test_policy_rejects_mismatched_trusted_idp_key(idp_store: InMemoryKeyStore) -> None:
    with pytest.raises(ValueError):
        IdJagPolicy(
            issuer=RAS,
            trusted_idps={"https://a/": TrustedIdP(issuer=IDP, key_store=idp_store)},
            governed_resources=frozenset({RESOURCE}),
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"allowed_algorithms": frozenset()},
        {"allowed_algorithms": frozenset({"RS256", "none"})},
        {"tenants": frozenset()},
    ],
)
def test_trusted_idp_rejects_unsafe_configuration(
    overrides: dict[str, Any], idp_store: InMemoryKeyStore
) -> None:
    with pytest.raises(ValueError):
        TrustedIdP(issuer=IDP, key_store=idp_store, **overrides)


# --------------------------------------------------------------------------- #
# End to end: ID-JAG → Passport access token → MCP-server verifier
# --------------------------------------------------------------------------- #


@pytest.fixture
def ras_issuer() -> Issuer:
    class _NoOIDC:
        def validate(self, id_token: str) -> Any:
            raise AssertionError("ID-JAG path must not touch the OIDC client")

    return Issuer(RAS, RSAKey.generate_key(2048), _NoOIDC(), now=lambda: NOW)


def test_id_jag_to_passport_end_to_end(
    idp_store: InMemoryKeyStore, mint: Callable[..., str], ras_issuer: Issuer
) -> None:
    v = IdJagValidator(_policy(idp_store, require_ial=2), now=lambda: NOW)
    grant = _validate(v, mint())
    token = ras_issuer.issue_from_id_jag(
        IdJagIssuanceRequest(
            grant=grant,
            audience=RESOURCE,
            agent_model="claude-opus-5-5",
            tool_scope=["tickets:read"],
        )
    )
    verifier = Verifier(
        VerificationPolicy(
            issuers=frozenset({RAS}),
            audience=RESOURCE,
            require_ial=2,
            require_typ=True,
            required_scope="tickets:read",
        ),
        InMemoryKeyStore({ras_issuer.kid: ras_issuer.public_jwk}),
        now=lambda: NOW,
    )
    passport = verifier.verify(token).passport
    assert passport.sub == grant.sub
    assert passport.ial == 2
    assert passport.acr == ACR_IAL2
    assert passport.agent.agent_id == CLIENT  # defaults to client_id
    assert passport.act.sub == CLIENT


def test_passport_audience_must_be_a_granted_resource(
    validator: IdJagValidator, mint: Callable[..., str], ras_issuer: Issuer
) -> None:
    grant = _validate(validator, mint())
    with pytest.raises(IssuanceError):
        ras_issuer.issue_from_id_jag(
            IdJagIssuanceRequest(
                grant=grant, audience="https://not-granted.example/", agent_model="m"
            )
        )


def test_explicit_agent_id_overrides_client_id(
    validator: IdJagValidator, mint: Callable[..., str], ras_issuer: Issuer
) -> None:
    grant = _validate(validator, mint())
    token = ras_issuer.issue_from_id_jag(
        IdJagIssuanceRequest(
            grant=grant, audience=RESOURCE, agent_model="m", agent_id="agent:triage"
        )
    )
    p = ras_issuer.verify_own(token).passport
    assert p.agent.agent_id == "agent:triage"


def test_token_type_uri_constant() -> None:
    assert ID_JAG_TOKEN_TYPE == "urn:ietf:params:oauth:token-type:id-jag"


# --------------------------------------------------------------------------- #
# DiscoveryKeyStore (§7.1, §9.5)
# --------------------------------------------------------------------------- #


@pytest.fixture
def http() -> Iterator[httpx.Client]:
    client = httpx.Client(timeout=5.0)
    yield client
    client.close()


def test_discovery_key_store_falls_back_to_oidc_discovery(
    mock_oidc: MockOIDCProvider, http: httpx.Client
) -> None:
    """The mock serves no RFC 8414 doc (404), only OIDC Discovery."""
    store = DiscoveryKeyStore(mock_oidc.issuer, http)
    assert store.get(mock_oidc.kid) is not None
    assert store.metadata()["issuer"] == mock_oidc.issuer


def test_discovery_key_store_validates_id_jag_end_to_end(
    mock_oidc: MockOIDCProvider, http: httpx.Client
) -> None:
    store = DiscoveryKeyStore(mock_oidc.issuer, http)
    policy = IdJagPolicy(
        issuer=RAS,
        trusted_idps={mock_oidc.issuer: TrustedIdP(issuer=mock_oidc.issuer, key_store=store)},
        governed_resources=frozenset({RESOURCE}),
    )
    token = joserfc_jwt.encode(
        {"alg": "RS256", "kid": mock_oidc.kid, "typ": "oauth-id-jag+jwt"},
        _base_claims(iss=mock_oidc.issuer),
        mock_oidc._key,
        algorithms=["RS256"],
    )
    grant = IdJagValidator(policy, now=lambda: NOW).validate(token, authenticated_client_id=CLIENT)
    assert grant.iss == mock_oidc.issuer


def test_discovery_key_store_rejects_issuer_mismatch(
    mock_oidc: MockOIDCProvider, http: httpx.Client
) -> None:
    """§9.5 / RFC 8414 §3.3: metadata must name the issuer we asked about."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("oauth-authorization-server"):
            return httpx.Response(
                200, json={"issuer": "https://attacker.example", "jwks_uri": "https://x/j"}
            )
        return httpx.Response(404)

    store = DiscoveryKeyStore(IDP, httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(DiscoveryError):
        store.get("k")


def test_discovery_key_store_uses_rfc8414_path_insertion() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(404)

    store = DiscoveryKeyStore(
        "https://idp.example.com/tenant1", httpx.Client(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(DiscoveryError):
        store.metadata()
    assert seen == [
        "https://idp.example.com/.well-known/oauth-authorization-server/tenant1",
        "https://idp.example.com/tenant1/.well-known/openid-configuration",
    ]


def test_discovery_key_store_rate_limits_kid_miss_refetch(
    mock_oidc: MockOIDCProvider, http: httpx.Client
) -> None:
    clock = [NOW]
    store = DiscoveryKeyStore(mock_oidc.issuer, http, now=lambda: clock[0])
    with pytest.raises(KeyNotFound):
        store.get("random-1")
    calls: list[str] = []
    original_get = http.get

    def counting_get(url: Any, **kw: Any) -> httpx.Response:
        calls.append(str(url))
        return original_get(url, **kw)

    http.get = counting_get  # type: ignore[method-assign]
    with pytest.raises(KeyNotFound):
        store.get("random-2")
    assert calls == []  # within min_refresh_interval: no network
    assert store.get(mock_oidc.kid) is not None  # cached by the first fetch
    assert calls == []
    clock[0] = NOW + timedelta(seconds=31)
    with pytest.raises(KeyNotFound):
        store.get("random-3")
    assert len(calls) == 1  # interval elapsed: metadata still cached, one JWKS fetch
    assert calls[0] == mock_oidc.jwks_uri
