"""Agent Passport issuer.

Takes a CSP-issued OIDC ID token, validates it via the configured `OIDCClient`,
and mints a signed Agent Passport delegation token (RFC 8693 token exchange).

The issuer knows nothing about specific CSPs — the `OIDCClient` Protocol is
the seam where any OIDC + PKCE provider plugs in. Chain delegation
(child-token minting) lives in this module too via `delegate()`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from uuid import uuid4

from joserfc import jwt as joserfc_jwt
from joserfc.jwk import RSAKey

from nist_agent_passport._clock import NowCallable, default_now
from nist_agent_passport._scope import scope_attenuates
from nist_agent_passport.claims import ActClaim, AgentClaims, Passport
from nist_agent_passport.errors import ScopeAttenuationError
from nist_agent_passport.oidc.base import OIDCClient
from nist_agent_passport.verifier import VerifiedPassport

DEFAULT_TTL = timedelta(minutes=15)
DEFAULT_CHILD_TTL = timedelta(minutes=5)


@dataclass(frozen=True)
class IssuanceRequest:
    """Inputs to a root-token issuance.

    `id_token`: the OIDC ID token from the CSP — proves who the principal is.
    `audience`: the verifier's identifier (e.g., MCP server URL); becomes `aud`.
    `agent_id`/`agent_model`: the agent acting on the principal's behalf.
    `tool_scope`: explicit tool/endpoint allowlist. Empty = no authority.
    `task_purpose`: short audit-only description; never used for policy.
    `ttl`: token lifetime. None → issuer's `default_ttl`.
    """

    id_token: str
    audience: str
    agent_id: str
    agent_model: str
    tool_scope: list[str] = field(default_factory=list)
    task_purpose: str | None = None
    ttl: timedelta | None = None


@dataclass(frozen=True)
class DelegationRequest:
    """Inputs to a child-token mint (sub-delegation).

    `parent`: a Passport already verified by a Verifier. The issuer trusts the
    structured proof — defense in depth comes at verification time when the
    downstream verifier walks the chain again.
    `audience`: the child's audience; may differ from the parent's.
    `agent_id`/`agent_model`: the agent receiving the delegation.
    `tool_scope`: MUST be a subset of `parent.passport.agent.tool_scope`.
        Enforced at issuance via `_scope.scope_attenuates`.
    `task_purpose`: short audit-only description.
    `ttl`: child lifetime; defaults to 5 minutes per CLAUDE.md (sub-delegated
        tokens should be short-lived).

    The child Passport inherits the principal's `sub`, `acr`, and IAL/AAL/FAL
    from the parent (NIST 800-63-3 levels propagate; the principal can't be
    re-asserted by an agent). The child's `act` claim wraps the parent's,
    forming an RFC 8693 actor chain.
    """

    parent: VerifiedPassport
    audience: str
    agent_id: str
    agent_model: str
    tool_scope: list[str] = field(default_factory=list)
    task_purpose: str | None = None
    ttl: timedelta | None = None


class Issuer:
    """Mints Agent Passport delegation tokens from validated OIDC ID tokens."""

    def __init__(
        self,
        issuer_url: str,
        signing_key: RSAKey,
        oidc_client: OIDCClient,
        default_ttl: timedelta = DEFAULT_TTL,
        now: NowCallable = default_now,
    ) -> None:
        self._issuer_url = issuer_url
        self._signing_key = signing_key
        self._kid = signing_key.thumbprint()
        self._oidc = oidc_client
        self._default_ttl = default_ttl
        self._now = now

    @property
    def issuer_url(self) -> str:
        return self._issuer_url

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def public_jwk(self) -> RSAKey:
        """Public-only view of the signing key for verifiers' key stores."""
        return RSAKey.import_key(self._signing_key.as_dict(private=False))

    def issue(self, request: IssuanceRequest) -> str:
        """Validate the CSP ID token and mint a signed root Passport (JWS)."""
        assertion = self._oidc.validate(request.id_token)
        now = self._now()
        ttl = request.ttl if request.ttl is not None else self._default_ttl
        passport = Passport(
            iss=self._issuer_url,
            sub=assertion.sub,
            aud=request.audience,
            iat=now,
            nbf=now,
            exp=now + ttl,
            jti=str(uuid4()),
            acr=assertion.acr,
            ial=assertion.ial,
            aal=assertion.aal,
            fal=assertion.fal,
            act=ActClaim(sub=request.agent_id),
            agent=AgentClaims(
                agent_id=request.agent_id,
                agent_model=request.agent_model,
                tool_scope=list(request.tool_scope),
                task_purpose=request.task_purpose,
            ),
        )
        return self._sign(passport)

    def delegate(self, request: DelegationRequest) -> str:
        """Mint a signed child Passport (JWS) from a verified parent token.

        Enforces scope attenuation at issuance (defense in depth — the verifier
        re-checks at chain walk). The child inherits the principal's `sub` and
        the chain's CSP-attested IAL/AAL/FAL/`acr`; the agent acting cannot
        raise these.
        """
        parent = request.parent.passport
        if not scope_attenuates(request.tool_scope, parent.agent.tool_scope):
            raise ScopeAttenuationError(request.tool_scope, parent.agent.tool_scope)

        now = self._now()
        ttl = request.ttl if request.ttl is not None else DEFAULT_CHILD_TTL
        child = Passport(
            iss=self._issuer_url,
            sub=parent.sub,
            aud=request.audience,
            iat=now,
            nbf=now,
            exp=now + ttl,
            jti=str(uuid4()),
            acr=parent.acr,
            ial=parent.ial,
            aal=parent.aal,
            fal=parent.fal,
            act=ActClaim(sub=request.agent_id, act=parent.act),
            agent=AgentClaims(
                agent_id=request.agent_id,
                agent_model=request.agent_model,
                tool_scope=list(request.tool_scope),
                task_purpose=request.task_purpose,
                parent_jti=parent.jti,
            ),
        )
        return self._sign(child)

    def _sign(self, passport: Passport) -> str:
        return joserfc_jwt.encode(
            {"alg": "RS256", "kid": self._kid},
            passport.to_jwt_claims(),
            self._signing_key,
            algorithms=["RS256"],
        )

    def verify_own(self, token: str) -> VerifiedPassport:
        """Verify a token signed by this issuer instance.

        Performs signature + structural + time + iss checks. Does NOT apply
        audience, IAL/AAL/FAL floor, scope, or wildcard policy — those are
        downstream concerns the issuer can't know. Used by the CLI's
        `delegate` command, where the agent holding a parent token wants to
        mint a child without first knowing what downstream policy any future
        verifier will apply.

        Defense in depth still holds: when the resulting child token reaches
        an MCP server, the server's `Verifier.verify(child, chain=...)` will
        re-walk and re-check everything.
        """
        # Build a one-issuer, one-key verifier with the parent's own audience
        # (extracted from the unverified payload) so the audience check
        # collapses to a tautology. Signature mismatches still get caught
        # because the verifier runs joserfc against the kid we know.
        from base64 import urlsafe_b64decode
        from json import loads

        from nist_agent_passport.keys import InMemoryKeyStore
        from nist_agent_passport.policy import VerificationPolicy
        from nist_agent_passport.verifier import Verifier

        try:
            payload_b64 = token.split(".")[1]
            padded = payload_b64 + "=" * (-len(payload_b64) % 4)
            payload = loads(urlsafe_b64decode(padded))
            aud = str(payload.get("aud", ""))
        except (IndexError, ValueError):
            aud = ""  # malformed → Verifier will catch it below

        policy = VerificationPolicy(
            issuers=frozenset({self._issuer_url}),
            audience=aud,
        )
        key_store = InMemoryKeyStore({self._kid: self.public_jwk})
        verifier = Verifier(policy, key_store, now=self._now)
        return verifier.verify(token)
