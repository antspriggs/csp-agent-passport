"""Pydantic models for the Agent Passport delegation token claim schema.

This module knows the shape of a Passport and how to round-trip it through a
JWT payload (JSON dict). It does not sign, verify, or fetch keys — that is
the job of `issuer.py` and `verifier.py`.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

AGENT_PASSPORT_CLAIM_NS = "https://agent-passport.org/claims/"

_AGENT_CLAIM_KEYS: tuple[str, ...] = (
    "agent_id",
    "agent_model",
    "tool_scope",
    "task_purpose",
    "parent_jti",
)


def _ns(name: str) -> str:
    return AGENT_PASSPORT_CLAIM_NS + name


class ActClaim(BaseModel):
    """RFC 8693 §4.1 `act` claim — the actor acting on the principal's behalf.

    Per RFC 8693 the `act` claim may itself contain a nested `act` to express
    a chain of actors. That nested form is the *conceptual* delegation chain.
    The token-issuance chain (one Passport's jti pointing to its parent's) is
    tracked separately in `AgentClaims.parent_jti`.
    """

    model_config = ConfigDict(extra="allow")

    sub: str
    act: ActClaim | None = None


class AgentClaims(BaseModel):
    """Agent Passport's namespaced agent-specific claims.

    These are a logical group in Python. When rendered to a JWT payload via
    `Passport.to_jwt_claims`, each field is spread as a top-level key under
    the `https://agent-passport.org/claims/` namespace.
    """

    agent_id: str
    agent_model: str
    tool_scope: list[str] = Field(default_factory=list)
    task_purpose: str | None = None
    parent_jti: str | None = None


class Passport(BaseModel):
    """An Agent Passport delegation token's claim set (unsigned payload)."""

    iss: str
    sub: str
    aud: str
    iat: AwareDatetime
    exp: AwareDatetime
    nbf: AwareDatetime
    jti: str

    # NIST 800-63-3 identity-assurance claims. All optional: OIDC's `acr` is
    # itself optional, and scope-driven auth (where authorization comes from
    # `tool_scope` alone, with no asserted identity assurance) is a supported
    # and common deployment mode. A verifier that requires any of these sets
    # the corresponding `require_*` to >= 1 in its `VerificationPolicy`.
    acr: str | None = None
    ial: int | None = Field(default=None, ge=1, le=3)
    aal: int | None = Field(default=None, ge=1, le=3)
    fal: int | None = Field(default=None, ge=1, le=3)

    act: ActClaim

    agent: AgentClaims

    def to_jwt_claims(self) -> dict[str, Any]:
        """Render to a JSON-serializable dict suitable as a JWT payload.

        Datetimes become integer Unix timestamps. `AgentClaims` fields are
        spread to top-level keys under the nist-agent-passport namespace; None-
        valued optional claims (including `acr`/`ial`/`aal`/`fal` when not
        asserted) are omitted entirely (not serialized as `null`).
        """
        out: dict[str, Any] = {
            "iss": self.iss,
            "sub": self.sub,
            "aud": self.aud,
            "iat": int(self.iat.timestamp()),
            "exp": int(self.exp.timestamp()),
            "nbf": int(self.nbf.timestamp()),
            "jti": self.jti,
            "act": self.act.model_dump(exclude_none=True),
        }
        if self.acr is not None:
            out["acr"] = self.acr
        if self.ial is not None:
            out["ial"] = self.ial
        if self.aal is not None:
            out["aal"] = self.aal
        if self.fal is not None:
            out["fal"] = self.fal
        for key, value in self.agent.model_dump(exclude_none=True).items():
            out[_ns(key)] = value
        return out

    @classmethod
    def from_jwt_claims(cls, claims: Mapping[str, Any]) -> Passport:
        """Inverse of `to_jwt_claims`. Reads namespaced agent claims back into
        an `AgentClaims` and rehydrates Unix timestamps as tz-aware UTC datetimes.
        """
        agent_data: dict[str, Any] = {}
        for key in _AGENT_CLAIM_KEYS:
            ns_key = _ns(key)
            if ns_key in claims:
                agent_data[key] = claims[ns_key]

        return cls(
            iss=claims["iss"],
            sub=claims["sub"],
            aud=claims["aud"],
            iat=datetime.fromtimestamp(claims["iat"], tz=UTC),
            exp=datetime.fromtimestamp(claims["exp"], tz=UTC),
            nbf=datetime.fromtimestamp(claims["nbf"], tz=UTC),
            jti=claims["jti"],
            acr=claims.get("acr"),
            ial=claims.get("ial"),
            aal=claims.get("aal"),
            fal=claims.get("fal"),
            act=ActClaim.model_validate(claims["act"]),
            agent=AgentClaims.model_validate(agent_data),
        )
