"""Round-trip and validation tests for the claim model."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from nist_agent_passport.claims import (
    AGENT_PASSPORT_CLAIM_NS,
    ActClaim,
    AgentClaims,
    Passport,
)


def _now() -> datetime:
    return datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)


def _example_passport(**overrides: Any) -> Passport:
    now = _now()
    fields: dict[str, Any] = dict(
        iss="https://issuer.example.com",
        sub="psa-abc123",
        aud="https://mcp.example.com/",
        iat=now,
        exp=now + timedelta(minutes=15),
        nbf=now,
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
            task_purpose="book a flight from SFO to JFK",
        ),
    )
    fields.update(overrides)
    return Passport(**fields)


def test_round_trip_basic() -> None:
    original = _example_passport()
    parsed = Passport.from_jwt_claims(original.to_jwt_claims())
    assert parsed == original


def test_round_trip_via_json() -> None:
    """to_jwt_claims output must survive an actual JSON encode/decode."""
    original = _example_passport()
    rendered = json.loads(json.dumps(original.to_jwt_claims()))
    assert Passport.from_jwt_claims(rendered) == original


def test_namespaced_keys_use_full_uri() -> None:
    claims = _example_passport().to_jwt_claims()
    assert claims[f"{AGENT_PASSPORT_CLAIM_NS}agent_id"] == "agent:alice"
    assert claims[f"{AGENT_PASSPORT_CLAIM_NS}agent_model"] == "claude-opus-4-7"
    assert claims[f"{AGENT_PASSPORT_CLAIM_NS}tool_scope"] == [
        "flights:search",
        "flights:book",
    ]
    assert claims[f"{AGENT_PASSPORT_CLAIM_NS}task_purpose"].startswith("book a flight")


def test_optional_claims_omitted_when_none() -> None:
    p = _example_passport(
        agent=AgentClaims(
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=["flights:*"],
        )
    )
    claims = p.to_jwt_claims()
    assert f"{AGENT_PASSPORT_CLAIM_NS}parent_jti" not in claims
    assert f"{AGENT_PASSPORT_CLAIM_NS}task_purpose" not in claims


def test_empty_tool_scope_preserved() -> None:
    """Empty tool_scope (= no authority) must round-trip distinct from absent."""
    p = _example_passport(
        agent=AgentClaims(
            agent_id="agent:alice",
            agent_model="claude-opus-4-7",
            tool_scope=[],
        )
    )
    rendered = p.to_jwt_claims()
    assert rendered[f"{AGENT_PASSPORT_CLAIM_NS}tool_scope"] == []
    parsed = Passport.from_jwt_claims(rendered)
    assert parsed.agent.tool_scope == []


def test_round_trip_with_act_chain() -> None:
    """RFC 8693 nested act chain (3 levels) round-trips."""
    inner = ActClaim(sub="agent:alice")
    middle = ActClaim(sub="agent:bob", act=inner)
    outer = ActClaim(sub="agent:carol", act=middle)
    parsed = Passport.from_jwt_claims(_example_passport(act=outer).to_jwt_claims())
    assert parsed.act.sub == "agent:carol"
    assert parsed.act.act is not None and parsed.act.act.sub == "agent:bob"
    assert parsed.act.act.act is not None and parsed.act.act.act.sub == "agent:alice"
    assert parsed.act.act.act.act is None


def test_round_trip_with_parent_jti() -> None:
    p = _example_passport()
    p.agent.parent_jti = "01J9ZK7XQF3D2P9R8MNX5T6W"
    parsed = Passport.from_jwt_claims(p.to_jwt_claims())
    assert parsed.agent.parent_jti == "01J9ZK7XQF3D2P9R8MNX5T6W"


def test_act_extra_fields_round_trip() -> None:
    """RFC 8693 permits arbitrary actor claims; extras must round-trip."""
    act = ActClaim.model_validate({"sub": "agent:alice", "iss": "https://other-issuer.example.com"})
    p = _example_passport(act=act)
    parsed = Passport.from_jwt_claims(p.to_jwt_claims())
    assert parsed.act.model_dump()["iss"] == "https://other-issuer.example.com"


def test_naive_datetime_rejected() -> None:
    naive = datetime(2026, 5, 15, 12, 0, 0)
    with pytest.raises(ValidationError):
        _example_passport(iat=naive)


@pytest.mark.parametrize("level", [0, 4, -1, 99])
def test_assurance_level_out_of_range_rejected(level: int) -> None:
    with pytest.raises(ValidationError):
        _example_passport(ial=level)
