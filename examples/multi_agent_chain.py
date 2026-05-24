"""End-to-end multi-agent delegation chain.

Run from project root:

    .venv/bin/python examples/multi_agent_chain.py

Matches the CLAUDE.md spec for this example:

  1. User authenticates via the (mock) OIDC provider.
  2. User mints a root Passport with broad scope.
  3. Alice delegates a narrower scope to Bob.
  4. Bob delegates a still-narrower scope to Carol.
  5. Carol calls a tool. The tool service's verifier walks the full chain,
     re-checking signatures, time bounds, IAL monotonicity, parent_jti
     linkage, and scope attenuation at every link.
  6. The full delegation tree is printed.

The "tool" here is a tiny in-process function — the point isn't the tool,
it's the chain walk. The same pattern composes with MCP servers (see
mcp_middleware.py) and LangChain tools (see langchain_tool_wrapper.py).
"""

from __future__ import annotations

import json
import sys
from base64 import urlsafe_b64decode
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from joserfc.jwk import RSAKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests" / "fixtures"))

from mock_oidc import MockOIDCProvider

from nist_agent_passport import (
    DelegationRequest,
    IDTokenValidator,
    InMemoryKeyStore,
    IssuanceRequest,
    Issuer,
    Passport,
    VerificationPolicy,
    Verifier,
    ial_acr_mapping,
)

CLIENT_ID = "nist-agent-passport-issuer"
ACR_IAL2 = "http://idmanagement.gov/ns/assurance/ial/2"
SVC_A = "https://service-a.example.com/"
SVC_B = "https://service-b.example.com/"
SVC_TOOL = "https://flights-mcp.example.com/"


def section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def jwt_payload(token: str) -> dict[str, Any]:
    p = token.split(".")[1]
    return json.loads(urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def book_flight_handler(*, sfo: str, jfk: str, on: str) -> dict[str, str]:
    """The 'tool' the leaf agent ultimately calls."""
    return {
        "reservation": f"BOOKED {sfo} -> {jfk} on {on}",
        "confirmation_code": "AGTPSPRT-1234",
    }


def call_tool(
    name: str,
    args: dict[str, Any],
    token: str,
    chain: Sequence[str],
    verifier: Verifier,
    handler: Callable[..., Any],
) -> dict[str, Any]:
    """Verify the token+chain against the tool's policy and invoke the handler.

    This is the seam where a real MCP server / LangChain Tool / HTTP service
    would live. Any verification failure raises a typed `VerificationError`;
    on success the handler runs with the verified principal context.
    """
    verified = verifier.verify(token, chain=chain)
    result = handler(**args)
    return {
        "tool": name,
        "principal_sub": verified.passport.sub,
        "actor_chain": _flatten_act(verified.passport.act),
        "scope_used": verified.passport.agent.tool_scope,
        "chain_depth": len(verified.chain),
        "result": result,
    }


def _flatten_act(act: Any) -> list[str]:
    actors: list[str] = []
    cur = act
    while cur is not None:
        actors.append(cur.sub)
        cur = cur.act
    return actors


def print_delegation_tree(leaf: Passport, parents: Sequence[Passport]) -> None:
    """Pretty-print the full chain root → ... → leaf with key claims at each step."""
    all_passports = [*parents, leaf]
    for depth, p in enumerate(all_passports):
        prefix = "  " * depth + ("|- " if depth else "")
        print(f"{prefix}{p.agent.agent_id} ({p.agent.agent_model})")
        print(f"{'  ' * depth}   aud:        {p.aud}")
        print(f"{'  ' * depth}   scope:      {p.agent.tool_scope}")
        print(f"{'  ' * depth}   jti:        {p.jti}")
        if p.agent.parent_jti:
            print(f"{'  ' * depth}   parent_jti: {p.agent.parent_jti}")
        print(f"{'  ' * depth}   ial/aal/fal: {p.ial}/{p.aal}/{p.fal}")


def main() -> None:
    csp = MockOIDCProvider().start()
    try:
        validator = IDTokenValidator(
            discovery_url=csp.discovery_url,
            client_id=CLIENT_ID,
            acr_mapping=ial_acr_mapping,
        )
        try:
            issuer = Issuer(
                issuer_url="https://my-passport-issuer.example.com",
                signing_key=RSAKey.generate_key(2048),
                oidc_client=validator,
            )
            key_store = InMemoryKeyStore({issuer.kid: issuer.public_jwk})

            def verifier_for(aud: str, **policy_overrides: Any) -> Verifier:
                return Verifier(
                    policy=VerificationPolicy(
                        issuers=frozenset({issuer.issuer_url}),
                        audience=aud,
                        **policy_overrides,
                    ),
                    key_store=key_store,
                )

            # ---- 1 & 2: user authenticates, mints root Passport ---------- #
            section("1-2. User authenticates; Alice receives broad root Passport")
            id_token = csp.mint_id_token(sub="user-alice", acr=ACR_IAL2, aud=CLIENT_ID)
            alice_jwt = issuer.issue(
                IssuanceRequest(
                    id_token=id_token,
                    audience=SVC_A,
                    agent_id="agent:alice",
                    agent_model="claude-opus-4-7",
                    tool_scope=["flights:*", "hotels:*", "calendar:*"],
                    task_purpose="plan a multi-day trip for the user",
                )
            )
            alice = verifier_for(SVC_A).verify(alice_jwt)
            print(f"   alice scope: {alice.passport.agent.tool_scope}")

            # ---- 3: Alice delegates a narrower scope to Bob -------------- #
            section("3. Alice delegates a narrower scope to Bob")
            bob_jwt = issuer.delegate(
                DelegationRequest(
                    parent=alice,
                    audience=SVC_B,
                    agent_id="agent:bob",
                    agent_model="claude-opus-4-7",
                    tool_scope=["flights:*"],
                    task_purpose="find and reserve flights",
                )
            )
            bob = verifier_for(SVC_B).verify(bob_jwt, chain=[alice_jwt])
            print(f"   bob scope:   {bob.passport.agent.tool_scope}")

            # ---- 4: Bob delegates a still-narrower scope to Carol -------- #
            section("4. Bob delegates a still-narrower scope to Carol")
            carol_jwt = issuer.delegate(
                DelegationRequest(
                    parent=bob,
                    audience=SVC_TOOL,
                    agent_id="agent:carol",
                    agent_model="claude-opus-4-7",
                    tool_scope=["flights:book"],
                    task_purpose="book the SFO->JFK flight on 2026-06-12",
                )
            )
            print("   carol scope: ['flights:book']  (just the one tool)")

            # ---- 5: Carol calls a tool; the tool verifies the full chain - #
            section("5. Carol calls flights:book through the tool service")
            tool_verifier = verifier_for(SVC_TOOL, require_ial=2, required_scope="flights:book")
            outcome = call_tool(
                name="flights:book",
                args={"sfo": "SFO", "jfk": "JFK", "on": "2026-06-12"},
                token=carol_jwt,
                chain=[alice_jwt, bob_jwt],
                verifier=tool_verifier,
                handler=book_flight_handler,
            )
            print("   [PASS] tool service verified the chain and executed:")
            print(json.dumps(outcome, indent=2))

            # ---- 6: Print the full delegation tree ------------------------ #
            section("6. Full delegation tree (root -> leaf)")
            verified = tool_verifier.verify(carol_jwt, chain=[alice_jwt, bob_jwt])
            print_delegation_tree(verified.passport, list(verified.chain))

            section("Done.")
        finally:
            validator.close()
    finally:
        csp.stop()


if __name__ == "__main__":
    main()
