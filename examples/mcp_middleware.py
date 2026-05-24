"""Agent Passport middleware for MCP-style tool servers.

Run from project root:

    .venv/bin/python examples/mcp_middleware.py

Pattern: wrap a server's tool-call dispatch so every call requires a verified
Agent Passport whose `tool_scope` covers the called tool's declared scope.

This file demonstrates the pattern with a tiny in-memory dispatcher to keep
the example dependency-free. The same `PassportMiddleware` class composes
with the real MCP SDK (`pip install mcp`) by wrapping the server's tool-call
handler at the boundary — see the bottom of this file for the wiring snippet.

Defense-in-depth: the middleware does NOT trust the issuer to have done
attenuation correctly. Every call re-walks the chain (when provided) and
re-checks scope coverage. The middleware is the policy enforcement point.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from joserfc.jwk import RSAKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests" / "fixtures"))

from mock_oidc import MockOIDCProvider

from nist_agent_passport import (
    IDTokenValidator,
    InMemoryKeyStore,
    IssuanceRequest,
    Issuer,
    ScopeViolation,
    VerificationError,
    VerificationPolicy,
    VerifiedPassport,
    Verifier,
    ial_acr_mapping,
)
from nist_agent_passport._scope import scope_covers_required

CLIENT_ID = "nist-agent-passport-issuer"
ACR_IAL2 = "http://idmanagement.gov/ns/assurance/ial/2"
MCP_AUDIENCE = "https://flights-mcp.example.com/"


# --------------------------------------------------------------------------- #
# The middleware
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Tool:
    name: str
    required_scope: str
    handler: Callable[..., Any]


class PassportMiddleware:
    """Wraps a tool dispatcher with Agent Passport verification.

    The middleware is constructed with a `Verifier` whose policy enforces the
    server's audience + IAL floor. The middleware itself enforces per-tool
    `required_scope` so one verifier instance can serve any number of tools.

    Wiring with the real MCP SDK (sketch):

        from mcp.server import Server
        server = Server("flights-mcp")
        mw = PassportMiddleware(verifier=v)
        mw.register("flights.search", "flights:search", _do_search)
        mw.register("flights.book",   "flights:book",   _do_book)

        @server.call_tool()
        async def handle_call(name, args):
            # MCP servers pass the Passport via an auth header / capability;
            # extract it before invoking the middleware.
            token, chain = _extract_passport_from_request_ctx()
            return mw.dispatch(name, args, token=token, chain=chain)
    """

    def __init__(self, verifier: Verifier) -> None:
        self._verifier = verifier
        self._tools: dict[str, _Tool] = {}

    def register(self, name: str, required_scope: str, handler: Callable[..., Any]) -> None:
        self._tools[name] = _Tool(name=name, required_scope=required_scope, handler=handler)

    def dispatch(
        self,
        tool_name: str,
        args: dict[str, Any],
        *,
        token: str,
        chain: Sequence[str] = (),
    ) -> Any:
        if tool_name not in self._tools:
            raise KeyError(f"unknown tool {tool_name!r}")
        tool = self._tools[tool_name]

        # Step 1: full verifier policy (sig, time, iss, aud, IAL/AAL/FAL,
        # wildcard, chain attenuation).
        verified: VerifiedPassport = self._verifier.verify(token, chain=chain)

        # Step 2: per-tool scope check.
        if not scope_covers_required(verified.passport.agent.tool_scope, tool.required_scope):
            raise ScopeViolation(tool.required_scope, verified.passport.agent.tool_scope)

        # Step 3: invoke the handler with the verified principal context.
        return tool.handler(verified=verified, **args)


# --------------------------------------------------------------------------- #
# Example tool handlers
# --------------------------------------------------------------------------- #


def _flights_search(verified: VerifiedPassport, *, origin: str, dest: str) -> dict[str, Any]:
    return {
        "tool": "flights.search",
        "for_principal": verified.passport.sub,
        "results": [
            {"flight": "AA101", "origin": origin, "dest": dest, "price": 312},
            {"flight": "DL202", "origin": origin, "dest": dest, "price": 287},
        ],
    }


def _flights_book(verified: VerifiedPassport, *, flight: str) -> dict[str, Any]:
    return {
        "tool": "flights.book",
        "for_principal": verified.passport.sub,
        "booked_flight": flight,
        "confirmation_code": "AGTPSPRT-9876",
    }


# --------------------------------------------------------------------------- #
# Demo
# --------------------------------------------------------------------------- #


def section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


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

            # Build one Verifier configured for THIS MCP server. Per-tool
            # scope is enforced by the middleware, not the verifier.
            server_verifier = Verifier(
                policy=VerificationPolicy(
                    issuers=frozenset({issuer.issuer_url}),
                    audience=MCP_AUDIENCE,
                    require_ial=2,
                ),
                key_store=key_store,
            )
            mw = PassportMiddleware(verifier=server_verifier)
            mw.register("flights.search", "flights:search", _flights_search)
            mw.register("flights.book", "flights:book", _flights_book)

            section("1. Mint a Passport with scope ['flights:search', 'flights:book']")
            id_token = csp.mint_id_token(sub="user-alice", acr=ACR_IAL2, aud=CLIENT_ID)
            passport = issuer.issue(
                IssuanceRequest(
                    id_token=id_token,
                    audience=MCP_AUDIENCE,
                    agent_id="agent:alice",
                    agent_model="claude-opus-4-7",
                    tool_scope=["flights:search", "flights:book"],
                    task_purpose="find and book a flight SFO->JFK",
                )
            )

            section("2. Call flights.search through the middleware")
            result = mw.dispatch(
                "flights.search",
                args={"origin": "SFO", "dest": "JFK"},
                token=passport,
            )
            print(f"   [PASS] {result}")

            section("3. Call flights.book — same Passport, also in scope")
            result = mw.dispatch(
                "flights.book",
                args={"flight": "AA101"},
                token=passport,
            )
            print(f"   [PASS] {result}")

            section("4. Mint a search-only Passport, then try to book")
            search_only = issuer.issue(
                IssuanceRequest(
                    id_token=id_token,
                    audience=MCP_AUDIENCE,
                    agent_id="agent:read-only",
                    agent_model="claude-opus-4-7",
                    tool_scope=["flights:search"],
                    task_purpose="research only — no bookings",
                )
            )
            try:
                mw.dispatch("flights.book", args={"flight": "AA101"}, token=search_only)
                print("   [FAIL] expected ScopeViolation")
            except ScopeViolation as e:
                print(f"   [PASS] middleware refused -> ScopeViolation: {e}")

            section("5. Wrong audience: Passport for a different MCP server")
            other_server_passport = issuer.issue(
                IssuanceRequest(
                    id_token=id_token,
                    audience="https://other-mcp.example.com/",
                    agent_id="agent:confused",
                    agent_model="claude-opus-4-7",
                    tool_scope=["flights:search", "flights:book"],
                )
            )
            try:
                mw.dispatch("flights.book", args={"flight": "AA101"}, token=other_server_passport)
                print("   [FAIL] expected VerificationError")
            except VerificationError as e:
                print(f"   [PASS] verifier refused -> {type(e).__name__}: {e}")

            section("Done.")
        finally:
            validator.close()
    finally:
        csp.stop()


if __name__ == "__main__":
    main()
