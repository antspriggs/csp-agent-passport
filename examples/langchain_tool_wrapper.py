"""Agent Passport wrapper for LangChain-style tools.

Run from project root:

    .venv/bin/python examples/langchain_tool_wrapper.py

Pattern: wrap any tool so it requires a verified Agent Passport whose
`tool_scope` covers the tool's declared scope before the underlying function
runs. The wrapper is shape-compatible with `langchain_core.tools.BaseTool`
(`.name`, `.description`, `.run(...)`), so it slots into LangChain agent
loops without modification.

This example does not import LangChain — the wrapper is small enough to
demonstrate the pattern standalone, and importing LangChain would force a
heavy dependency on every example user. To use with real LangChain:

    pip install langchain-core
    # Then either:
    #   (a) Use `PassportProtectedTool` directly — its interface matches
    #       BaseTool.run().
    #   (b) Subclass BaseTool and copy the verify+scope-check pattern from
    #       PassportProtectedTool._invoke() into your _run() method.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, field
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
TOOL_AUDIENCE = "https://tool-host.example.com/"


# --------------------------------------------------------------------------- #
# The wrapper
# --------------------------------------------------------------------------- #


@dataclass
class PassportProtectedTool:
    """A tool that requires a verified Agent Passport before running.

    Shape-compatible with LangChain's `BaseTool`. Drop into any agent loop
    that calls `tool.run(<input>)` — pass the Passport JWS as the first
    positional input (and the chain as `chain=...` if present).

    The wrapper is responsible for two things:
      1. Verifying the Passport via the injected `Verifier`.
      2. Enforcing that `tool_scope` covers this tool's `required_scope`.
    """

    name: str
    description: str
    required_scope: str
    verifier: Verifier
    func: Callable[..., Any]
    # Standard LangChain BaseTool attributes (defaults match BaseTool's).
    return_direct: bool = False
    args_schema: Any = field(default=None)

    def run(self, token: str, *, chain: tuple[str, ...] = (), **kwargs: Any) -> Any:
        """Verify the Passport, then invoke the underlying function."""
        return self._invoke(token=token, chain=chain, kwargs=kwargs)

    async def arun(self, token: str, *, chain: tuple[str, ...] = (), **kwargs: Any) -> Any:
        return self._invoke(token=token, chain=chain, kwargs=kwargs)

    def _invoke(self, *, token: str, chain: tuple[str, ...], kwargs: dict[str, Any]) -> Any:
        verified: VerifiedPassport = self.verifier.verify(token, chain=chain)
        if not scope_covers_required(verified.passport.agent.tool_scope, self.required_scope):
            raise ScopeViolation(self.required_scope, verified.passport.agent.tool_scope)
        return self.func(verified=verified, **kwargs)


# --------------------------------------------------------------------------- #
# Example tool funcs (would be your real tool implementations)
# --------------------------------------------------------------------------- #


def _get_weather(verified: VerifiedPassport, *, city: str) -> dict[str, Any]:
    return {
        "for_principal": verified.passport.sub,
        "city": city,
        "temp_f": 67,
        "conditions": "partly cloudy",
    }


def _send_email(verified: VerifiedPassport, *, to: str, subject: str, body: str) -> dict[str, Any]:
    return {
        "sent_by": verified.passport.agent.agent_id,
        "on_behalf_of": verified.passport.sub,
        "to": to,
        "subject": subject,
        "body_preview": body[:40] + ("..." if len(body) > 40 else ""),
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
            tool_verifier = Verifier(
                policy=VerificationPolicy(
                    issuers=frozenset({issuer.issuer_url}),
                    audience=TOOL_AUDIENCE,
                    require_ial=2,
                ),
                key_store=key_store,
            )

            weather = PassportProtectedTool(
                name="get_weather",
                description="Get current weather for a city.",
                required_scope="weather:read",
                verifier=tool_verifier,
                func=_get_weather,
            )
            email = PassportProtectedTool(
                name="send_email",
                description="Send an email on the user's behalf.",
                required_scope="email:send",
                verifier=tool_verifier,
                func=_send_email,
            )

            id_token = csp.mint_id_token(sub="user-alice", acr=ACR_IAL2, aud=CLIENT_ID)

            section("1. Read-only Passport (weather:read) calls get_weather")
            read_only = issuer.issue(
                IssuanceRequest(
                    id_token=id_token,
                    audience=TOOL_AUDIENCE,
                    agent_id="agent:alice-research",
                    agent_model="claude-opus-4-7",
                    tool_scope=["weather:read"],
                    task_purpose="check the weather in SF",
                )
            )
            result = weather.run(read_only, city="San Francisco")
            print(f"   [PASS] {result}")

            section("2. Same Passport tries send_email — refused (missing scope)")
            try:
                email.run(read_only, to="b@example.com", subject="hi", body="hello")
                print("   [FAIL] expected ScopeViolation")
            except ScopeViolation as e:
                print(f"   [PASS] tool wrapper refused -> ScopeViolation: {e}")

            section("3. Full Passport (both scopes) succeeds at both tools")
            full = issuer.issue(
                IssuanceRequest(
                    id_token=id_token,
                    audience=TOOL_AUDIENCE,
                    agent_id="agent:alice-assistant",
                    agent_model="claude-opus-4-7",
                    tool_scope=["weather:read", "email:send"],
                    task_purpose="research and send a weather update email",
                )
            )
            print(f"   weather: {weather.run(full, city='New York')}")
            print(
                f"   email:   "
                f"{email.run(full, to='b@example.com', subject='NYC weather', body='Sunny, 72F.')}"
            )

            section("4. Tampered Passport — flip a byte in the signature")
            tampered = full[:-4] + "AAAA"
            try:
                weather.run(tampered, city="Anywhere")
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
