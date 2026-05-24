"""End-to-end Agent Passport demo.

Run from project root:

    source .venv/bin/activate
    python examples/quickstart.py

Walks through a complete delegation-token issuance:

  1. Boot an in-process mock OIDC provider (stands in for any real CSP).
  2. Show the well-known discovery document driving CSP configuration.
  3. The user "logs in" at the CSP and receives an OIDC ID token at IAL-2.
  4. Configure the Agent Passport issuer and verifier with their own keypair.
  5. Exchange the ID token for an Agent Passport delegation token (RFC 8693).
  6. Decode and pretty-print the Passport claims.
  7. A downstream MCP server verifies the Passport against its policy.
  8. Two failure-mode demos: wrong audience, and IAL-1 token vs IAL-2 policy.

This exercises the entire library surface. To run against a real CSP,
configure `CSP_*` env vars per `.env.example` and use the CLI instead.
"""

from __future__ import annotations

import json
import sys
from base64 import urlsafe_b64decode
from pathlib import Path
from typing import Any

import httpx
from joserfc.jwk import RSAKey

# The mock OIDC provider lives under tests/ — only on sys.path during pytest.
# Inject it manually so this demo (which is not a test) can import it.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests" / "fixtures"))

from mock_oidc import MockOIDCProvider

from nist_agent_passport import (
    AudienceMismatch,
    IALInsufficient,
    IDTokenValidator,
    InMemoryKeyStore,
    IssuanceRequest,
    Issuer,
    VerificationPolicy,
    Verifier,
    ial_acr_mapping,
)


def section(title: str) -> None:
    print()
    print("=" * 72)
    print(title)
    print("=" * 72)


def jwt_payload(token: str) -> dict[str, Any]:
    """Decode a JWT payload for *display only*. No signature check."""
    payload_b64 = token.split(".")[1]
    padded = payload_b64 + "=" * (-len(payload_b64) % 4)
    return json.loads(urlsafe_b64decode(padded))


def main() -> None:
    section("1. Boot a mock OIDC provider (stand-in for any real CSP)")
    csp = MockOIDCProvider().start()
    try:
        print(f"   issuer URL:      {csp.issuer}")
        print(f"   discovery URL:   {csp.discovery_url}")
        print(f"   signing kid:     {csp.kid[:24]}...")

        section("2. Fetch the discovery doc — every other URL flows from this")
        discovery = httpx.get(csp.discovery_url).json()
        print(
            json.dumps(
                {
                    "issuer": discovery["issuer"],
                    "jwks_uri": discovery["jwks_uri"],
                    "id_token_signing_alg_values_supported": discovery[
                        "id_token_signing_alg_values_supported"
                    ],
                },
                indent=2,
            )
        )
        jwks = httpx.get(discovery["jwks_uri"]).json()
        print(f"   JWKS keys: {len(jwks['keys'])}; kid {jwks['keys'][0]['kid'][:24]}...")

        section("3. User authenticates at the CSP — receive an OIDC ID token")
        client_id = "nist-agent-passport-issuer"
        id_token = csp.mint_id_token(
            sub="user-alice-pairwise",
            acr="http://idmanagement.gov/ns/assurance/ial/2",
            aud=client_id,
        )
        print(f"   id_token (truncated): {id_token[:60]}...")
        print("   id_token claims:")
        print(json.dumps(jwt_payload(id_token), indent=2))

        section("4. Configure the Agent Passport issuer + verifier")
        issuer_key = RSAKey.generate_key(2048)
        validator = IDTokenValidator(
            discovery_url=csp.discovery_url,
            client_id=client_id,
            acr_mapping=ial_acr_mapping,
        )
        try:
            issuer = Issuer(
                issuer_url="https://my-passport-issuer.example.com",
                signing_key=issuer_key,
                oidc_client=validator,
            )
            print(f"   issuer URL:    {issuer.issuer_url}")
            print(f"   issuer kid:    {issuer.kid[:24]}...")

            mcp_audience = "https://flights-mcp.example.com/"
            verifier = Verifier(
                policy=VerificationPolicy(
                    issuers=frozenset({issuer.issuer_url}),
                    audience=mcp_audience,
                    require_ial=2,
                    required_scope="flights:book",
                ),
                key_store=InMemoryKeyStore({issuer.kid: issuer.public_jwk}),
            )
            print(f"   verifier aud:  {mcp_audience}")
            print("   policy:        require_ial=2, required_scope='flights:book'")

            section("5. Exchange ID token -> Passport (RFC 8693 token exchange)")
            passport_jwt = issuer.issue(
                IssuanceRequest(
                    id_token=id_token,
                    audience=mcp_audience,
                    agent_id="agent:alice-booking-bot",
                    agent_model="claude-opus-4-7",
                    tool_scope=["flights:search", "flights:book"],
                    task_purpose="book a flight from SFO to JFK on Tuesday",
                )
            )
            print(f"   passport (truncated): {passport_jwt[:60]}...")

            section("6. Decode Passport claims (display only)")
            print(json.dumps(jwt_payload(passport_jwt), indent=2))

            section("7. Downstream MCP server verifies the Passport")
            verified = verifier.verify(passport_jwt)
            p = verified.passport
            print("   [PASS] verification succeeded")
            print(f"     principal sub: {p.sub}")
            print(f"     IAL/AAL/FAL:   {p.ial}/{p.aal}/{p.fal}")
            print(f"     agent:         {p.agent.agent_id} ({p.agent.agent_model})")
            print(f"     tool scope:    {p.agent.tool_scope}")
            print(f"     task purpose:  {p.agent.task_purpose!r}")
            print(f"     valid until:   {p.exp.isoformat()}")

            section("8. Failure modes (defense in depth)")

            wrong_aud_verifier = Verifier(
                policy=VerificationPolicy(
                    issuers=frozenset({issuer.issuer_url}),
                    audience="https://other-server.example.com/",
                    require_ial=2,
                ),
                key_store=InMemoryKeyStore({issuer.kid: issuer.public_jwk}),
            )
            try:
                wrong_aud_verifier.verify(passport_jwt)
                print("   [FAIL] wrong-audience verifier unexpectedly accepted")
            except AudienceMismatch as e:
                print(f"   [PASS] wrong audience rejected -> AudienceMismatch: {e}")

            weak_id_token = csp.mint_id_token(
                sub="user-alice-pairwise",
                acr="http://idmanagement.gov/ns/assurance/ial/1",
                aud=client_id,
            )
            weak_passport = issuer.issue(
                IssuanceRequest(
                    id_token=weak_id_token,
                    audience=mcp_audience,
                    agent_id="agent:alice",
                    agent_model="claude-opus-4-7",
                    tool_scope=["flights:book"],
                )
            )
            try:
                verifier.verify(weak_passport)
                print("   [FAIL] IAL-1 passport unexpectedly accepted by IAL-2 policy")
            except IALInsufficient as e:
                print(f"   [PASS] IAL-1 rejected by IAL-2 policy -> IALInsufficient: {e}")

            section("Done.")
        finally:
            validator.close()
    finally:
        csp.stop()


if __name__ == "__main__":
    main()
