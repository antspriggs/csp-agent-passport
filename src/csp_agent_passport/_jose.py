"""Internal JOSE helpers shared by the issuer and verifier."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from csp_agent_passport.errors import InvalidToken


def parse_jws_header(token: str) -> dict[str, Any]:
    """Parse the *unverified* JWS header for alg/kid inspection.

    Used to make alg-allowlist and key-resolution decisions before invoking
    the JOSE library, so we never hand a malformed or `alg:none` token to
    code that might do the wrong thing with it.
    """
    if not isinstance(token, str) or token.count(".") != 2:
        raise InvalidToken("token is not a compact JWS")
    header_b64 = token.split(".", 1)[0]
    if not header_b64:
        raise InvalidToken("JWS header segment is empty")
    padded = header_b64 + "=" * (-len(header_b64) % 4)
    try:
        header_bytes = base64.urlsafe_b64decode(padded)
        header = json.loads(header_bytes)
    except (binascii.Error, ValueError) as e:
        raise InvalidToken(f"could not decode JWS header: {e}") from e
    if not isinstance(header, dict):
        raise InvalidToken("JWS header is not a JSON object")
    return header


# --------------------------------------------------------------------------- #
# Explicit typing (RFC 8725 §3.11)
# --------------------------------------------------------------------------- #

# DESIGN NOTE — Passport media type
# ---------------------------------
# `agent-passport+jwt` is an unregistered media-type suffix in the RFC 8725
# §3.11 style (`application/agent-passport+jwt`, with the `application/`
# prefix dropped per RFC 7515 §4.1.9). It exists so verifiers can tell a
# Passport apart from an ID token, an RFC 9068 access token, or an ID-JAG
# without inspecting claims. If the claim namespace is ever registered, the
# media type should be registered alongside it.
PASSPORT_TYP = "agent-passport+jwt"

# draft-ietf-oauth-identity-assertion-authz-grant-06 §3.
ID_JAG_TYP = "oauth-id-jag+jwt"

# JWT `typ` values that positively identify a token as something OTHER than
# an OIDC ID token. ID-JAG -06 §4.3.3 requires a token-exchange server to
# reject a subject token "if it has a typ header naming a different token
# type"; access tokens, ID-JAGs, and client assertions MUST NOT be accepted as
# identity assertions. An allowlist would be stricter, but real CSPs send
# ID tokens with `typ` absent, `JWT`, or vendor values, so an allowlist breaks
# interop. The denylist covers every registered JWT type that a CSP could
# plausibly sign with the same key as its ID tokens.
NON_ID_TOKEN_TYPS: frozenset[str] = frozenset(
    {
        "at+jwt",  # RFC 9068 access token
        ID_JAG_TYP,
        PASSPORT_TYP,
        "logout+jwt",  # OIDC Back-Channel Logout
        "secevent+jwt",  # RFC 8417 Security Event Token
        "dpop+jwt",  # RFC 9449 DPoP proof
        "token-introspection+jwt",  # RFC 9701
        "client-authentication+jwt",  # draft-ietf-oauth-rfc7523bis
        "txn_token",  # draft-ietf-oauth-transaction-tokens (no +jwt suffix)
        "wit+jwt",  # WIMSE workload identity token
    }
)


def normalize_typ(typ: object) -> str | None:
    """Canonicalize a JWS `typ` header value for comparison.

    RFC 7515 §4.1.9: media type names are case-insensitive and the
    `application/` prefix SHOULD be omitted, so `application/AT+JWT` and
    `at+jwt` are the same type. Non-string values return None and are
    treated by callers as malformed.
    """
    if not isinstance(typ, str):
        return None
    lowered = typ.strip().lower()
    if lowered.startswith("application/"):
        lowered = lowered[len("application/") :]
    return lowered
