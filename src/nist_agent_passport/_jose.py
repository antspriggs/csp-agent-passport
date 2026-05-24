"""Internal JOSE helpers shared by the issuer and verifier."""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from nist_agent_passport.errors import InvalidToken


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
