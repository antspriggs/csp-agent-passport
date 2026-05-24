"""Public-key resolution for the verifier.

v0 ships a single in-memory store. The `KeyStore` Protocol is the seam where
a future JWKS-over-HTTPS fetcher (with `kid` cache + miss refresh) plugs in
without touching the verifier.
"""

from __future__ import annotations

from typing import Any, Protocol

from nist_agent_passport.errors import KeyNotFound


class KeyStore(Protocol):
    """Resolve a public key by its JWS `kid` header value.

    Implementations MUST raise `KeyNotFound` (not `KeyError`) on miss so the
    verifier can map the failure to a typed error without leaking dict semantics.
    The returned value is whatever the verifier's JWS library accepts as a
    public key (e.g., an `authlib.jose.JsonWebKey`).
    """

    def get(self, kid: str) -> Any: ...


class InMemoryKeyStore:
    """Dict-backed `KeyStore`. Suitable for tests and v0 single-key issuers."""

    def __init__(self, keys: dict[str, Any] | None = None) -> None:
        self._keys: dict[str, Any] = dict(keys) if keys else {}

    def add(self, kid: str, key: Any) -> None:
        self._keys[kid] = key

    def get(self, kid: str) -> Any:
        try:
            return self._keys[kid]
        except KeyError as e:
            raise KeyNotFound(kid) from e
