"""Public-key resolution for the verifier.

`InMemoryKeyStore` serves tests and single-key issuers. `DiscoveryKeyStore`
resolves keys from an issuer's RFC 8414 / OIDC Discovery metadata and its
`jwks_uri`, with `kid` cache + miss refresh. Both satisfy the `KeyStore`
Protocol, so verifiers never depend on how keys are obtained.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit, urlunsplit

import httpx
from joserfc.jwk import JWKRegistry

from csp_agent_passport.errors import DiscoveryError, JWKSError, KeyNotFound


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


class DiscoveryKeyStore:
    """`KeyStore` that resolves keys from an issuer's published metadata.

    Configured by issuer URL only (CLAUDE.md's well-known-only rule). The
    metadata document is located per RFC 8414 §3 first
    (`/.well-known/oauth-authorization-server`, path-inserted) and falls back
    to OIDC Discovery 1.0 (`<issuer>/.well-known/openid-configuration`), as
    ID-JAG -06 §7.1 permits. The document's `issuer` MUST equal the configured
    issuer (RFC 8414 §3.3; ID-JAG -06 §9.5) or it is rejected.

    Caching: metadata for `metadata_ttl` (default 5 minutes); JWKS keys by
    `kid`, refetched on a `kid` miss. Refetches on miss are rate-limited to
    one per `min_refresh_interval` so a flood of tokens with random `kid`s
    cannot turn the verifier into a request amplifier against the issuer.
    """

    def __init__(
        self,
        issuer: str,
        http: httpx.Client,
        now: Callable[[], datetime] | None = None,
        metadata_ttl: timedelta = timedelta(minutes=5),
        min_refresh_interval: timedelta = timedelta(seconds=30),
    ) -> None:
        self._issuer = issuer
        self._http = http
        self._now = now if now is not None else (lambda: datetime.now(UTC))
        self._metadata_ttl = metadata_ttl
        self._min_refresh = min_refresh_interval
        self._metadata: dict[str, Any] | None = None
        self._metadata_at: datetime | None = None
        self._keys: dict[str, Any] = {}
        self._last_jwks_fetch: datetime | None = None

    @property
    def issuer(self) -> str:
        return self._issuer

    def metadata(self) -> dict[str, Any]:
        """Return the (cached) authorization-server metadata document."""
        now = self._now()
        if (
            self._metadata is not None
            and self._metadata_at is not None
            and now - self._metadata_at < self._metadata_ttl
        ):
            return self._metadata
        errors: list[str] = []
        for url in _metadata_urls(self._issuer):
            try:
                response = self._http.get(url)
                if response.status_code == 404:
                    errors.append(f"{url}: 404")
                    continue
                response.raise_for_status()
                doc = response.json()
            except (httpx.HTTPError, ValueError) as e:
                errors.append(f"{url}: {e}")
                continue
            if not isinstance(doc, dict):
                raise DiscoveryError(f"metadata at {url} is not a JSON object")
            if doc.get("issuer") != self._issuer:
                raise DiscoveryError(
                    f"metadata at {url} names issuer {doc.get('issuer')!r}, "
                    f"expected {self._issuer!r} (RFC 8414 §3.3)"
                )
            if not isinstance(doc.get("jwks_uri"), str):
                raise DiscoveryError(f"metadata at {url} has no jwks_uri")
            self._metadata = doc
            self._metadata_at = now
            return doc
        raise DiscoveryError(f"no metadata found for issuer {self._issuer!r}: {errors}")

    def get(self, kid: str) -> Any:
        if kid in self._keys:
            return self._keys[kid]
        now = self._now()
        if self._last_jwks_fetch is not None and now - self._last_jwks_fetch < self._min_refresh:
            raise KeyNotFound(kid)
        self._last_jwks_fetch = now
        jwks_uri = str(self.metadata()["jwks_uri"])
        try:
            response = self._http.get(jwks_uri)
            response.raise_for_status()
            jwks = response.json()
        except (httpx.HTTPError, ValueError) as e:
            raise JWKSError(f"could not fetch JWKS from {jwks_uri}: {e}") from e
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise JWKSError(f"JWKS at {jwks_uri} is not a valid JWKS object")
        fresh: dict[str, Any] = {}
        for key_dict in jwks["keys"]:
            if isinstance(key_dict, dict) and isinstance(key_dict.get("kid"), str):
                fresh[key_dict["kid"]] = JWKRegistry.import_key(key_dict)
        # Replace rather than merge so keys the issuer has retired stop
        # verifying once the JWKS is refreshed.
        self._keys = fresh
        if kid not in self._keys:
            raise KeyNotFound(kid)
        return self._keys[kid]


def _metadata_urls(issuer: str) -> list[str]:
    """RFC 8414 §3.1 path-inserted URL, then the OIDC Discovery URL."""
    parts = urlsplit(issuer)
    path = parts.path.rstrip("/")
    rfc8414 = urlunsplit(
        (parts.scheme, parts.netloc, "/.well-known/oauth-authorization-server" + path, "", "")
    )
    oidc = issuer.rstrip("/") + "/.well-known/openid-configuration"
    return [rfc8414, oidc] if rfc8414 != oidc else [rfc8414]
