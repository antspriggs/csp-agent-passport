"""In-process OIDC provider for hermetic testing.

Per CLAUDE.md: NOT a security boundary, NOT a quickstart for end users — its
only job is to make the test suite hermetic so contributors can run `pytest`
without any external CSP credentials.

Implementation notes:
- Stdlib `ThreadingHTTPServer` only; no extra dependency.
- Binds to a random localhost port (port 0); the OS picks one.
- Ephemeral RSA-2048 keypair generated per provider instance.
- Publishes OIDC discovery + JWKS so an issuer (or test) can validate tokens
  end-to-end via the same path it would use against a real CSP.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import TracebackType
from typing import Any
from urllib.parse import urlsplit

from joserfc import jwt as joserfc_jwt
from joserfc.jwk import RSAKey


class _Server(ThreadingHTTPServer):
    """ThreadingHTTPServer subclass that carries a back-reference to its provider.

    The handler reads `self.server.provider` to dispatch endpoints without
    needing module-level state (which would break if multiple providers ran
    concurrently in the same process).
    """

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        provider: MockOIDCProvider,
    ) -> None:
        super().__init__(address, handler)
        self.provider = provider


class _Handler(BaseHTTPRequestHandler):
    server: _Server

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        provider = self.server.provider
        if path == "/.well-known/openid-configuration":
            self._send_json(200, provider.discovery_document())
        elif path == "/.well-known/jwks.json":
            self._send_json(200, provider.jwks())
        else:
            self.send_error(404)

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress per-request logging — would clutter pytest output.
        return


class MockOIDCProvider:
    """In-process OIDC provider with discovery, JWKS, and an ID-token mint helper.

    Lifecycle: call `start()` to bind a random localhost port and begin serving
    on a daemon thread; call `stop()` to shut down. Also usable as a context
    manager. The same instance MAY be restarted after stop().
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        self._host = host
        self._key: RSAKey = RSAKey.generate_key(2048)
        self._kid: str = self._key.thumbprint()
        self._server: _Server | None = None
        self._thread: Thread | None = None

    # ----- properties --------------------------------------------------- #

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def public_jwk(self) -> RSAKey:
        """A public-only view of the signing key, suitable for verification."""
        return RSAKey.import_key(self._key.as_dict(private=False))

    @property
    def issuer(self) -> str:
        if self._server is None:
            raise RuntimeError("provider not started; call start() first")
        host, port = self._server.server_address[:2]
        host_str = host.decode() if isinstance(host, bytes) else host
        return f"http://{host_str}:{port}"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/.well-known/jwks.json"

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    # ----- lifecycle ---------------------------------------------------- #

    def start(self) -> MockOIDCProvider:
        if self._server is not None:
            return self
        self._server = _Server((self._host, 0), _Handler, self)
        self._thread = Thread(target=self._server.serve_forever, daemon=True, name="mock-oidc")
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    def __enter__(self) -> MockOIDCProvider:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.stop()

    # ----- documents ---------------------------------------------------- #

    def discovery_document(self) -> dict[str, Any]:
        """Subset of the OIDC Core 1.0 discovery document.

        Sufficient for the OIDC client adapter to find the JWKS and token
        endpoints. We do not advertise endpoints we have not implemented.
        """
        return {
            "issuer": self.issuer,
            "jwks_uri": self.jwks_uri,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "response_types_supported": ["code"],
            "subject_types_supported": ["pairwise"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid"],
            "claims_supported": [
                "sub",
                "iss",
                "aud",
                "exp",
                "iat",
                "nbf",
                "acr",
                "nonce",
            ],
        }

    def jwks(self) -> dict[str, Any]:
        """JWKS document publishing the provider's public signing key."""
        public = self._key.as_dict(private=False)
        public["kid"] = self._kid
        public["use"] = "sig"
        public["alg"] = "RS256"
        return {"keys": [public]}

    # ----- token mint --------------------------------------------------- #

    def mint_id_token(
        self,
        sub: str,
        acr: str,
        aud: str,
        ttl: timedelta = timedelta(minutes=15),
        now: datetime | None = None,
        **extra_claims: Any,
    ) -> str:
        """Mint a signed OIDC ID token with realistic claim shape.

        `acr` is passed through verbatim — pass whatever ACR URI you want
        your test to exercise. Extra OIDC claims (e.g. `nonce`, `email`)
        can be supplied as kwargs.
        """
        if self._server is None:
            raise RuntimeError("provider not started; call start() first")
        issued_at = now if now is not None else datetime.now(UTC)
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": sub,
            "aud": aud,
            "iat": int(issued_at.timestamp()),
            "nbf": int(issued_at.timestamp()),
            "exp": int((issued_at + ttl).timestamp()),
            "acr": acr,
        }
        claims.update(extra_claims)
        return joserfc_jwt.encode(
            {"alg": "RS256", "kid": self._kid},
            claims,
            self._key,
            algorithms=["RS256"],
        )
