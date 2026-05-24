"""OAuth 2.0 Authorization Code + PKCE login flow for native apps.

Implements RFC 6749 §4.1 (Authorization Code), RFC 7636 (PKCE), and the
local-loopback redirect pattern recommended by RFC 8252 (OAuth 2.0 for Native
Apps). Discovery is well-known-driven (per CLAUDE.md) — only the CSP's
discovery URL is hardcoded; `authorization_endpoint` and `token_endpoint`
come from the discovery doc.

Used by `nist-agent-passport login`. Built as a library function so tests can call
it directly with a mocked or in-process CSP.
"""

from __future__ import annotations

import secrets
import threading
import urllib.parse
import webbrowser
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import httpx

DEFAULT_TIMEOUT_S = 300


@dataclass(frozen=True)
class LoginResult:
    id_token: str
    access_token: str | None
    raw_token_response: dict[str, Any]


class LoginError(Exception):
    """Anything that prevented a successful login completing."""


def login_local_loopback(
    discovery_url: str,
    client_id: str,
    client_secret: str | None,
    redirect_uri: str,
    scopes: list[str],
    open_browser: bool = True,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    http: httpx.Client | None = None,
) -> LoginResult:
    """Run an OAuth 2.0 Authorization Code flow with PKCE against `discovery_url`.

    Steps:
      1. GET the discovery doc; pull `authorization_endpoint` + `token_endpoint`.
      2. Generate PKCE verifier + S256 challenge; generate `state`.
      3. Build the auth URL; open the user's browser (or print it).
      4. Bind a one-shot local HTTP server on the redirect URI's host/port;
         wait for the CSP to redirect back with `?code=...&state=...`.
      5. Verify `state`; POST the code (with PKCE verifier) to `token_endpoint`.
      6. Return the `id_token` (and any access_token) from the token response.

    `client_secret` may be None for public clients; only sent if provided.
    """
    own_http = http is None
    http = http or httpx.Client(timeout=10.0)
    try:
        try:
            resp = http.get(discovery_url)
            resp.raise_for_status()
            disc = resp.json()
        except (httpx.HTTPError, ValueError) as e:
            raise LoginError(f"could not fetch discovery from {discovery_url}: {e}") from e

        for required in ("authorization_endpoint", "token_endpoint"):
            if required not in disc:
                raise LoginError(f"discovery doc missing {required!r}")

        code_verifier = secrets.token_urlsafe(64)
        code_challenge = (
            urlsafe_b64encode(sha256(code_verifier.encode()).digest()).rstrip(b"=").decode()
        )
        state = secrets.token_urlsafe(32)

        parsed_redirect = urllib.parse.urlparse(redirect_uri)
        if parsed_redirect.scheme != "http" or parsed_redirect.hostname not in (
            "localhost",
            "127.0.0.1",
        ):
            raise LoginError(
                f"redirect_uri must be http://localhost or http://127.0.0.1, got {redirect_uri!r}"
            )

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        auth_url = f"{disc['authorization_endpoint']}?{urllib.parse.urlencode(params)}"

        received: dict[str, str] = {}

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                qs = urllib.parse.urlparse(self.path).query
                received.update(dict(urllib.parse.parse_qsl(qs)))
                body = (
                    b"<html><body><h2>Login complete.</h2>"
                    b"<p>You may close this window.</p></body></html>"
                )
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                return

        host = parsed_redirect.hostname or "127.0.0.1"
        port = parsed_redirect.port or 0
        server = HTTPServer((host, port), _Handler)
        thread = threading.Thread(
            target=server.handle_request, daemon=True, name="nist-agent-passport-login"
        )
        thread.start()

        if open_browser:
            webbrowser.open(auth_url)
        else:
            print(f"Open this URL in your browser to log in:\n  {auth_url}")

        thread.join(timeout=timeout_s)
        server.server_close()

        if thread.is_alive():
            raise LoginError(f"login timed out after {timeout_s}s — no callback received")
        if "error" in received:
            err_desc = received.get("error_description", "<no description>")
            raise LoginError(f"CSP returned error: {received['error']!r} — {err_desc}")
        if "code" not in received:
            raise LoginError("CSP callback did not include a 'code' parameter")
        if received.get("state") != state:
            raise LoginError("OAuth state mismatch — possible CSRF; rejecting")

        token_form: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": received["code"],
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier,
        }
        if client_secret:
            token_form["client_secret"] = client_secret

        try:
            tresp = http.post(disc["token_endpoint"], data=token_form)
            tresp.raise_for_status()
            tokens = tresp.json()
        except (httpx.HTTPError, ValueError) as e:
            raise LoginError(f"token endpoint exchange failed: {e}") from e

        if "id_token" not in tokens:
            raise LoginError("token response did not include an `id_token`")

        return LoginResult(
            id_token=str(tokens["id_token"]),
            access_token=(str(tokens["access_token"]) if "access_token" in tokens else None),
            raw_token_response=tokens,
        )
    finally:
        if own_http:
            http.close()
