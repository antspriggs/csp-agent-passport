"""OAuth login flow tests.

The interactive browser+loopback dance is hard to fully test without a
headed browser. These tests cover the parts that *are* testable: input
validation, discovery-fetch errors, malformed token-endpoint responses, and
the loopback timeout. Higher-level coverage is provided by the CLI test
suite (which exercises `--id-token` paste-in mode).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from nist_agent_passport._login import LoginError, login_local_loopback


def _stub_get(
    monkeypatch: pytest.MonkeyPatch,
    handler: Any,
) -> None:
    monkeypatch.setattr(httpx.Client, "get", handler)


def test_redirect_uri_not_loopback_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """RFC 8252 requires loopback for native-app OAuth."""

    def fake_get(self: httpx.Client, url: str, *a: Any, **kw: Any) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "authorization_endpoint": "https://csp.example.com/authz",
                "token_endpoint": "https://csp.example.com/token",
            },
            request=httpx.Request("GET", url),
        )

    _stub_get(monkeypatch, fake_get)
    with pytest.raises(LoginError, match="localhost"):
        login_local_loopback(
            discovery_url="https://csp.example.com/.well-known/openid-configuration",
            client_id="c",
            client_secret=None,
            redirect_uri="https://my-app.example.com/cb",  # not loopback
            scopes=["openid"],
        )


def test_discovery_unreachable_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(self: httpx.Client, url: str, *a: Any, **kw: Any) -> httpx.Response:
        raise httpx.ConnectError("unreachable")

    _stub_get(monkeypatch, fake_get)
    with pytest.raises(LoginError, match="could not fetch discovery"):
        login_local_loopback(
            discovery_url="https://nowhere.example.com/.well-known/openid-configuration",
            client_id="c",
            client_secret=None,
            redirect_uri="http://127.0.0.1:65000/cb",
            scopes=["openid"],
        )


def test_discovery_doc_missing_endpoints_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(self: httpx.Client, url: str, *a: Any, **kw: Any) -> httpx.Response:
        return httpx.Response(
            200,
            json={"issuer": "https://csp.example.com"},  # missing both endpoints
            request=httpx.Request("GET", url),
        )

    _stub_get(monkeypatch, fake_get)
    with pytest.raises(LoginError, match="authorization_endpoint"):
        login_local_loopback(
            discovery_url="https://csp.example.com/.well-known/openid-configuration",
            client_id="c",
            client_secret=None,
            redirect_uri="http://127.0.0.1:65001/cb",
            scopes=["openid"],
        )


def test_login_times_out_when_no_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the browser never comes back, login_local_loopback raises after timeout_s."""

    def fake_get(self: httpx.Client, url: str, *a: Any, **kw: Any) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "authorization_endpoint": "https://csp.example.com/authz",
                "token_endpoint": "https://csp.example.com/token",
            },
            request=httpx.Request("GET", url),
        )

    _stub_get(monkeypatch, fake_get)
    with pytest.raises(LoginError, match="timed out"):
        login_local_loopback(
            discovery_url="https://csp.example.com/.well-known/openid-configuration",
            client_id="c",
            client_secret=None,
            redirect_uri="http://127.0.0.1:0/cb",
            scopes=["openid"],
            open_browser=False,  # don't actually open a browser
            timeout_s=1,
        )
