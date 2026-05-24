"""CLI tests via Typer's `CliRunner`.

Per-test isolation:
  - `monkeypatch` redirects `XDG_DATA_HOME` to a tmp dir so each test gets a
    fresh issuer signing key and ID-token store.
  - The mock OIDC provider provides discovery + JWKS so `issue` runs against
    a real (in-process) CSP via the IDTokenValidator.
  - CSP env vars (CSP_*) are set on `monkeypatch` so the CLI reads them.

The OAuth code flow itself (`nist-agent-passport login` without `--id-token`) is
tested via `_login.login_local_loopback` separately, with a mocked discovery /
token endpoint, so we don't actually open a browser in CI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mock_oidc import MockOIDCProvider
from typer.testing import CliRunner

from nist_agent_passport.cli import app

CLIENT_ID = "nist-agent-passport-issuer"
ACR_IAL2 = "http://idmanagement.gov/ns/assurance/ial/2"  # NIST IAL-2 (identity verified + MFA)
MCP_AUDIENCE = "https://mcp.example.com/"


@pytest.fixture
def runner() -> CliRunner:
    # mix_stderr=False so error output doesn't pollute stdout assertions.
    return CliRunner()


@pytest.fixture
def cli_env(
    tmp_path: Path,
    mock_oidc: MockOIDCProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Isolated storage + CSP env for a CLI test."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setenv("CSP_DISCOVERY_URL", mock_oidc.discovery_url)
    monkeypatch.setenv("CSP_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("CSP_CLIENT_SECRET", "")  # mock doesn't need it
    monkeypatch.setenv("AGENT_PASSPORT_ISSUER", "https://issuer.local")
    return tmp_path / "nist-agent-passport"


# --------------------------------------------------------------------------- #
# where
# --------------------------------------------------------------------------- #


def test_where_prints_xdg_data_dir(runner: CliRunner, cli_env: Path) -> None:
    result = runner.invoke(app, ["where"])
    assert result.exit_code == 0
    assert result.stdout.strip() == str(cli_env)


# --------------------------------------------------------------------------- #
# login --id-token (paste-in)
# --------------------------------------------------------------------------- #


def test_login_paste_in_stores_token(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    id_token = mock_oidc.mint_id_token(sub="u1", acr=ACR_IAL2, aud=CLIENT_ID)
    result = runner.invoke(app, ["login", "--id-token", id_token])
    assert result.exit_code == 0, result.output
    stored = (cli_env / "id_token").read_text()
    assert stored == id_token


def test_login_missing_env_fails_cleanly(
    runner: CliRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    # Set to empty (not delenv) so python-dotenv loading a local .env
    # cannot repopulate it — `_required_env` treats empty as unset.
    monkeypatch.setenv("CSP_DISCOVERY_URL", "")
    result = runner.invoke(app, ["login", "--id-token", "x"])
    assert result.exit_code == 2
    assert "CSP_DISCOVERY_URL" in result.output


# --------------------------------------------------------------------------- #
# issue
# --------------------------------------------------------------------------- #


def test_issue_round_trip_with_verify(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    """login → issue → verify, all via the CLI."""
    id_token = mock_oidc.mint_id_token(sub="user-alice", acr=ACR_IAL2, aud=CLIENT_ID)
    assert runner.invoke(app, ["login", "--id-token", id_token]).exit_code == 0

    issue_result = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "agent:alice",
            "--agent-model",
            "claude-opus-4-7",
            "--tool-scope",
            "flights:*",
            "--task-purpose",
            "book a flight",
            "--aud",
            MCP_AUDIENCE,
            "--ttl",
            "600",
        ],
    )
    assert issue_result.exit_code == 0, issue_result.output
    passport_jwt = issue_result.stdout.strip()
    assert passport_jwt.count(".") == 2

    verify_result = runner.invoke(
        app,
        [
            "verify",
            "--aud",
            MCP_AUDIENCE,
            "--require-ial",
            "2",
            "--required-scope",
            "flights:book",
            passport_jwt,
        ],
    )
    assert verify_result.exit_code == 0, verify_result.output
    assert "verified" in verify_result.output
    body = verify_result.stdout.split("\n", 1)[1]
    data = json.loads(body)
    assert data["sub"] == "user-alice"
    assert data["ial"] == 2
    assert data["agent_id"] == "agent:alice"


def test_issue_without_login_fails(runner: CliRunner, cli_env: Path) -> None:
    result = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "a",
            "--agent-model",
            "m",
            "--tool-scope",
            "x",
            "--aud",
            "y",
        ],
    )
    assert result.exit_code == 2
    assert "No stored ID token" in result.output


# --------------------------------------------------------------------------- #
# verify failure modes
# --------------------------------------------------------------------------- #


def test_verify_wrong_audience_fails(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    id_token = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID)
    runner.invoke(app, ["login", "--id-token", id_token])
    issued = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "a",
            "--agent-model",
            "m",
            "--tool-scope",
            "x:*",
            "--aud",
            MCP_AUDIENCE,
        ],
    )
    passport = issued.stdout.strip()

    result = runner.invoke(app, ["verify", "--aud", "https://other.example.com/", passport])
    assert result.exit_code == 1
    assert "AudienceMismatch" in result.output


def test_verify_insufficient_ial_fails(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    id_token = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID)
    runner.invoke(app, ["login", "--id-token", id_token])
    issued = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "a",
            "--agent-model",
            "m",
            "--tool-scope",
            "x",
            "--aud",
            MCP_AUDIENCE,
        ],
    )
    result = runner.invoke(
        app, ["verify", "--aud", MCP_AUDIENCE, "--require-ial", "3", issued.stdout.strip()]
    )
    assert result.exit_code == 1
    assert "IALInsufficient" in result.output


# --------------------------------------------------------------------------- #
# inspect
# --------------------------------------------------------------------------- #


def test_inspect_prints_all_claims(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    id_token = mock_oidc.mint_id_token(sub="user-x", acr=ACR_IAL2, aud=CLIENT_ID)
    runner.invoke(app, ["login", "--id-token", id_token])
    issued = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "agent:x",
            "--agent-model",
            "claude-opus-4-7",
            "--tool-scope",
            "tool:read",
            "--task-purpose",
            "demo",
            "--aud",
            MCP_AUDIENCE,
        ],
    )
    result = runner.invoke(app, ["inspect", issued.stdout.strip()])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["sub"] == "user-x"
    assert data["aud"] == MCP_AUDIENCE
    assert data["https://agent-passport.org/claims/agent_id"] == "agent:x"
    assert data["https://agent-passport.org/claims/tool_scope"] == ["tool:read"]


def test_inspect_reads_token_from_stdin(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    id_token = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID)
    runner.invoke(app, ["login", "--id-token", id_token])
    issued = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "a",
            "--agent-model",
            "m",
            "--tool-scope",
            "x",
            "--aud",
            MCP_AUDIENCE,
        ],
    )
    passport = issued.stdout.strip()
    result = runner.invoke(app, ["inspect"], input=passport)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["aud"] == MCP_AUDIENCE


# --------------------------------------------------------------------------- #
# delegate
# --------------------------------------------------------------------------- #


def test_delegate_creates_valid_child(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    """issue → delegate → inspect child to confirm parent_jti + nested act."""
    id_token = mock_oidc.mint_id_token(sub="user-alice", acr=ACR_IAL2, aud=CLIENT_ID)
    runner.invoke(app, ["login", "--id-token", id_token])
    parent = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "agent:alice",
            "--agent-model",
            "claude-opus-4-7",
            "--tool-scope",
            "flights:*",
            "--aud",
            "https://svc-a.example.com/",
        ],
    ).stdout.strip()

    child_result = runner.invoke(
        app,
        [
            "delegate",
            "--agent-id",
            "agent:bob",
            "--agent-model",
            "claude-opus-4-7",
            "--tool-scope",
            "flights:book",
            "--aud",
            "https://svc-b.example.com/",
            parent,
        ],
    )
    assert child_result.exit_code == 0, child_result.output
    child_jwt = child_result.stdout.strip()
    payload = json.loads(runner.invoke(app, ["inspect", child_jwt]).stdout)
    assert payload["aud"] == "https://svc-b.example.com/"
    assert payload["sub"] == "user-alice"  # principal preserved
    assert payload["act"]["sub"] == "agent:bob"
    assert payload["act"]["act"]["sub"] == "agent:alice"
    assert payload["https://agent-passport.org/claims/parent_jti"]


def test_delegate_overbroad_scope_fails(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    id_token = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID)
    runner.invoke(app, ["login", "--id-token", id_token])
    parent = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "a",
            "--agent-model",
            "m",
            "--tool-scope",
            "flights:*",
            "--aud",
            "https://svc-a.example.com/",
        ],
    ).stdout.strip()
    result = runner.invoke(
        app,
        [
            "delegate",
            "--agent-id",
            "b",
            "--agent-model",
            "m",
            "--tool-scope",
            "payments:charge",  # not in parent
            "--aud",
            "https://svc-b.example.com/",
            parent,
        ],
    )
    assert result.exit_code == 1
    assert "ScopeAttenuationError" in result.output


def test_default_acr_mapping_accepts_ial_token(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    """Default mapping (CSP_ACR_MAPPING unset → 'ial') accepts canonical IAL URIs."""
    ial2_token = mock_oidc.mint_id_token(
        sub="u", acr="http://idmanagement.gov/ns/assurance/ial/2", aud=CLIENT_ID
    )
    assert runner.invoke(app, ["login", "--id-token", ial2_token]).exit_code == 0
    result = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "a",
            "--agent-model",
            "m",
            "--tool-scope",
            "x",
            "--aud",
            MCP_AUDIENCE,
        ],
    )
    assert result.exit_code == 0, result.output


def test_default_acr_mapping_accepts_legacy_loa_3_token(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    """Default mapping accepts the legacy `…/loa/3` URI some CSPs still emit.

    Pins the conservative translation: LOA-3 → IAL-2 (documents verified +
    MFA), not IAL-3 (in-person supervised proofing).
    """
    loa3_token = mock_oidc.mint_id_token(
        sub="u", acr="http://idmanagement.gov/ns/assurance/loa/3", aud=CLIENT_ID
    )
    runner.invoke(app, ["login", "--id-token", loa3_token])
    issued = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "a",
            "--agent-model",
            "m",
            "--tool-scope",
            "x",
            "--aud",
            MCP_AUDIENCE,
        ],
    )
    assert issued.exit_code == 0, issued.output
    # require_ial=3 must reject this token (the conservative collapse).
    rejected = runner.invoke(
        app,
        ["verify", "--aud", MCP_AUDIENCE, "--require-ial", "3", issued.stdout.strip()],
    )
    assert rejected.exit_code == 1
    assert "IALInsufficient" in rejected.output


def test_default_acr_mapping_rejects_unknown_acr(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    """Default mapping rejects URIs that aren't `…/ial/N` or in the legacy table."""
    bad_token = mock_oidc.mint_id_token(sub="u", acr="urn:not:any:standard:mapping", aud=CLIENT_ID)
    runner.invoke(app, ["login", "--id-token", bad_token])
    result = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "a",
            "--agent-model",
            "m",
            "--tool-scope",
            "x",
            "--aud",
            MCP_AUDIENCE,
        ],
    )
    # Issuer raises UnsupportedAcr; CLI surfaces it as a non-zero exit.
    assert result.exit_code != 0


def test_csp_acr_mapping_unknown_value_fails_fast(
    runner: CliRunner,
    cli_env: Path,
    mock_oidc: MockOIDCProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CSP_ACR_MAPPING", "not-a-real-mapping")
    id_token = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID)
    runner.invoke(app, ["login", "--id-token", id_token])
    result = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "a",
            "--agent-model",
            "m",
            "--tool-scope",
            "x",
            "--aud",
            MCP_AUDIENCE,
        ],
    )
    assert result.exit_code == 2
    assert "Unknown CSP_ACR_MAPPING" in result.output


def test_delegate_reads_parent_from_stdin(
    runner: CliRunner, cli_env: Path, mock_oidc: MockOIDCProvider
) -> None:
    id_token = mock_oidc.mint_id_token(sub="u", acr=ACR_IAL2, aud=CLIENT_ID)
    runner.invoke(app, ["login", "--id-token", id_token])
    parent = runner.invoke(
        app,
        [
            "issue",
            "--agent-id",
            "a",
            "--agent-model",
            "m",
            "--tool-scope",
            "x:*",
            "--aud",
            "https://svc-a.example.com/",
        ],
    ).stdout.strip()
    result = runner.invoke(
        app,
        [
            "delegate",
            "--agent-id",
            "b",
            "--agent-model",
            "m",
            "--tool-scope",
            "x:y",
            "--aud",
            "https://svc-b.example.com/",
        ],
        input=parent,
    )
    assert result.exit_code == 0, result.output
