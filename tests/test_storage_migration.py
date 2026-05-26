"""Coverage for the v0.2.0 XDG-directory rename in `_storage.xdg_data_dir`.

The package renamed from `nist-agent-passport` to `agent-passport` in v0.2.0;
the storage layer auto-migrates the legacy `$XDG_DATA_HOME/nist-agent-passport/`
to `$XDG_DATA_HOME/agent-passport/` on first call so existing users don't lose
their issuer signing key. Tests cover the three cases: legacy-only,
new-already-exists (don't clobber), and fresh install.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_passport._storage import _DIR_NAME, _LEGACY_DIR_NAME, xdg_data_dir


@pytest.fixture
def xdg_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point `$XDG_DATA_HOME` at an empty temp dir for the duration of the test."""
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    return tmp_path


def test_legacy_dir_migrates_to_new(xdg_home: Path) -> None:
    legacy = xdg_home / _LEGACY_DIR_NAME
    legacy.mkdir()
    (legacy / "issuer_signing_key.json").write_text('{"kty": "RSA"}')

    returned = xdg_data_dir()

    assert returned == xdg_home / _DIR_NAME
    assert returned.exists()
    assert (returned / "issuer_signing_key.json").read_text() == '{"kty": "RSA"}'
    assert not legacy.exists(), "legacy dir should be renamed away, not left behind"


def test_both_dirs_present_does_not_clobber(xdg_home: Path) -> None:
    """If a user already ran v0.2.0 (creating the new dir) and still has a stale
    legacy dir, the migration must not overwrite the new dir's contents."""
    legacy = xdg_home / _LEGACY_DIR_NAME
    legacy.mkdir()
    (legacy / "issuer_signing_key.json").write_text('{"kty": "legacy"}')
    new = xdg_home / _DIR_NAME
    new.mkdir()
    (new / "issuer_signing_key.json").write_text('{"kty": "current"}')

    returned = xdg_data_dir()

    assert returned == new
    assert (new / "issuer_signing_key.json").read_text() == '{"kty": "current"}'
    assert legacy.exists(), "legacy must remain untouched when new already exists"


def test_fresh_install_creates_new_dir(xdg_home: Path) -> None:
    returned = xdg_data_dir()

    assert returned == xdg_home / _DIR_NAME
    assert returned.exists()
    assert not (xdg_home / _LEGACY_DIR_NAME).exists()
