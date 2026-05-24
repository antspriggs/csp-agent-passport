"""XDG-style persistent storage for the CLI.

Stores three things across invocations:
  - The most recent ID token from the CSP (so `issue` doesn't need to re-login).
  - The local issuer's signing key (so `issue` and `delegate` mint with a
    stable kid that verifiers can pin).
  - CSP-side bookkeeping (which discovery URL the ID token came from).

Layout (under `$XDG_DATA_HOME/nist-agent-passport/`, or `~/.local/share/nist-agent-passport/`):
  id_token                  text file with the raw compact JWS
  id_token_meta.json        {"discovery_url": "...", "client_id": "..."}
  issuer_signing_key.json   JWK private-key dict (kty=RSA, includes d/p/q/...)

Files containing secrets (id_token, issuer_signing_key.json) are chmod 600.
Loaders return None if the file is absent, never raise.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from joserfc.jwk import RSAKey

_DIR_NAME = "nist-agent-passport"


def xdg_data_dir() -> Path:
    """Return `$XDG_DATA_HOME/nist-agent-passport`, creating it if missing."""
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    p = Path(base) / _DIR_NAME
    p.mkdir(parents=True, exist_ok=True)
    return p


def _id_token_path() -> Path:
    return xdg_data_dir() / "id_token"


def _id_token_meta_path() -> Path:
    return xdg_data_dir() / "id_token_meta.json"


def _issuer_key_path() -> Path:
    return xdg_data_dir() / "issuer_signing_key.json"


@dataclass(frozen=True)
class IDTokenMeta:
    discovery_url: str
    client_id: str


def save_id_token(token: str, meta: IDTokenMeta) -> Path:
    p = _id_token_path()
    p.write_text(token)
    p.chmod(0o600)
    mp = _id_token_meta_path()
    mp.write_text(json.dumps({"discovery_url": meta.discovery_url, "client_id": meta.client_id}))
    mp.chmod(0o644)
    return p


def load_id_token() -> str | None:
    p = _id_token_path()
    if not p.exists():
        return None
    return p.read_text().strip()


def load_id_token_meta() -> IDTokenMeta | None:
    p = _id_token_meta_path()
    if not p.exists():
        return None
    raw = json.loads(p.read_text())
    return IDTokenMeta(
        discovery_url=str(raw["discovery_url"]),
        client_id=str(raw["client_id"]),
    )


def load_or_create_issuer_key() -> RSAKey:
    """Load the issuer's signing key, generating + persisting one on first use."""
    p = _issuer_key_path()
    if p.exists():
        return RSAKey.import_key(json.loads(p.read_text()))
    key = RSAKey.generate_key(2048)
    p.write_text(json.dumps(key.as_dict(private=True), indent=2))
    p.chmod(0o600)
    return key


def issuer_key_path() -> Path:
    """Public accessor for inspection / `nist-agent-passport` config commands."""
    return _issuer_key_path()
