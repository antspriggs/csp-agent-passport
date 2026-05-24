"""In-process OIDC provider for hermetic testing. See `provider.py` for design."""

from mock_oidc.provider import MockOIDCProvider

__all__ = ["MockOIDCProvider"]
