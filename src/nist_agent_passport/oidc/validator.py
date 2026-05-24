"""OIDC ID-token validator.

Discovery-driven (per CLAUDE.md's well-known-only rule): given the CSP's
discovery URL and our `client_id`, the validator fetches the discovery
document, follows `jwks_uri`, and verifies the ID token's signature, time
window, `iss`, and `aud` against what discovery advertises.

Caching: discovery is fetched once per validator. JWKS keys are cached by
`kid`; an unknown `kid` triggers a JWKS refetch (the deferred rotation story).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from types import TracebackType
from typing import Any

import httpx
from joserfc import jwt as joserfc_jwt
from joserfc.errors import BadSignatureError, JoseError
from joserfc.jwk import JWKRegistry

from nist_agent_passport._clock import NowCallable, default_now
from nist_agent_passport._jose import parse_jws_header
from nist_agent_passport.errors import (
    AlgorithmNotAllowed,
    AudienceMismatch,
    DiscoveryError,
    Expired,
    InvalidSignature,
    InvalidToken,
    JWKSError,
    NotYetValid,
    UntrustedIssuer,
)
from nist_agent_passport.oidc.base import AcrMapping, OIDCAssertion

DEFAULT_ALLOWED_ALGORITHMS: tuple[str, ...] = ("RS256", "ES256", "EdDSA")


class IDTokenValidator:
    """Validates OIDC ID tokens against a CSP discovered via well-known.

    Construct once per (CSP discovery URL, client_id) and reuse. Owns its
    httpx client unless one is injected; close via `close()` or the context
    manager protocol to release the connection pool.
    """

    def __init__(
        self,
        discovery_url: str,
        client_id: str,
        acr_mapping: AcrMapping,
        http: httpx.Client | None = None,
        now: NowCallable = default_now,
        clock_skew: timedelta = timedelta(seconds=30),
        allowed_algorithms: Iterable[str] = DEFAULT_ALLOWED_ALGORITHMS,
    ) -> None:
        self._discovery_url = discovery_url
        self._client_id = client_id
        self._acr_mapping = acr_mapping
        self._http = http if http is not None else httpx.Client(timeout=10.0)
        self._owns_http = http is None
        self._now = now
        self._clock_skew = clock_skew
        self._allowed_algorithms: list[str] = sorted(set(allowed_algorithms))
        if "none" in {a.lower() for a in self._allowed_algorithms}:
            raise ValueError("'none' is never a valid algorithm")
        if not self._allowed_algorithms:
            raise ValueError("allowed_algorithms must not be empty")
        self._discovery: dict[str, Any] | None = None
        self._jwks_keys: dict[str, Any] = {}

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> IDTokenValidator:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def validate(self, id_token: str) -> OIDCAssertion:
        discovery = self._get_discovery()

        header = parse_jws_header(id_token)
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self._allowed_algorithms:
            raise AlgorithmNotAllowed(
                alg if isinstance(alg, str) else None, self._allowed_algorithms
            )
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidToken("ID token JWS header missing 'kid'")

        key = self._get_jwks_key(kid, str(discovery["jwks_uri"]))

        try:
            decoded = joserfc_jwt.decode(id_token, key, algorithms=self._allowed_algorithms)
        except BadSignatureError as e:
            raise InvalidSignature(str(e)) from e
        except JoseError as e:
            raise InvalidToken(f"JOSE decode failed: {e}") from e

        claims = decoded.claims

        expected_iss = str(discovery["issuer"])
        actual_iss = claims.get("iss")
        if actual_iss != expected_iss:
            raise UntrustedIssuer(
                str(actual_iss) if actual_iss is not None else "<missing>",
                {expected_iss},
            )

        aud = claims.get("aud")
        if isinstance(aud, str):
            if aud != self._client_id:
                raise AudienceMismatch(self._client_id, aud)
            aud_str = aud
        elif isinstance(aud, list):
            if self._client_id not in aud:
                raise AudienceMismatch(self._client_id, ",".join(str(x) for x in aud))
            aud_str = self._client_id
        else:
            raise InvalidToken("ID token 'aud' missing or wrong type")

        now = self._now()
        exp_ts = claims.get("exp")
        if not isinstance(exp_ts, int | float):
            raise InvalidToken("ID token missing 'exp'")
        exp = datetime.fromtimestamp(exp_ts, tz=UTC)
        if now > exp + self._clock_skew:
            raise Expired(exp, now)

        nbf_ts = claims.get("nbf")
        if isinstance(nbf_ts, int | float):
            nbf = datetime.fromtimestamp(nbf_ts, tz=UTC)
            if now < nbf - self._clock_skew:
                raise NotYetValid(nbf, now)

        # `acr` is optional in OIDC. When absent, scope-driven auth applies:
        # the assertion carries no identity-assurance levels, and downstream
        # verifiers either accept that (require_ial=0) or reject (require_ial>=1).
        acr_raw = claims.get("acr")
        if isinstance(acr_raw, str):
            acr: str | None = acr_raw
            levels = self._acr_mapping(acr_raw)
            ial: int | None = levels.ial
            aal: int | None = levels.aal
            fal: int | None = levels.fal
        else:
            acr = None
            ial = aal = fal = None

        sub = claims.get("sub")
        if not isinstance(sub, str):
            raise InvalidToken("ID token missing or non-string 'sub'")

        return OIDCAssertion(
            iss=expected_iss,
            sub=sub,
            aud=aud_str,
            acr=acr,
            ial=ial,
            aal=aal,
            fal=fal,
            raw_claims=dict(claims),
        )

    def _get_discovery(self) -> dict[str, Any]:
        if self._discovery is not None:
            return self._discovery
        try:
            response = self._http.get(self._discovery_url)
            response.raise_for_status()
            doc = response.json()
        except (httpx.HTTPError, ValueError) as e:
            raise DiscoveryError(
                f"could not fetch discovery from {self._discovery_url}: {e}"
            ) from e
        if not isinstance(doc, dict):
            raise DiscoveryError("discovery doc is not a JSON object")
        for required in ("issuer", "jwks_uri"):
            if required not in doc:
                raise DiscoveryError(f"discovery doc missing {required!r}")
        self._discovery = doc
        return doc

    def _get_jwks_key(self, kid: str, jwks_uri: str) -> Any:
        if kid in self._jwks_keys:
            return self._jwks_keys[kid]
        try:
            response = self._http.get(jwks_uri)
            response.raise_for_status()
            jwks = response.json()
        except (httpx.HTTPError, ValueError) as e:
            raise JWKSError(f"could not fetch JWKS from {jwks_uri}: {e}") from e
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise JWKSError("JWKS doc is not a valid JWKS object")
        for key_dict in jwks["keys"]:
            if isinstance(key_dict, dict) and isinstance(key_dict.get("kid"), str):
                self._jwks_keys[key_dict["kid"]] = JWKRegistry.import_key(key_dict)
        if kid not in self._jwks_keys:
            raise JWKSError(f"no key with kid={kid!r} in JWKS at {jwks_uri}")
        return self._jwks_keys[kid]
