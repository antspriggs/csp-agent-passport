# Changelog

All notable changes to Agent Passport are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (breaking)

- **ACR / IAL / AAL / FAL are now optional throughout.** Aligned with OIDC
  (where `acr` is optional) and supports scope-driven auth as a first-class
  deployment mode.
  - `Passport.acr` / `ial` / `aal` / `fal` are now `Optional`. None means
    "not asserted"; tokens without identity assurance still verify under
    the default policy.
  - `OIDCAssertion.acr` / `ial` / `aal` / `fal` are now `Optional`.
    `IDTokenValidator.validate()` no longer raises when the ID token has no
    `acr` claim; it returns an assertion with `acr=None` and no levels.
  - `VerificationPolicy.require_ial` / `require_aal` / `require_fal` defaults
    changed from **1 → 0**. `0` means "skip this check". A verifier that
    needs identity assurance sets the relevant `require_*` to `1`, `2`, or
    `3`. Range widened from 1–3 to 0–3.
  - Chain walk: assurance levels propagate forward only. A child claiming
    IAL the parent doesn't assert raises `ChainBroken` ("IAL appeared in
    chain"). A child legitimately dropping the claim (parent has IAL=2,
    child has IAL=None) is fine.
  - JWT serialization: `acr`/`ial`/`aal`/`fal` are omitted from the JWT
    payload when None (not serialized as `null`).

- **CSP env vars renamed** from `IDME_*` to `CSP_*` so the same configuration
  works with any OIDC + PKCE provider. Migration: in your `.env`, replace
  `IDME_DISCOVERY_URL`/`CLIENT_ID`/`CLIENT_SECRET`/`REDIRECT_URI`/`SCOPES`
  with `CSP_*` equivalents.
- **Removed all ID.me callouts from the public API.** The library has no
  vendor-specific identifiers anywhere it can be imported.
  - Deleted `src/agent_passport/oidc/idme_adapter.py` and
    `tests/test_idme_adapter.py`.
  - Removed `idme_acr_mapping`, `IDME_ACR_MAPPING`, `IDME_PRODUCTION_DISCOVERY_URL`,
    `IDME_SANDBOX_DISCOVERY_URL`, and the `IDME_LIVE_DISCOVERY_URL` env var
    from the public surface.
  - The `CSP_ACR_MAPPING` selector no longer accepts `idme`; values are now
    `ial` (default) or `pkg.module:function_name` for a custom mapping.
- **Dropped LOA terminology from the public surface.** Agent Passport speaks
  NIST 800-63-3 IAL/AAL/FAL exclusively. `loa_acr_mapping` → `ial_acr_mapping`.
  The legacy IAF `…/loa/1` and `…/loa/3` URIs that several CSPs still emit
  are absorbed by the built-in mapping (with the conservative `…/loa/3` →
  IAL-2 translation baked in) — they never enter the rest of the codebase.

### Added

- **Universal `ial_acr_mapping`** — single built-in mapping that handles both
  canonical NIST 800-63-3 `…/ial/N` URIs and the legacy IAF `…/loa/1`/`…/loa/3`
  URIs. Translates conservatively: `…/loa/3` → IAL-2 (not IAL-3) so a verifier
  with `require_ial=3` correctly rejects legacy LOA-3 tokens. Replaces the
  old `loa_acr_mapping` + `idme_acr_mapping` pair.
- **`CSP_ACR_MAPPING` selector** — choose the ACR mapping without touching
  code. Values: `ial` (default) or `pkg.module:function_name` for a custom
  mapping. Custom mappings let any CSP plug in via env alone.

## [0.0.1] — 2026-05-24

First public alpha. Library, CLI, three runnable examples; hermetic test
suite + one gated live-sandbox test.

### Added

- **Claim model** (`claims.py`) — Pydantic v2 `Passport`, `ActClaim`,
  `AgentClaims` with round-trip JWT serialization. Namespaced agent claims
  expand to top-level JWT keys at the `https://agent-passport.org/claims/`
  URI prefix.
- **Verifier** (`verifier.py`) — signature, time window with configurable
  clock skew (default 30s, hard ceiling 120s), trusted-issuer allowlist,
  exact-match audience, IAL/AAL/FAL floors, wildcard policy, required scope
  (`fnmatch` semantics), and chain walking with re-verification of
  attenuation + IAL monotonicity at every link.
- **Issuer** (`issuer.py`) — RFC 8693 token exchange from a CSP ID token to
  a signed Passport; `delegate()` for child-token minting with
  scope-attenuation enforcement (`ScopeAttenuationError` on violation).
- **OIDC client** (`oidc/`) — `IDTokenValidator` resolves CSPs entirely
  through well-known discovery (RFC 8414 / OIDC Discovery 1.0); `ial_acr_mapping`
  in `oidc/base.py` translates the CSP's `acr` URI to canonical IAL/AAL/FAL,
  with a conservative default for the legacy IAF `…/loa/3` URI that several
  CSPs still emit (translated to IAL-2, not IAL-3 — DESIGN NOTE explains why
  this matters for downstream verifiers with `require_ial=3`).
- **CLI** (`cli.py`) — `agent-passport login` / `issue` / `verify` /
  `inspect` / `delegate` / `where`. OAuth 2.0 Authorization Code + PKCE
  (RFC 7636) over a local-loopback redirect (RFC 8252) for the login flow.
  Tokens compose via stdin pipes.
- **Storage** (`_storage.py`) — XDG-style persistence
  (`$XDG_DATA_HOME/agent-passport/`) for the ID token, ID-token metadata,
  and the issuer's signing key (RSA-2048, generated on first use, chmod 600).
- **Mock OIDC provider** (`tests/fixtures/mock_oidc/`) — in-process
  `ThreadingHTTPServer` with discovery + JWKS endpoints and an ID-token
  mint helper, used by the entire test suite for hermetic E2E coverage.
- **Examples** (`examples/`) — `quickstart.py`, `multi_agent_chain.py`,
  `mcp_middleware.py`, `langchain_tool_wrapper.py`. All run from a clean
  checkout against the mock OIDC.
- **Typed exception hierarchy** rooted at `AgentPassportError`, split into
  `VerificationError` (verifier-side failures) and `IssuanceError`
  (issuer-side: `DiscoveryError`, `JWKSError`, `UnsupportedAcr`,
  `ScopeAttenuationError`).
- **Documentation** — `README.md` (quickstart, CLI reference, examples
  table, project layout), `CLAUDE.md` (full design context: trust model,
  standards rationale, security guardrails).

### Security

- `alg: none` is rejected at the `VerificationPolicy` constructor and at
  the JWS header parse, before any JOSE library call (defense in depth).
- Allowed JOSE algorithms pinned to `RS256`, `ES256`, `EdDSA` by default;
  HMAC algorithms explicitly out (asymmetric keys required so the issuer's
  private key never reaches verifiers).
- Scope attenuation enforced at both issuance (`ScopeAttenuationError`) and
  verification (chain walk in `ChainBroken`).
- IAL/AAL/FAL monotonic non-increasing along the chain; CSP-attested levels
  cannot be raised by intermediate agents.
- Wildcard scope (`*`) is default-deny; verifiers must opt in via
  `allow_wildcard_scope=True`.
- Audience is exact-match; substring and path-prefix mismatches rejected.
- Pairwise `sub` always sourced from the CSP; never overwritten by the agent.
- PKCE (S256) and cryptographically-random `state` on the login flow;
  loopback-only redirect URI per RFC 8252.
- Tokens stored at chmod 600; private signing key (JWK JSON) chmod 600.

### Quality gates

- 172 tests + 1 gated (live ID.me sandbox), all hermetic by default.
- `mypy --strict` passes on `src/` and `tests/` (30 files).
- `ruff check` and `ruff format` clean.
- Coverage ~84% overall; 100% on `claims`, `errors`, `keys`, `_scope`, the
  OIDC base + adapter, and the package root.

### Known limitations

- No token revocation endpoint (RFC 7662) — short TTLs are the sole
  defense; on the roadmap for v0.1.
- Single-issuer single-key v0 — JWKS hosting, key rotation, and an HSM
  back end are explicitly deferred.
- The login flow against a real CSP is exercised by the CLI's
  `--id-token` paste-in path in tests; full browser-OAuth integration
  testing requires extending the mock provider with `/authorize` + `/token`
  endpoints.
- The built-in `ial_acr_mapping` handles canonical NIST `…/ial/N` URIs plus
  two legacy IAF URIs (`…/loa/1`, `…/loa/3`). CSPs that emit other ACR forms
  need a custom `AcrMapping` wired in via `CSP_ACR_MAPPING=pkg.module:func`.
