# Changelog

All notable changes to NIST Agent Passport are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed (breaking)

- **Renamed package from `agent-passport` to `nist-agent-passport`.** The
  generic name is contested in the agent-identity namespace (multiple
  parallel projects: an `agentpassport` PyPI suite, `agent-passport-standard`
  with blockchain anchoring, `agentpassportai/agent-passport` framed as
  "OAuth for the agentic era"). The new name signals the NIST 800-63-3 /
  RFC 8693 / OIDC + PKCE lineage explicitly, which is this project's
  differentiated value.
  - Python import path: `agent_passport` → `nist_agent_passport`
  - PyPI package: `agent-passport` → `nist-agent-passport`
  - CLI binary: `agent-passport` → `nist-agent-passport`
  - Claim namespace URI **unchanged** at `https://agent-passport.org/claims/`
    (semantic identifier separate from the package name; any tokens issued
    against the v0.0.1 namespace still parse against the renamed library).

### Added

- **`CODE_OF_CONDUCT.md`** — Contributor Covenant 2.1, enforcement
  contact wired to the maintainer.
- **`MAINTAINERS.md`** — names the maintainer (`@antspriggs`) with role
  + contact, documents how to propose maintainership.
- **`pip-audit` step in CI** — fails the build on any OSV-known CVE in
  the resolved dependency tree (`--strict` mode).
- **`.github/workflows/release.yml`** — publishes to PyPI on GitHub
  Release via Trusted Publishing (OIDC, no API token in repo secrets).
  Requires a one-time registration on PyPI's side before the first
  release will succeed; see the workflow's header comment.

## [0.0.1] — 2026-05-24

First public alpha. Library, CLI, four runnable examples; hermetic test
suite + GitHub Actions CI matrix on Python 3.11 / 3.12 / 3.13.

### Added

- **Claim model** (`claims.py`) — Pydantic v2 `Passport`, `ActClaim`,
  `AgentClaims` with round-trip JWT serialization. Namespaced agent claims
  expand to top-level JWT keys at the `https://agent-passport.org/claims/`
  URI prefix. `acr` / `ial` / `aal` / `fal` are all optional — scope-driven
  auth is a supported deployment mode.
- **Verifier** (`verifier.py`) — signature, time window with configurable
  clock skew (default 30s, hard ceiling 120s), trusted-issuer allowlist,
  exact-match audience, IAL/AAL/FAL floors (default 0 = unset; opt-in via
  `require_*` ≥ 1), wildcard policy, required scope (`fnmatch` semantics),
  and chain walking with re-verification of attenuation + IAL/AAL/FAL
  monotonicity at every link. Chain rule: assurance levels propagate
  forward only — a child cannot claim an assurance level the parent
  doesn't have.
- **Issuer** (`issuer.py`) — RFC 8693 token exchange from a CSP ID token to
  a signed Passport; `delegate()` for child-token minting with
  scope-attenuation enforcement (`ScopeAttenuationError` on violation).
- **OIDC client** (`oidc/`) — `IDTokenValidator` resolves CSPs entirely
  through well-known discovery (RFC 8414 / OIDC Discovery 1.0); no
  hardcoded endpoints. `ial_acr_mapping` in `oidc/base.py` translates the
  CSP's `acr` URI to canonical IAL/AAL/FAL, handling both the canonical
  NIST `…/ial/N` URIs and the legacy IAF `…/loa/1`/`…/loa/3` URIs that
  several CSPs still emit. `…/loa/3` translates conservatively to IAL-2
  (not IAL-3) — a verifier with `require_ial=3` therefore correctly
  rejects legacy LOA-3 tokens.
- **CLI** (`cli.py`) — `nist-agent-passport login` / `issue` / `verify` /
  `inspect` / `delegate` / `where`. OAuth 2.0 Authorization Code + PKCE
  (RFC 7636) over a local-loopback redirect (RFC 8252) for the login flow.
  Generic `CSP_*` env vars — works with any OIDC + PKCE provider.
  `CSP_ACR_MAPPING` selector (`ial` default, or `pkg.module:func_name`
  for a custom mapping) lets non-standard CSPs slot in via env alone, no
  code changes.
- **Storage** (`_storage.py`) — XDG-style persistence
  (`$XDG_DATA_HOME/nist-agent-passport/`) for the ID token, ID-token metadata,
  and the issuer's signing key (RSA-2048, generated on first use, chmod 600).
- **Mock OIDC provider** (`tests/fixtures/mock_oidc/`) — in-process
  `ThreadingHTTPServer` with discovery + JWKS endpoints and an ID-token
  mint helper, used by the entire test suite for hermetic E2E coverage.
- **Examples** (`examples/`) — `quickstart.py`, `multi_agent_chain.py`,
  `mcp_middleware.py`, `langchain_tool_wrapper.py`. All run from a clean
  checkout against the mock OIDC; each is smoke-tested in CI.
- **Typed exception hierarchy** rooted at `AgentPassportError`, split into
  `VerificationError` (verifier-side failures) and `IssuanceError`
  (issuer-side: `DiscoveryError`, `JWKSError`, `UnsupportedAcr`,
  `ScopeAttenuationError`).
- **Project hygiene** — `LICENSE` (Apache-2.0), `CONTRIBUTING.md` (DCO
  sign-off required), `SECURITY.md` (private vuln-disclosure via GitHub
  Security Advisories), GitHub Actions CI workflow, PEP 561 `py.typed`
  marker for downstream type-checking, branch protection on `main`.
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
  cannot be raised by intermediate agents. Levels propagate forward only:
  agents cannot manufacture assurance the CSP didn't attest.
- Wildcard scope (`*`) is default-deny; verifiers must opt in via
  `allow_wildcard_scope=True`.
- Audience is exact-match; substring and path-prefix mismatches rejected.
- Pairwise `sub` always sourced from the CSP; never overwritten by the agent.
- PKCE (S256) and cryptographically-random `state` on the login flow;
  loopback-only redirect URI per RFC 8252.
- Tokens stored at chmod 600; private signing key (JWK JSON) chmod 600.
- No vendor-specific identifiers in the public API; the library is
  generic OIDC + PKCE end to end. Legacy `…/loa/N` URIs that some CSPs
  emit are absorbed at the `ial_acr_mapping` boundary and never enter the
  rest of the codebase.

### Quality gates

- 166 tests passing, all hermetic by default.
- `mypy --strict` passes on `src/` and `tests/` (28 files).
- `ruff check` and `ruff format` clean.
- Coverage ~91% overall; 100% on `claims`, `errors`, `keys`, `_scope`,
  `oidc/base`, and the package root.
- GitHub Actions CI green on Python 3.11 / 3.12 / 3.13.

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
