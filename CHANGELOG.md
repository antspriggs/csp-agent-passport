# Changelog

All notable changes to Agent Passport are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Aligns Agent Passport with
[draft-ietf-oauth-identity-assertion-authz-grant-06](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/)
(ID-JAG, 31 Oct 2026), the IETF spec behind Cross App Access and MCP's
Enterprise-Managed Authorization. Token shape is unchanged; the only wire
change is a `typ` header on newly issued Passports.

### Added

- **`IdJagValidator`** (`csp_agent_passport.idjag`): Resource Authorization
  Server-side validation of ID-JAGs presented via the RFC 7523 jwt-bearer
  grant, per -06 §4.4.1: `typ` = `oauth-id-jag+jwt`, trusted `iss` (+
  `tenant` for multi-tenant IdPs), per-IdP algorithm allowlist (RS256 +
  ES256 default), `aud` = this AS's issuer, `client_id` = the authenticated
  client, time window + maximum lifetime, `resource` governed by this AS
  (simple string comparison), and `jti` replay protection (on by default via
  `InMemoryReplayCache`; pluggable `ReplayCache` for multi-replica). The
  IdP's `acr` goes through the same `AcrMapping` as the Passport issuer, so
  an AS can enforce NIST SP 800-63-3 IAL/AAL/FAL floors on an ID-JAG, which
  the spec itself does not define. `oauth_error_for()` maps failures to
  `invalid_grant` / `invalid_client`.
- **`Issuer.issue_from_id_jag(IdJagIssuanceRequest)`**: mints a Passport as
  the Resource AS's access token from a verified ID-JAG. `aud` must be one
  of the grant's `resource` values; `sub`, `acr`, and IAL/AAL/FAL come from
  the grant and cannot be overridden.
- **`DiscoveryKeyStore`**: `KeyStore` configured by issuer URL alone.
  Resolves RFC 8414 metadata (path-inserted), falls back to OIDC Discovery,
  enforces metadata `issuer` == configured issuer (RFC 8414 §3.3, ID-JAG
  §9.5), caches JWKS by `kid` with rate-limited refetch on miss.
- New typed errors: `TokenTypeMismatch`, `ClientMismatch`,
  `ClientAuthenticationRequired`, `SenderConstraintUnsupported`,
  `ResourceNotGoverned`, `ReplayDetected`, `LifetimeTooLong`.

### Changed

- **Passports now carry `typ: agent-passport+jwt`** (RFC 8725 §3.11 explicit
  typing). The verifier **always** rejects a Passport whose `typ` names a
  different JWT type (`at+jwt`, `oauth-id-jag+jwt`, ...). Untyped tokens
  (no `typ`, or the generic `JWT` that pre-v0.3.0 issuers emitted) are still
  accepted unless `VerificationPolicy(require_typ=True)`. **Deprecation:**
  the `require_typ` default flips to `True` in v0.4.0.

### Security

- **`IDTokenValidator` rejects non-ID-token JWTs as subject tokens.** Before
  this change, a CSP-signed RFC 9068 access token (or ID-JAG, logout token,
  ...) whose `aud` equalled the issuer's `client_id` would have been accepted
  as an ID token and exchanged for a Passport. ID-JAG -06 §4.3.3 requires a
  token-exchange server to reject subject tokens whose `typ` names a
  different token type. Implemented as a denylist of registered JWT types so
  CSPs that send `typ: JWT` or no `typ` keep working.

### Not implemented (documented)

- Proof of possession (`cnf`, -06 §9.11). ID-JAGs carrying `cnf` are
  rejected with `SenderConstraintUnsupported`, as the spec requires of a
  server that cannot verify the confirmation method. Tracked with the
  existing RFC 7800 `cnf` roadmap item.
- Agent Passport does not *issue* ID-JAGs. That is the enterprise IdP's role;
  see README "ID-JAG and MCP Enterprise-Managed Authorization".

## [0.2.1] — 2026-05-26

The v0.2.0 rename to `agent-passport` could not be claimed on PyPI — the
similarity check rejected it as too close to the existing `nist-agent-passport`
and `agent-passport-system` projects. v0.2.1 re-renames to `csp-agent-passport`
("CSP" per NIST SP 800-63 terminology for Credential Service Provider, which
accurately describes the project's substrate role without claiming NIST
endorsement). The GitHub repository was renamed alongside, so `nist-` no longer
appears in any URL or title. **v0.2.0 was never released to PyPI**; v0.2.1 is
the first PyPI release under the new name.

### Changed (breaking)

- **Renamed package from `agent-passport` to `csp-agent-passport`.**
  - Python import path: `agent_passport` → `csp_agent_passport`
  - PyPI distribution: `agent-passport` → `csp-agent-passport`
  - CLI binary: `agent-passport` → `csp-agent-passport`
  - Claim namespace URI **unchanged** at `https://agent-passport.org/claims/`
    — wire-compatible across every rename in this project's history.
- **GitHub repository renamed** from `antspriggs/nist-agent-passport` to
  `antspriggs/csp-agent-passport`. GitHub serves permanent redirects on the
  old URL; existing inbound links continue to work. Developers with local
  clones should update the remote:
  `git remote set-url origin https://github.com/antspriggs/csp-agent-passport.git`.
- **XDG state directory chain-migration.** `_storage.xdg_data_dir()` now
  auto-migrates two legacy directory names — `agent-passport/` (v0.2.0,
  never shipped on PyPI but used by local devs) and `nist-agent-passport/`
  (v0.0.1–v0.1.x, shipped) — to the current `csp-agent-passport/`. The
  newer legacy wins when both exist; the current dir is never clobbered.
  Five tests in `tests/test_storage_migration.py` cover the cases.

### Notes

- PyPI Trusted Publisher must be re-registered for the new project name
  before this release can publish. Owner `antspriggs`, Repository name
  `csp-agent-passport`, Workflow filename `release.yml`, Environment `pypi`.

## [0.2.0] — 2026-05-26 *(never released to PyPI — superseded by [0.2.1])*

Intended breaking release: package and CLI renamed from `nist-agent-passport`
to `agent-passport` per NIST endorsement policy. The PyPI Project Name
`agent-passport` turned out to be unobtainable (similarity check). The rename
mechanical work and supporting docs are preserved here for history; the
re-rename to `csp-agent-passport` is in [0.2.1].

### Changed (breaking)

- **Renamed package from `nist-agent-passport` to `agent-passport`.**
  [NIST's published policy](https://www.nist.gov/open/license) forbids
  implying NIST approves or endorses any product; a `nist-` prefix from
  a non-NIST author crosses that line. There is no formal NIST
  endorsement of this library — the alignment with NCCOE / RFC 8693 /
  SP 800-63-3 is genuine and is now claimed in prose rather than in
  the package name.
  - Python import path: `nist_agent_passport` → `agent_passport`
  - PyPI distribution: `nist-agent-passport` → `agent-passport`
  - CLI binary: `nist-agent-passport` → `agent-passport`
  - Claim namespace URI **unchanged** at `https://agent-passport.org/claims/`.
  - GitHub repository URL **unchanged** at
    https://github.com/antspriggs/nist-agent-passport (URL stability
    for inbound links). *(Subsequently renamed in v0.2.1.)*
- **XDG state directory auto-migration.** `_storage.py` checks for a
  legacy `$XDG_DATA_HOME/nist-agent-passport/` on first call to
  `xdg_data_dir()`; if present and the new `$XDG_DATA_HOME/agent-passport/`
  does not yet exist, the directory is renamed in place — preserving the
  issuer signing key and any stored ID token. *(Subsequently extended to
  also migrate from `agent-passport/` in v0.2.1.)*

### Added

- **`COMPARISON.md`** — honest positioning vs. ZeroID (closest
  comparable OSS), SPIFFE/SPIRE (complementary, not competing), other
  projects in the broader agent-passport namespace, and commercial NHI
  vendors.
- **`ROADMAP.md`** extended with candidate items from the May 2026
  standards-landscape scan: MCP authorization-spec parity (RFC 9728
  Protected Resource Metadata, RFC 7591 Dynamic Client Registration,
  RFC 8707 Resource Indicators, first-class MCP middleware); agentic
  commerce claims (`txn_constraints`, `cart_binding`, `intent_digest`,
  `txn_id` mirroring AP2 / ACP / Mastercard field names);
  proof-of-possession via RFC 7800 `cnf`; SPIFFE-shaped `agent_id`;
  chain-visualization `inspect --tree`; standards alignment
  refinements; new Ecosystem alignment section with a quarterly IETF /
  OpenID / commerce-protocol watch list.

### Changed

- **RFC 8485 Vectors of Trust demoted to "input-side only"** in
  CLAUDE.md and README. The active 2025–2026 agent-identity drafts
  (OpenID whitepaper, `draft-klrc-aiagent-auth`, AuthZEN, WIMSE) do not
  cite VoT; the de facto vocabulary is OIDC `acr` + IDA `verified_claims`.
  The IAL/AAL/FAL numerics in the token remain canonical — no token-shape
  change. The library still reads `vot/vtm/vtr` from the CSP when emitted.
- **README intro blockquote** corrected — "NIST SP 800-63 Vectors of
  Trust" conflated two different standards; replaced with "NIST SP
  800-63-3 assurance levels."

### Fixed

- **`pyproject.toml` project URLs** were pointing at a non-existent
  `nist-agent-passport/nist-agent-passport` GitHub org; corrected to
  `antspriggs/nist-agent-passport` (the actual repo at v0.2.0 time;
  later renamed in v0.2.1). Added `Documentation`, `Changelog`,
  `Roadmap` URLs while there.

## [0.1.2] — 2026-05-25

First release with the complete release-provenance enforcement chain
active end-to-end. No library/API changes; pure release-pipeline
hardening + SBOM validation.

### Added

- **Release-from-main invariant enforced by the release workflow.**
  `release.yml` refuses to publish if the tagged commit is not
  reachable from `origin/main` — guards against tagging an unmerged
  commit (tags are a separate namespace from branches and aren't
  covered by branch protection). Combined with the existing `main`
  branch protection (PRs required, admin-enforced) and the new `pypi`
  environment deployment-branches policy (restricts deploys to `v*`
  tag refs), every PyPI artifact corresponds to a PR-reviewed,
  CI-green, on-`main` commit, approved at deploy time. Documented in
  `GOVERNANCE.md` under "Release policy".

### Fixed

- **Release workflow could publish to PyPI but failed to attach the
  SBOM** to the GitHub Release (HTTP 403 from `gh release upload`,
  observed during the v0.1.1 run). Root cause: granting
  `id-token: write` to the workflow caused all other permissions to
  default to read/none, denying the `contents: write` that
  `gh release upload` requires. Fixed by adding `contents: write`
  explicitly. SBOMs for v0.1.0 and v0.1.1 were backfilled by
  uploading generated CycloneDX docs to those releases via a local
  `gh release upload`; v0.1.2 will be the first release where the
  SBOM attach step runs successfully in CI.

## [0.1.1] — 2026-05-24

### Fixed

- **README links broken on PyPI.** Relative Markdown links (`./CLAUDE.md`,
  `./CONTRIBUTING.md`, `examples/quickstart.py`, …) rendered as dead
  links on the PyPI project page because PyPI doesn't resolve relative
  paths from a README. Rewritten to absolute `https://github.com/...`
  URLs that resolve correctly on both PyPI and GitHub.

### Added

- **`GOVERNANCE.md`** — documents the BDFL model (@antspriggs is current
  BDFL), how decisions get made, what's out of scope even for the BDFL,
  how the model is expected to evolve as the project grows, and how to
  remove/replace the BDFL if needed.
- **Versioning & deprecation policy** in `README.md` — pinned: in `0.y.z`
  any release MAY break; from `1.0.0` onward, deprecations get at least
  one minor-version notice and CHANGELOG lists them explicitly. SemVer
  2.0.0 throughout.
- **CycloneDX SBOM per release** — `release.yml` now generates a
  CycloneDX JSON SBOM against the resolved dependency tree of the
  just-built wheel and uploads it as a GitHub Release asset (filename:
  `nist-agent-passport-{version}.cdx.json` through v0.1.x;
  `csp-agent-passport-{version}.cdx.json` from v0.2.1+).

## [0.1.0] — 2026-05-24

First **PyPI** release. Substantive renaming, scope-driven-auth-by-default,
and OSS-readiness work since v0.0.1.

### Changed (breaking)

- **Renamed package from `agent-passport` to `nist-agent-passport`.** The
  generic name is contested in the agent-identity namespace (multiple
  parallel projects: an `agentpassport` PyPI suite, `agent-passport-standard`
  with blockchain anchoring, `agentpassportai/agent-passport` framed as
  "OAuth for the agentic era"). The new name signals the NIST 800-63-3 /
  RFC 8693 / OIDC + PKCE lineage explicitly, which is this project's
  differentiated value. (Note: this rename was itself reverted in v0.2.0
  per NIST endorsement policy, then re-renamed to `csp-agent-passport`
  in v0.2.1 when PyPI rejected `agent-passport` for similarity.)
  - Python import path: `agent_passport` → `nist_agent_passport`
  - PyPI package: `agent-passport` → `nist-agent-passport`
  - CLI binary: `agent-passport` → `nist-agent-passport`
  - Claim namespace URI **unchanged** at `https://agent-passport.org/claims/`
    (semantic identifier separate from the package name; any tokens issued
    against the v0.0.1 namespace still parse against the renamed library).
- **CLI `verify --require-ial/aal/fal` defaults are now 0** (was 1) and
  the accepted range is `0..3` (was `1..3`). `0` skips the check; matches
  the library's `VerificationPolicy.require_*` default. Surfaced by the
  first real-CSP integration test against production ID.me (no `acr`
  claim emitted; previous CLI default would have rejected legitimate
  scope-only tokens).
- **ACR / IAL / AAL / FAL are now optional throughout.** Aligned with
  OIDC (where `acr` is optional) and supports scope-driven auth as a
  first-class deployment mode. `Passport.acr/ial/aal/fal` and
  `OIDCAssertion.acr/ial/aal/fal` are `Optional`; `IDTokenValidator`
  no longer raises on missing `acr`; verifier chain walk enforces that
  assurance levels can only propagate forward (a child cannot claim
  what its parent doesn't assert).
- **Generic `CSP_*` env vars.** Renamed from `IDME_*` so the same
  configuration works with any OIDC + PKCE provider.

### Added

- **`CODE_OF_CONDUCT.md`** — Contributor Covenant 2.1, enforcement
  contact wired to the maintainer.
- **`MAINTAINERS.md`** — names the maintainer (`@antspriggs`) with role
  + contact, documents how to propose maintainership.
- **`pip-audit` step in CI** — fails the build on any OSV-known CVE in
  the resolved dependency tree; skips our own editable install.
- **`.github/workflows/release.yml`** — publishes to PyPI on GitHub
  Release via Trusted Publishing (OIDC, no API token in repo secrets).
- **First real-CSP integration validated** against production ID.me.
  The library handles the no-`acr` path end-to-end via scope-driven
  auth; the integration revealed (and we fixed) a CLI default-mismatch
  bug that had survived the unit-test matrix.

### Fixed

- `test_login_missing_env_fails_cleanly` no longer depends on absence
  of `.env`; uses `setenv("")` so `python-dotenv` cannot repopulate
  the var at test time.

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
- **CLI** (`cli.py`) — `agent-passport login` / `issue` / `verify` /
  `inspect` / `delegate` / `where`. OAuth 2.0 Authorization Code + PKCE
  (RFC 7636) over a local-loopback redirect (RFC 8252) for the login flow.
  Generic `CSP_*` env vars — works with any OIDC + PKCE provider.
  `CSP_ACR_MAPPING` selector (`ial` default, or `pkg.module:func_name`
  for a custom mapping) lets non-standard CSPs slot in via env alone, no
  code changes.
- **Storage** (`_storage.py`) — XDG-style persistence
  (`$XDG_DATA_HOME/agent-passport/`) for the ID token, ID-token metadata,
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
