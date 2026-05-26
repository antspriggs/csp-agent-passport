# Agent Passport

> Verifiable, identity-rooted delegation tokens for AI agents — built on existing standards (OIDC, OAuth 2.0 Token Exchange, JWT, NIST SP 800-63-3 assurance levels).

**Status:** v0 alpha. Library, CLI, and three runnable examples work end-to-end against a hermetic mock OIDC provider. Live CSP integration needs your `CSP_*` configuration in `.env`.

## Why

When a user tells an AI agent "do X on my behalf," there is no standard, verifiable way for a downstream tool, MCP server, or another agent to know:

1. **Who** the principal is (and how strongly that identity was proofed),
2. **What** authority the agent was actually granted,
3. **For how long** the grant is valid,
4. **What chain** of delegation got us here (user → agent A → agent B → tool C).

Most agent frameworks paper over this with bare API keys. Agent Passport closes the gap with short-lived, scope-bound, NIST-identity-rooted delegation tokens that downstream verifiers check cryptographically — with chain attenuation enforced at issuance *and* re-checked at verification.

This project is a concrete contribution to the [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative) and the related [NCCOE Software and AI Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization) project.

## Install

Requires Python 3.11+.

```bash
pip install nist-agent-passport
```

The install registers a `nist-agent-passport` console script.

For local development (running the test suite, editing source), see
[CONTRIBUTING.md](https://github.com/antspriggs/nist-agent-passport/blob/main/CONTRIBUTING.md) for the editable-install instructions.

## Quickstart

The fastest path to seeing the full loop without any external CSP credentials is to run one of the bundled examples:

```bash
python examples/quickstart.py
```

That script boots an in-process mock OIDC provider, mints an ID token, exchanges it for an Agent Passport (RFC 8693), verifies it against a policy, and demonstrates two typed-error paths. Output is annotated section-by-section.

For real CSP integration, copy `.env.example` to `.env`, fill in your sandbox credentials, then drive the CLI:

```bash
nist-agent-passport login                                                  # OAuth code + PKCE; browser opens
nist-agent-passport issue \
    --agent-id agent:alice \
    --agent-model claude-opus-4-7 \
    --tool-scope 'flights:*' \
    --task-purpose 'book a flight SFO->JFK' \
    --aud https://my-mcp-server.example.com/ \
    --ttl 900 > passport.jwt

nist-agent-passport inspect < passport.jwt                                 # decode and pretty-print
nist-agent-passport verify --aud https://my-mcp-server.example.com/ \
    --require-ial 2 --required-scope 'flights:book' < passport.jwt
```

To delegate further (e.g., from agent Alice to agent Bob):

```bash
nist-agent-passport delegate \
    --agent-id agent:bob \
    --agent-model claude-opus-4-7 \
    --tool-scope 'flights:book' \
    --aud https://other-svc.example.com/ \
    --ttl 300 < passport.jwt > child.jwt
```

`nist-agent-passport --help` lists all subcommands; each has its own `--help`.

## Configure your CSP

Agent Passport works with any OIDC + PKCE provider via a generic `CSP_*` env-var namespace. Discovery-driven by design (per OIDC Discovery 1.0 / RFC 8414), so only the well-known URL is hardcoded:

| Variable | Purpose |
|---|---|
| `CSP_DISCOVERY_URL` | Full URL to your CSP's `/.well-known/openid-configuration`. |
| `CSP_CLIENT_ID` | OAuth client identifier for your registered app. |
| `CSP_CLIENT_SECRET` | OAuth client secret (omit / leave blank for public clients). |
| `CSP_REDIRECT_URI` | Loopback callback URL for the OAuth code flow; RFC 8252 requires `http://localhost:<port>` or `http://127.0.0.1:<port>`. |
| `CSP_SCOPES` | Space-separated OIDC scopes (e.g. `"openid email profile"`). |
| `CSP_ACR_MAPPING` | Which `acr` → IAL/AAL/FAL mapping to use: `ial` (default — handles NIST 800-63-3 `…/ial/N` URIs plus the legacy `…/loa/1` and `…/loa/3` URIs that some providers still emit), or a Python import path `pkg.module:func_name` for a custom mapping when your CSP emits ACR URIs outside the built-in set. |

For most CSPs, only `CSP_DISCOVERY_URL` and `CSP_CLIENT_ID`/`SECRET` need changing — the built-in `ial` mapping handles the common URI forms. Custom CSPs slot in via a one-function `AcrMapping` referenced by Python import path; no library changes needed.

## CLI reference

| Command | Purpose |
|---|---|
| `login` | OAuth Authorization Code + PKCE against the configured CSP (RFC 8252). Stores the ID token under `$XDG_DATA_HOME/nist-agent-passport/`. `--id-token <jwt>` skips the OAuth dance for paste-in / scripted use. |
| `issue` | Mint a root Passport from the stored ID token. Flags: `--agent-id`, `--agent-model`, `--tool-scope` (repeatable), `--task-purpose`, `--aud`, `--ttl` (default 900s). |
| `verify <token>` | Verify against a policy and print the verified claims as JSON. Flags: `--aud` (required), `--require-ial`/`--require-aal`/`--require-fal`, `--required-scope`, `--issuer` (repeatable). Token from arg or stdin. |
| `inspect <token>` | Decode (no signature check) and pretty-print every claim, including namespaced agent claims and any chained `act`. |
| `delegate <parent>` | Mint a child Passport from a parent (with attenuated scope). Flags: `--agent-id`, `--agent-model`, `--aud`, `--tool-scope` (repeatable), `--task-purpose`, `--ttl` (default 300s). |
| `where` | Print the XDG data directory used for the ID-token store and the local issuer's signing key. |

All token args read from stdin when `-` or absent, so the commands compose:

```bash
nist-agent-passport issue ... | nist-agent-passport delegate --aud ... --agent-id ...
```

## Examples

| File | What it shows |
|---|---|
| [`examples/quickstart.py`](https://github.com/antspriggs/nist-agent-passport/blob/main/examples/quickstart.py) | The full loop: login → issue → verify, plus two failure-mode demos (`AudienceMismatch`, `IALInsufficient`). |
| [`examples/multi_agent_chain.py`](https://github.com/antspriggs/nist-agent-passport/blob/main/examples/multi_agent_chain.py) | Alice → Bob → Carol delegation; the leaf service walks the full chain, re-checking attenuation and IAL monotonicity; prints the delegation tree. |
| [`examples/mcp_middleware.py`](https://github.com/antspriggs/nist-agent-passport/blob/main/examples/mcp_middleware.py) | A `PassportMiddleware` class that wraps a tool dispatcher, enforces per-tool `required_scope`, and shows defense-in-depth refusal of overbroad and wrong-audience tokens. Drop-in pattern for MCP servers. |
| [`examples/langchain_tool_wrapper.py`](https://github.com/antspriggs/nist-agent-passport/blob/main/examples/langchain_tool_wrapper.py) | A `PassportProtectedTool` shape-compatible with `langchain_core.tools.BaseTool`. Demonstrates scope enforcement and signature-tamper detection. |

Every example runs from a clean checkout against the hermetic in-process mock OIDC provider — no external creds needed:

```bash
python examples/quickstart.py
python examples/multi_agent_chain.py
python examples/mcp_middleware.py
python examples/langchain_tool_wrapper.py
```

## How this fits

There are several adjacent open-source projects. The honest map:

- **You want a turnkey identity *service*** (Postgres + server, real-time revocation today, DPoP, dynamic client registration) — look at [ZeroID](https://github.com/highflame-ai/zeroid).
- **You want a `pip install` *library*** to embed in an MCP middleware or LangChain tool wrapper, with NIST SP 800-63-3 IAL/AAL/FAL propagated through the delegation chain — you're in the right place.
- **You need workload identity** (cryptographically attested "what runtime is this?") — look at [SPIFFE/SPIRE](https://spiffe.io/). It composes with Agent Passport, doesn't replace it.
- **You're a security team buying a control plane** (discovery, governance, dashboards) — look at the commercial NHI vendors (Aembit, Astrix, Oasis, Token, Entro). This library deliberately doesn't compete there.

See [COMPARISON.md](https://github.com/antspriggs/nist-agent-passport/blob/main/COMPARISON.md) for the full write-up, including where Agent Passport is ahead, behind, or complementary.

## Library use

Three primitives compose to cover every use case:

```python
from nist_agent_passport import (
    Issuer, IssuanceRequest, DelegationRequest,
    Verifier, VerificationPolicy, InMemoryKeyStore,
    IDTokenValidator, ial_acr_mapping,
)
```

- **`Issuer`** takes an OIDC-validated identity assertion (via `IDTokenValidator` + an `AcrMapping`) and mints signed delegation Passports. `issue()` for roots; `delegate()` for children (with issuer-side scope-attenuation enforcement).
- **`Verifier`** validates a Passport against a `VerificationPolicy`: signature, time window with clock-skew tolerance, trusted issuer, audience exact-match, IAL/AAL/FAL floors, wildcard policy, required scope. For chained tokens, `verify(token, chain=[...])` walks the chain root-first and re-checks every link.
- **`IDTokenValidator`** validates an OIDC ID token against a CSP discovered via `/.well-known/openid-configuration` (no hardcoded endpoints). `ial_acr_mapping` is the built-in `acr` → IAL/AAL/FAL translation; supply your own `AcrMapping` for CSPs that emit non-standard URIs.

Typed exceptions inherit from `AgentPassportError`:
- `VerificationError` branch: `InvalidSignature`, `Expired`, `NotYetValid`, `AudienceMismatch`, `IALInsufficient`, `ScopeViolation`, `WildcardScopeNotAllowed`, `ChainBroken`, `MalformedClaims`, …
- `IssuanceError` branch: `DiscoveryError`, `JWKSError`, `UnsupportedAcr`, `ScopeAttenuationError`.

Branch on the type, not the message.

## Standards

Agent Passport composes existing standards rather than inventing new ones:

- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — JSON Web Token
- [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) — JSON Web Signature
- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — OAuth 2.0 Token Exchange (the `act` claim and nested actor chains)
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) — PKCE
- [RFC 8252](https://datatracker.ietf.org/doc/html/rfc8252) — OAuth 2.0 for Native Apps (local-loopback redirect)
- [RFC 8485](https://datatracker.ietf.org/doc/html/rfc8485) — Vectors of Trust (input-side only; carried through from the CSP when emitted, but IAL/AAL/FAL numerics are the canonical assurance representation in the Passport)
- [NIST SP 800-63-3](https://pages.nist.gov/800-63-3/) — Digital Identity Guidelines (IAL/AAL/FAL)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) and [Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)

## Project layout

```
nist-agent-passport/
├── pyproject.toml
├── README.md
├── CLAUDE.md                              # full design context
├── .env.example                           # CSP config template
├── src/nist_agent_passport/
│   ├── claims.py                          # Pydantic Passport / AgentClaims / ActClaim
│   ├── issuer.py                          # Issuer, IssuanceRequest, DelegationRequest
│   ├── verifier.py                        # Verifier, VerifiedPassport, chain walking
│   ├── policy.py                          # VerificationPolicy
│   ├── keys.py                            # KeyStore Protocol + InMemoryKeyStore
│   ├── errors.py                          # typed exception hierarchy
│   ├── cli.py                             # Typer-based CLI
│   └── oidc/
│       ├── base.py                        # OIDCClient Protocol, AssuranceLevels, ial_acr_mapping
│       └── validator.py                   # IDTokenValidator (discovery + JWKS)
├── examples/                              # see "Examples" above
└── tests/
    ├── fixtures/mock_oidc/                # in-process OIDC provider for hermetic tests
    └── test_*.py                          # 141+ tests; full coverage of every error path
```

## Versioning & deprecation policy

The project follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

**While in `0.y.z` (alpha)** — any release MAY contain breaking changes.
Breaking changes are flagged under `### Changed (breaking)` in
[CHANGELOG.md](https://github.com/antspriggs/nist-agent-passport/blob/main/CHANGELOG.md). Adopters should pin a specific version
or version range (e.g. `nist-agent-passport>=0.1,<0.2`).

**Once `1.0.0` ships:**

- **Breaking changes** require a major-version bump (`1.x.y` → `2.0.0`).
- **Deprecations** are announced at least one minor version before
  removal — so a feature deprecated in `1.4.0` cannot be removed before
  `2.0.0`, and a feature deprecated in `1.4.0` will continue to work
  (with a `DeprecationWarning`) through every `1.x` release.
- **Security fixes** may ship as patch releases on supported versions
  without notice; see [SECURITY.md](https://github.com/antspriggs/nist-agent-passport/blob/main/SECURITY.md) for the supported-versions
  table.
- The CHANGELOG's `### Deprecated` section is the authoritative list of
  deprecated APIs and their planned removal versions.

Governance: see [GOVERNANCE.md](https://github.com/antspriggs/nist-agent-passport/blob/main/GOVERNANCE.md).
Candidate next steps: see [ROADMAP.md](https://github.com/antspriggs/nist-agent-passport/blob/main/ROADMAP.md).

## Development

```bash
pip install -e '.[dev]'

pytest                                     # full suite, hermetic
pytest --cov=nist_agent_passport --cov-report=term-missing
ruff check . && ruff format --check .
mypy                                       # --strict, covers src/ + tests/
```

The test suite is fully hermetic (the mock OIDC provider runs in-process on a random port) — no creds or network needed.

See [CLAUDE.md](https://github.com/antspriggs/nist-agent-passport/blob/main/CLAUDE.md) for the design context behind every decision in this codebase: the trust model, why each RFC is used, security guardrails, and the suggested order of work.

## License

Apache-2.0.
