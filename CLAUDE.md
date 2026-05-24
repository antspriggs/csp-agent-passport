# Agent Passport

> Verifiable, identity-rooted delegation tokens for AI agents — built on existing standards (OIDC, OAuth 2.0 Token Exchange, JWT, NIST SP 800-63 Vectors of Trust).

This file is project context for Claude Code. Read it first; it captures decisions already made so you don't re-litigate them and so the implementation stays aligned with NIST's AI Agent Standards Initiative.

---

## Mission

When a user tells an AI agent "do X on my behalf," there is currently no standard, verifiable way for downstream tools, MCP servers, or other agents to know:

1. **Who** the principal is (and how strongly that identity was proofed),
2. **What** authority the agent was actually granted,
3. **For how long** the grant is valid,
4. **What chain** of delegation got us here (user → agent A → agent B → tool C).

Most agent frameworks paper over this with bare API keys. Agent Passport closes the gap by issuing short-lived, scope-bound, NIST-identity-rooted delegation tokens that downstream verifiers can check cryptographically.

This project is a deliberate, concrete contribution to the **Agent Identity & Authorization** pillar of the [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative) and the related [NCCOE Software and AI Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization) project.

---

## Audience and primary deliverable

- **Audience:** developers building AI agent frameworks (LangChain, LlamaIndex, AutoGen, MCP runtimes) who need a drop-in identity/authorization primitive.
- **Primary deliverable:** an open-source Python library (`nist-agent-passport`) plus a CLI demo and a small set of `examples/`.
- **Explicitly not in scope (for v0):** a hosted dashboard, a TypeScript SDK, key rotation infrastructure, a production-grade key store. These are deferred until the primitives are right.

---

## Standards baseline

Build on these. Do not invent new crypto, new claim names that duplicate existing ones, or a new identity assurance vocabulary.

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519) — token format.
- [RFC 7515 — JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515) — signing.
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) — the model for exchanging an OIDC ID token for a delegation token. The `act` claim ([§4.1](https://datatracker.ietf.org/doc/html/rfc8693#section-4.1)) is the standard way to express "agent acting on behalf of user."
- [RFC 8485 — Vectors of Trust](https://datatracker.ietf.org/doc/html/rfc8485) — `vot`/`vtm`/`vtr` for expressing identity assurance in OIDC. Use these where the CSP supports them; otherwise carry the CSP's `acr` value forward.
- [NIST SP 800-63-3 — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/) — defines IAL (Identity Assurance Level), AAL (Authenticator Assurance Level), FAL (Federation Assurance Level). The whole point of this project is to propagate these levels into the agent's delegation token.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) — the user-authentication step.

If a need arises that an existing RFC covers, use the RFC. New claim names are a last resort and must be namespaced (e.g., `https://agent-passport.org/claims/agent_id`).

### CSP configuration: well-known discovery only

CSPs are configured by their **issuer URL** (or by an explicit discovery URL when the CSP doesn't follow the default path). The OIDC client adapter MUST resolve every other endpoint — `jwks_uri`, `token_endpoint`, `authorization_endpoint`, `userinfo_endpoint`, supported algorithms, supported `acr` values — by fetching the discovery document at `<issuer>/.well-known/openid-configuration` ([OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html); [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) for the analogous OAuth case at `/.well-known/oauth-authorization-server`).

Consequences:
- `.env.example` has one URL per CSP, not five.
- Adding a new CSP is a configuration change, not a code change. Any OIDC + PKCE provider works.
- CSP endpoint changes (a token URL moving, a key rotation in JWKS) are picked up automatically; the adapter re-fetches discovery and JWKS on `kid` miss.
- Tests for the adapter verify it consumes discovery metadata; they MUST fail if the adapter ever hardcodes an endpoint URL.
- Cache discovery for a short TTL (default 5 minutes) and JWKS by `kid` (refresh on miss). Never cache without an invalidation path.

---

## Architecture

Three components, in one package:

```
                                        ┌──────────────────────┐
                  OIDC ID token         │                      │
   ┌──────────┐  (with acr=ial2)        │   Token Issuer       │
   │   CSP    ├────────────────────────▶│   (RFC 8693 token    │
   └──────────┘                         │    exchange)         │
                                        │                      │
                                        └──────────┬───────────┘
                                                   │
                                                   │ short-lived
                                                   │ delegation JWT
                                                   ▼
   ┌─────────────────────────────────────────────────────────────┐
   │   Agent runtime (LangChain / MCP client / custom)           │
   │                                                             │
   │   Carries the delegation JWT on every outbound tool call.   │
   │   When sub-delegating to another agent, mints a child       │
   │   token via the issuer with parent_jti set.                 │
   └─────────────────────────────────────────────────────────────┘
                                                   │
                                                   │
                                                   ▼
                                        ┌──────────────────────┐
                                        │   Token Verifier     │
                                        │                      │
                                        │   Used by MCP        │
                                        │   servers, tool      │
                                        │   APIs, sub-agents.  │
                                        │                      │
                                        │   Checks signature,  │
                                        │   expiry, scope,     │
                                        │   chain, IAL policy. │
                                        └──────────────────────┘
```

**Issuer**: takes a CSP-issued OIDC ID token, validates it, mints a short-lived delegation JWT layering the agent-acting claims on top. Also handles child-token minting for sub-delegation.

**Verifier**: a library and a CLI that any downstream service can use to validate a delegation token. Returns either a structured `VerifiedPassport` object (principal, agent, scope, chain, IAL/AAL) or a typed error.

**OIDC client adapter**: knows how to talk to a CSP via OIDC + PKCE (and to a hermetic mock provider for tests). Maps the CSP's `acr` values into the canonical IAL/AAL/FAL representation Agent Passport uses internally.

### Key management (v0)

The issuer holds a single signing keypair. v0 ships the simplest viable story:

- An RSA-2048 (or Ed25519) keypair is generated at issuer startup if no key is configured, or loaded from a path supplied via env var (`AGENT_PASSPORT_SIGNING_KEY`).
- The corresponding public key is published as JWKS at `<issuer>/.well-known/jwks.json`. The `kid` is the SHA-256 thumbprint of the JWK (RFC 7638).
- Verifiers fetch JWKS over HTTPS, cache by `kid`, and refresh on `kid` miss. Cache TTL defaults to 1 hour.
- **Key rotation, multi-key sets, hardware-backed storage, and HSM integration are explicitly deferred.** The `keys.py` module is structured so a future `KeyStore` interface can be substituted without touching `issuer.py` or `verifier.py`.

The verifier's `KeyStore` is an injected dependency, not a global. Tests pass an in-memory store; the CLI defaults to fetching from the configured issuer URL.

---

## Token claim model

A delegation JWT carries:

**Standard JWT claims (RFC 7519):**
- `iss` — the Agent Passport issuer URL.
- `sub` — pairwise subject identifier from the upstream CSP. Never the user's email or government ID. Most CSPs issue `sub` per relying party (not per relying-party-plus-agent), so two delegation tokens minted for the same user but different agents will share `sub`. Use `jti` + `agent_id` to distinguish sessions in audit logs.
- `aud` — the verifier audience. **One audience = one server.** For an MCP server with many tools, `aud` identifies the *server* (e.g., `https://mcp.example.com/`); the specific tools the agent may invoke are expressed via `tool_scope`. `aud` is a single string in v0, not an array; verifiers do exact-match. Cross-server delegation requires minting a separate token per audience.
- `iat`, `exp`, `nbf` — short lifetime; default 15 minutes for top-level, 5 minutes for sub-delegated.
- `jti` — unique token ID. Carried into children as `parent_jti` and used as the audit-log correlation key. v0 has **no revocation endpoint** — short TTLs are the sole defense against compromised tokens. RFC 7662 introspection is on the roadmap; until then, `ttl` is your blast-radius knob.

**Identity assurance (RFC 8485 + NIST SP 800-63-3) — all optional:**
- `acr` — pass through the upstream CSP's `acr` value verbatim (e.g., `http://idmanagement.gov/ns/assurance/ial/2`). **Optional**: OIDC's `acr` is itself optional, and many CSPs / deployments use scope-driven auth without asserting identity assurance. When absent, this claim is omitted from the JWT.
- `ial`, `aal`, `fal` — canonical numeric levels (1, 2, or 3) that the verifier can compare against policy. Derived from `acr`. **All optional**: when the upstream `acr` is absent, these are too. A `VerificationPolicy` with `require_ial=0` (the default) accepts tokens with no IAL claim — scope-driven auth is the supported default. A verifier that needs identity assurance sets `require_ial=1`/`2`/`3`, in which case the token MUST carry at least that level (a Passport with no `ial` is rejected).

**Delegation (RFC 8693 §4.1):**
- `act` — an object describing the agent acting on the principal's behalf. Per RFC 8693, may itself contain a nested `act` for chains.

**Agent-specific (namespaced):**
- `https://agent-passport.org/claims/agent_id` — stable identifier for the agent instance.
- `https://agent-passport.org/claims/agent_model` — e.g., `claude-opus-4-7`, `gpt-5`.
- `https://agent-passport.org/claims/tool_scope` — explicit allowlist of tool/endpoint patterns. Strings, matched with Python `fnmatch` semantics (`*` matches within a path segment, no `**` recursion, case-sensitive). Pattern syntax is fixed; no regex, no URI templates. **Empty array = no authority.**
- `https://agent-passport.org/claims/task_purpose` — short human-readable string explaining intent ("book a flight from SFO to JFK on Tuesday"). **Audit-only in v0.** Surfaced to verifiers and written to logs, but the verifier MUST NOT make access-control decisions on it. All policy enforcement goes through `tool_scope`. Treating natural-language intent as a security boundary is a footgun; if a future version wants policy on intent, it will use a structured claim, not free text.
- `https://agent-passport.org/claims/parent_jti` — `jti` of the parent token in a delegation chain. Absent on root tokens.

**Scope attenuation rule**: a child token's `tool_scope` MUST be a subset of its parent's. The issuer enforces this when minting children. The verifier re-checks at validation time when walking chains.

---

## CSP integration

CSP credentials live in a `.env` file at the project root, loaded at runtime via `python-dotenv`. `.env` is in `.gitignore`; `.env.example` ships placeholder values. **Do not paste credentials into chat or commit them.**

Agent Passport speaks generic OIDC + PKCE — any provider works. There are no CSP-specific adapters in the codebase: configuration is discovery-driven, the `acr` → IAL/AAL/FAL translation is one pluggable function, and the public API mentions no vendor names. Agent Passport speaks IAL/AAL/FAL only — no LOA terminology in any user-facing surface; the few legacy IAF `…/loa/N` URIs that some providers still emit are absorbed by the default mapping and never enter the rest of the system.

**Required env vars:**
```
CSP_CLIENT_ID=...
CSP_CLIENT_SECRET=...
CSP_REDIRECT_URI=http://localhost:8765/callback
CSP_DISCOVERY_URL=https://your-csp.example.com/.well-known/openid-configuration
CSP_SCOPES="openid ..."                          # space-separated per OIDC; verify exact scope names from your CSP's docs
CSP_ACR_MAPPING=ial                              # ial (default) | pkg.module:func_name
```

**ACR mapping (`acr` → `AssuranceLevels`):** implemented as `ial_acr_mapping` in `src/nist_agent_passport/oidc/base.py`. Single function + a translation table — read it in one screen, audit it in two minutes. Handles:
- The canonical NIST 800-63-3 `http://idmanagement.gov/ns/assurance/ial/N` URIs (for N in 1–3).
- The legacy IAF `…/loa/1` and `…/loa/3` URIs some CSPs still emit, translated conservatively: `…/loa/3` → IAL-2 (documents proofed + MFA), **not** IAL-3 (which requires in-person supervised proofing). A downstream verifier with `require_ial=3` therefore correctly rejects legacy LOA-3 tokens.

When a CSP emits ACR URIs outside this set, write your own `AcrMapping` function and point `CSP_ACR_MAPPING` at it (e.g. `CSP_ACR_MAPPING=mypackage.csp:my_mapping`). Do not edit the built-in translations in place — every other deployment depends on those defaults staying conservative.

---

## Mock OIDC provider

A small in-process OIDC provider that issues realistic ID tokens with proper VoT/`acr` claims. Its only job is to make the test suite hermetic so contributors don't need real CSP credentials to run tests. It is **not** a security boundary, **not** a quickstart for end users (the README's quickstart targets a real CSP), and **not** shipped as a public-facing component.

Lives in `tests/fixtures/mock_oidc/`. Uses an ephemeral RSA keypair generated at test-suite startup. Publishes a JWKS endpoint on a random localhost port so the issuer can validate tokens against it normally.

**Onramp split:** the README quickstart targets a real CSP — adopters need to see the real flow. The mock provider is the *contributor* onramp: a fresh checkout runs the full test suite end-to-end with no external creds via the mock. Anyone touching the library should be able to make changes and run `pytest` without applying for any CSP sandbox account first.

---

## CLI surface

```
nist-agent-passport login                 # runs the OIDC dance against the configured CSP, stores ID token locally
nist-agent-passport issue                 # mints a delegation token from the stored ID token
    --agent-id <id>
    --agent-model <model>
    --tool-scope <pattern>           # repeatable
    --task-purpose <string>
    --aud <audience>
    --ttl <seconds>                  # default 900
nist-agent-passport verify <token>        # validates signature/expiry/scope; prints VerifiedPassport
    --require-ial <n>
    --require-aal <n>
    --aud <audience>
    --required-scope <pattern>
nist-agent-passport inspect <token>       # decodes and pretty-prints all claims, including the chain
nist-agent-passport delegate <token>      # mints a child token; --tool-scope must be a subset
    --agent-id <id>
    --tool-scope <pattern>
    --ttl <seconds>                  # default 300
```

The CLI is the primary demo surface. README quickstart should walk through `login` → `issue` → `inspect` → `verify` end-to-end.

---

## Examples

`examples/` ships with:

1. **`mcp_middleware.py`** — wraps an MCP server so it requires an Agent Passport on connect. Each tool registers a required scope; the middleware rejects calls whose token doesn't cover the scope.
2. **`langchain_tool_wrapper.py`** — a `Tool` subclass (or equivalent for the current LangChain API) that validates the passport before calling the wrapped tool.
3. **`multi_agent_chain.py`** — end-to-end demo: user authenticates via mock provider, mints a token with broad scope, delegates a narrower token to agent A, which delegates a still-narrower token to agent B, which calls a tool. Verifier walks the chain and prints the full delegation tree.

Examples should be runnable standalone, with comments that explain the standards being applied.

---

## Project layout

```
nist-agent-passport/
├── pyproject.toml
├── README.md                  # public-facing: rationale, quickstart, NIST refs
├── CLAUDE.md                  # this file
├── .env.example
├── .gitignore                 # excludes .env, *.pem, dist/, etc.
├── src/
│   └── nist_agent_passport/
│       ├── __init__.py
│       ├── claims.py          # Pydantic models for the token claim schema
│       ├── issuer.py          # token-exchange logic
│       ├── verifier.py        # signature, scope, chain, IAL policy
│       ├── policy.py          # IAL/AAL policy types
│       ├── keys.py            # JWK loading, JWKS publishing
│       ├── oidc/
│       │   ├── __init__.py
│       │   ├── base.py        # OIDCClient + AcrMapping + ial_acr_mapping
│       │   └── validator.py   # IDTokenValidator (discovery + JWKS)
│       └── cli.py             # Typer-based CLI
├── examples/
│   ├── mcp_middleware.py
│   ├── langchain_tool_wrapper.py
│   └── multi_agent_chain.py
└── tests/
    ├── fixtures/
    │   └── mock_oidc/         # in-process mock CSP
    ├── test_claims.py
    ├── test_issuer.py
    ├── test_verifier.py
    ├── test_oidc_validator.py
    └── test_chain_attenuation.py
```

---

## Build commands

```bash
# install (editable, with dev extras)
pip install -e '.[dev]'

# run tests
pytest

# run tests with coverage
pytest --cov=nist_agent_passport --cov-report=term-missing

# lint and format
ruff check .
ruff format .

# type check
mypy src/

# run the CLI from source
python -m nist_agent_passport --help
```

Use Python 3.11+. Use Pydantic v2. Use `joserfc` for JWT/JOSE handling (single dependency, JWS + JWK + JWT in one place; ships `py.typed`; the modern successor to `authlib.jose`, written by the same author — do not pull in `authlib` or `pyjwt`). Use `httpx` for HTTP. Use `Typer` for the CLI (better ergonomics than Click for typed commands).

Pydantic v2 + `mypy --strict` mostly works but its plugin occasionally needs help on generic models and discriminated unions. A narrow `# type: ignore[...]` with a specific error code is acceptable on Pydantic model definitions when the alternative is restructuring the schema for the type checker; do not blanket-ignore an entire file.

---

## Coding conventions

- **Type-annotate everything.** `mypy --strict` should pass on `src/`.
- **Pydantic models for all claim shapes.** Validation at the boundary, dataclasses inside.
- **Errors are typed.** Custom exception hierarchy rooted at `AgentPassportError`. Verification failures distinguish `InvalidSignature`, `Expired`, `ScopeViolation`, `IALInsufficient`, `ChainBroken`, etc. — verifier callers should be able to make policy decisions on the error type.
- **No global state.** Issuer and verifier are classes you instantiate with config (key material, allowed audiences, policy).
- **Tests first for the verifier.** It's the security-critical component; every error path should have a test.
- **Time is injected.** Pass a `now: Callable[[], datetime]` into the verifier so tests can pin time without monkey-patching.
- **Logs are structured.** Use `structlog` or stdlib `logging` with extras; never log token contents at INFO level (only `jti`).

---

## Security guardrails

- **Never log a full token at INFO or above.** Log `jti`, `sub`, `agent_id`, `iss`, `aud`. The full token is a bearer credential.
- **Never accept `alg: none`.** Reject any JWS with no signature. Pin allowed algorithms to `RS256`, `ES256`, `EdDSA`.
- **Verify `iss` and `aud` strictly.** Allowlist of issuers, exact-match on audience.
- **Enforce `exp` and `nbf` with a small clock-skew tolerance.** Configurable per `Verifier` instance via a `clock_skew: timedelta` constructor arg; default 30 seconds, hard ceiling 120 seconds (the constructor rejects larger values). Different deployments need different tolerances; do not bake the default into call sites.
- **Scope attenuation is enforced at issuance AND at verification.** Defense in depth.
- **The CSP's `acr` is the source of truth for IAL.** Do not let a downstream agent claim a higher IAL than the root token — verifier checks that the chain's IAL is monotonically non-increasing. The issuer sets `ial`/`aal`/`fal` on the root token from the CSP's `acr`; child tokens **inherit** these values from the parent and cannot raise them. The delegating agent has no input here — there is no API for "delegate at a lower IAL," because `ial` describes how the *principal* was proofed, not the agent's confidence in the delegation. Worked example: root token has `ial=2`. Agent A mints a child for Agent B; the child carries `ial=2`. A verifier with policy `require-ial >= 3` rejects both. A verifier with `require-ial >= 2` accepts both. The chain-walk re-checks at each hop and rejects on the first violation.
- **Reject tokens whose `tool_scope` claims `*` unless the verifier's policy explicitly opts in.** The default-deny stance is part of the value prop.

---

## Suggested first task sequence for Claude Code

Work in this order; each step has a natural test gate:

1. **Scaffold the package** — `pyproject.toml`, `src/`, `tests/`, `.env.example`, `.gitignore`, basic README skeleton. Confirm `pip install -e '.[dev]'` and `pytest` (with no tests) pass.
2. **Write the claim model** — `claims.py` with Pydantic models for `Passport`, `ActClaim`, `AgentClaims`. Round-trip tests (Passport → JWT → Passport).
3. **Implement the verifier first, before the issuer** — write the verifier against hand-crafted test JWTs. This nails down the security contract before there's any temptation to make the issuer "just work" with the verifier's bugs. The verifier consumes already-canonical `ial`/`aal`/`fal` integers from the token; it does **not** know about CSP-specific `acr` URIs. The `acr` → canonical mapping is the adapter's job (step 8), performed at issuance time. This keeps the verifier independent of any specific CSP and lets step 3 proceed without the adapter existing yet.
4. **Stand up the mock OIDC provider** — pytest fixture that boots an in-process provider on a random port with an ephemeral RSA keypair.
5. **Implement the issuer** — RFC 8693 token exchange against the mock provider. Test the whole loop: ID token in → delegation token out → verifier accepts.
6. **Implement chain delegation** — child-token minting, scope attenuation enforcement, chain walking on verify.
7. **Build the CLI** — Typer-based, thin wrappers over the library.
8. **CSP-agnostic ACR mapping** — `ial_acr_mapping` handles both canonical NIST 800-63-3 URIs and the legacy IAF `…/loa/1`/`…/loa/3` URIs some CSPs still emit. Test against the mock provider with realistic `acr` values; CSPs emitting other URI shapes plug in a custom `AcrMapping` via `CSP_ACR_MAPPING=pkg.module:func`.
9. **Examples** — write the three example files. Each one should run from a clean checkout.
10. **README** — public-facing quickstart targeting a real CSP; rationale; NIST/RFC references; pointer to CLAUDE.md for design context.
11. **Polish** — ruff, mypy, coverage. Ship.

---

## What to do if something feels wrong

If you hit a design question this doc doesn't answer, default to:
1. **What do the relevant RFCs say?** Read them; don't guess.
2. **What does the NIST SP 800-63-3 vocabulary call this?** Use that name.
3. **What's the most restrictive interpretation?** This is a security library; default-deny.
4. **Would a security reviewer raise an eyebrow?** If yes, restructure.

If a question is genuinely undecidable from those, leave a clearly-marked `# DESIGN NOTE:` comment and surface it in the PR description rather than silently picking.

---

## References

- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [NCCOE — Software and AI Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization)
- [NIST SP 800-63-3 — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [RFC 7519 — JWT](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 — JWS](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [RFC 8485 — Vectors of Trust](https://datatracker.ietf.org/doc/html/rfc8485)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8252 — OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)
