# Roadmap

This file is a list of **candidate** next steps, not commitments. Each entry
explains the value, the rough effort, and what's currently blocking it.
Discussion happens in GitHub issues; this file is the index.

Ordering is by my (the maintainer's) current sense of priority, not by
size. Priorities will shift as feedback arrives.

## Strategic

### Engage with the NIST AI Agent Standards Initiative

**Value:** the project's stated mission is to contribute to the [NIST AI
Agent Standards Initiative](https://www.nist.gov/caisi/ai-agent-standards-initiative)
(launched Feb 17, 2026 under CAISI) and the related [NCCOE Software and AI
Agent Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization)
project. We now have a real, runnable, NIST-grounded implementation —
this is the moment to engage.

**Current status (May 2026):**
- NCCOE concept paper public comment closed **April 2, 2026**. Authors:
  Harold Booth, Bill Fisher, **Ryan Galluzzo** (project lead; also leads
  NIST SP 800-63 program), Joshua Roberts.
- CAISI RFI on AI Agent Security (FR 2026-00206, docket NIST-2025-0035)
  closed **March 9, 2026**; ~937 comments received.
- No open public comment windows currently. Next likely openings: (a) a
  Federal Register Notice soliciting **collaborators** for the NCCOE
  demonstration project (NCCOE's standard pattern after a concept paper),
  (b) draft of the **AI Agent Interoperability Profile** expected Q4 2026
  from CAISI, which historically ships with a public comment period.

**Concrete actions, ordered by cost:**

1. **Write a 1-page brief** mapping every claim/check in this library to
   the specific NIST SP 800-63-3 / RFC 8693 / OIDC clauses it implements,
   plus the NCCOE concept paper's four focus areas (Identification &
   Authentication, Authorization, Access Delegation, Logging &
   Transparency). Material exists in [CLAUDE.md](https://github.com/antspriggs/nist-agent-passport/blob/main/CLAUDE.md);
   needs distillation for a non-implementer audience.
2. **Introductory email to `AI-Identity@nist.gov`** — the live mailbox
   for the NCCOE project team. Accepts unsolicited input between formal
   windows. Should follow [Package rename](#package-rename-nist-agent-passport--agent-passport)
   to avoid an awkward "your project is named after us" conversation.
3. **File a Letter of Interest** when the Federal Register Notice for
   NCCOE collaborators drops. Offer Agent Passport as a reference
   implementation of the "Authorization" and "Access Delegation" focus
   areas. NCCOE collaborator process and CRADA template documented at
   https://www.nccoe.nist.gov/get-involved/collaborate-us-technical-contributions.
4. **Submit a public comment** to the CAISI AI Agent Interoperability
   Profile draft when it ships in Q4 2026.
5. **Propose the namespaced claim schema** (`https://agent-passport.org/claims/`)
   for inclusion in whatever registry NIST or OpenID Foundation maintains
   for agent-identity claims.

**Status:** unblocked; needs maintainer time. Lower-commitment alternative
to the LOI path: join the [NCCOE Community of Interest](https://www.nccoe.nist.gov/get-involved)
for updates.

### Package rename: `nist-agent-passport` → `agent-passport`

**Value:** [NIST's published policy](https://www.nist.gov/open/license)
forbids implying NIST approves or endorses any product. A PyPI package
prefixed `nist-` from a non-NIST author crosses that line; NIST General
Counsel has historically asked projects to rename. There is no formal NIST
endorsement of this library — only genuine *alignment* with the NCCOE
concept paper, RFC 8693, and SP 800-63-3, which the README states
directly. Earlier rename (now, alpha) is cheaper than later (under
pressure, after broader adoption).

**Approach:**
- Rename package: `src/nist_agent_passport/` → `src/agent_passport/`.
- Rename PyPI distribution and CLI script: `nist-agent-passport` →
  `agent-passport`.
- Publish a transitional `nist-agent-passport` release that re-exports
  from `agent_passport` and emits a `DeprecationWarning`. Keep for one or
  two minor versions before sunsetting on PyPI.
- Update all README/docs/CLAUDE.md references, `[project.urls]` (current
  pyproject.toml points to the wrong GitHub org), CHANGELOG breaking
  entry, and the `pip install` line in the quickstart.
- Namespaced claim URI `https://agent-passport.org/claims/*` is already
  unprefixed — **no token-shape change**, fully wire-compatible across the
  rename.
- GitHub repository rename is a separate decision (URL stability matters
  for inbound links).

**Status:** designed; breaking; awaiting maintainer go/no-go.

### Standards alignment refinements

Three corrections to the project's stated standards baseline, surfaced by
the May 2026 IETF/OpenID landscape scan:

1. **Demote RFC 8485 (Vectors of Trust) from baseline to optional input.**
   Conspicuously absent from every active agent-identity draft (OpenID
   whitepaper, `draft-klrc-aiagent-auth`, AuthZEN, WIMSE WG). De facto
   vocabulary is OIDC `acr` + IDA `verified_claims`. The IAL/AAL/FAL
   numerics in our token stay canonical; nothing about the token shape
   changes. README and CLAUDE.md framing should reflect this.
2. **Plan for `agentic_ctx` field alignment.** Amazon's
   [`draft-araut-oauth-transaction-tokens-for-agents`](https://datatracker.ietf.org/doc/draft-araut-oauth-transaction-tokens-for-agents/)
   proposes an `agentic_ctx` claim (`current_actor`, `originator`,
   `chain_metadata`) that overlaps our `act` + `parent_jti` chain
   metadata. If it gains WG adoption, alias our field names so a Passport
   projects mechanically into `agentic_ctx`. Track quarterly.
3. **Add a hook for structured intent.** CLAUDE.md correctly flags
   free-text intent as a footgun and keeps `task_purpose` audit-only. The
   FIDO Agentic Authentication TWG and the proposed AUDIT BoF are both
   pushing toward structured intent claims. Plan an `intent_digest`
   companion (hash of approved intent string + optional URI pointer) so
   the audit trail is tamper-evident without becoming policy-bearing. See
   the [Agentic commerce claims](#agentic-commerce-claims) item below.

**Status:** items 1–2 are doc-only; item 3 is implementation work tracked
under Library features.

### Second-CSP validation

**Value:** the project is generic OIDC + PKCE, but only ID.me has been
exercised end-to-end against the live wire. A second CSP would either
confirm or surface portability bugs.

**Candidates** (in order of expected ease):
- **Login.gov sandbox** — the federal-government NIST-aligned CSP. Most
  natural fit; expected to emit canonical `…/ial/N` URIs that our
  default mapping already handles.
- **Auth0 free tier** — universally available; tests the `0` IAL path
  more thoroughly (Auth0 typically doesn't emit `acr` for username/
  password auth).
- **Keycloak self-hosted** — tests against an open-source CSP we can
  configure ourselves; valuable for the hermetic-integration story.

**Status:** unblocked; same shape as the ID.me integration we just did.

## Library features

### MCP authorization spec parity

**Value:** the [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
is short, opinionated, and built on a small set of IETF standards. To be
a drop-in MCP authorization implementation, three primitives are required
that we don't ship yet. Without them, no MCP client can discover or
fully use us.

**Pieces to implement:**

1. **RFC 9728 — OAuth 2.0 Protected Resource Metadata.** Helper that
   exposes `.well-known/oauth-protected-resource` for an MCP server,
   advertising the Agent Passport issuer as the authorization server.
   Required by MCP spec §2.3.1 / §2.3.2. Without this, MCP clients can't
   locate our issuer.
2. **RFC 7591 — OAuth 2.0 Dynamic Client Registration.** Endpoint on the
   issuer that lets agents register themselves at first use. Required for
   the long tail of agents that don't pre-register. MCP spec §2.4.
3. **RFC 8707 — Resource Indicators.** Accept `resource` parameter in the
   issuer's token-exchange call; mirror it into `aud`; the verifier
   already does exact-match. MCP spec §2.5.1. Small plumbing change;
   unlocks the spec-compliant flow.
4. **Promote `examples/mcp_middleware.py` to a first-class subpackage**
   that implements the full 401 → `WWW-Authenticate` → discovery →
   Bearer-validate handshake from spec §2.3. Currently a sketch.

**Status:** designed; medium effort total; each piece independently
shippable.

### Agentic commerce claims

**Value:** the openly-specified agent commerce protocols ([AP2](https://ap2-protocol.org/specification/),
[ACP](https://www.agenticcommerce.dev/), [Visa TAP](https://github.com/visa/trusted-agent-protocol),
Mastercard Verifiable Intent) all expect the same shape of constraints on
an agent-identity token: transaction caps, merchant binding, short
expiry, and RFC 7800 `cnf` for autonomous agents. Today `tool_scope`
expresses action-shaped authority but not value-shaped — adding
transaction-binding claims makes Agent Passport a credible identity
substrate for the commerce stack.

**Proposed claims** (all namespaced under `https://agent-passport.org/claims/`,
all optional, attenuation rule applies — children may tighten, never
loosen):

- `txn_constraints`: `{ max_amount_minor, currency, merchant_allowlist,
  mcc_allowlist, executions{max,frequency} }`. Field names mirror AP2 +
  Mastercard so a verifier can project to either mechanically.
- `cart_binding`: `{ checkout_hash, alg }`. Mirrors AP2's `checkout_hash`;
  one-shot-binds a Passport to a merchant-signed cart.
- `intent_digest`: `{ alg, value, uri }`. Hash of the human-approved
  intent string so `task_purpose` becomes tamper-evident without becoming
  policy-bearing.
- `txn_id`: UUID stamped at first use; mirrors AP2 `transaction_id` for
  dispute-evidence join.

Add `VerificationPolicy.require_txn_constraints=True` for verifiers in
the payment path. Keep `tool_scope` for non-payment authority; the new
claims are layered, not replacements.

**Status:** designed; medium effort.

### Proof-of-possession via RFC 7800 `cnf`

**Value:** the IETF WIMSE WG is moving firmly toward proof-of-possession
(WIT + WPT) rather than bearer tokens. AP2 already requires RFC 7800
`cnf` for autonomous mandates. Adding an optional `cnf` claim (JWK
thumbprint) lets a Passport bind to the agent's keypair so an
intercepted token can't be replayed by another holder. Bearer remains
valid for v0; this is the v1 hook.

**Status:** designed; small effort (additive claim, optional enforcement
via `VerificationPolicy.require_cnf`).

### SPIFFE-shaped `agent_id`

**Value:** the NCCOE concept paper names SPIFFE/SPIRE alongside OAuth.
NIST is signaling the agent-identification layer (who the agent *is*,
attested cryptographically) may be SPIFFE-based, with OAuth handling
delegation on top. Today `agent_id` is a free string; accepting a SPIFFE
ID URI shape (`spiffe://trust-domain/path`) keeps us forward-compatible
without committing to SPIFFE.

**Status:** unblocked; small; pure validation + docs change.

### Chain visualization in `inspect`

**Value:** the delegation chain (`act` + `parent_jti`) is already in the
token; `nist-agent-passport inspect --tree` would render it as a
human-readable tree (depth, agent_id per hop, IAL at each link, scope
delta from parent). Pure CLI sugar over existing data.

**Status:** unblocked; small.

### Token revocation (RFC 7662 introspection)

**Value:** today the only defense against a compromised token is its TTL
(default 15 min for root, 5 min for child). For high-assurance
deployments that need to invalidate a token immediately on detected
compromise, we need an introspection endpoint per [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)
and a revocation list the verifier can consult. ZeroID ships real-time
revocation today; this is the gap that most reduces the asymmetry.

**Design sketch:**
- Issuer maintains a revocation list keyed by `jti` (could be a Bloom
  filter for size, or a small DB).
- Verifier consults the revocation list on each verify, with a short
  cache TTL so revocations propagate in seconds not minutes.
- RFC 7662 `POST /introspect` endpoint on the issuer; takes a token,
  returns `active: true/false` + claim metadata.

**Status:** designed; significant implementation effort; flagged in
[CHANGELOG.md](https://github.com/antspriggs/nist-agent-passport/blob/main/CHANGELOG.md)
Known Limitations since v0.0.1.

### JWKS hosting and key rotation

**Value:** v0 ships a single-issuer single-key model. Real deployments
need to rotate signing keys without invalidating in-flight tokens (overlap
period with old + new keys both publishable), and to publish the JWKS
over HTTPS for verifiers to fetch on `kid` miss.

**Design sketch:**
- Issuer supports an ordered key list (newest first); signs with newest,
  verifies against any of them.
- JWKS endpoint at `<issuer>/.well-known/jwks.json` serves all currently-
  valid public keys.
- Rotation = add new key to the list (signs going forward), retire old
  key after max-token-TTL has elapsed.
- Verifier's `KeyStore` Protocol grows a JWKS-fetching implementation
  (today only the in-memory `InMemoryKeyStore` exists).

**Status:** designed; medium effort.

### Full browser-OAuth integration test

**Value:** the CLI's `login` (OAuth code + PKCE) is exercised via the
paste-in `--id-token` path in CI. The full browser dance is not — we
caught the CLI-default bug only because of the live ID.me integration.
Adding `/authorize` and `/token` endpoints to the mock OIDC provider
would let us test the full dance hermetically in CI on every PR.

**Effort:** ~half a day. The mock provider already implements discovery
+ JWKS; adding the OAuth endpoints is well-understood mechanical work.

**Status:** unblocked; small.

### CLI PII redaction in `inspect`

**Value:** the ID.me integration revealed that `nist-agent-passport
inspect` happily prints legal names, emails, residential addresses, etc.
when the ID token carries them. For a tool people will run in shared
terminals (or paste into shared chats), default-redact-with-opt-in is
the safer posture.

**Design sketch:**
- Default: redact OIDC's standard PII claims (`email`, `phone_number`,
  `address`, `name`, `family_name`, `given_name`, …) with `<redacted>`.
- `--show-pii` flag opts in to plaintext.
- Tests for both modes.

**Effort:** ~30 min.

**Status:** unblocked; small; flagged during the ID.me live test.

## Ecosystem alignment

### Watch list — drafts and specs to track

The agent-identity standards landscape is moving fast. These are the
specific documents and groups to monitor quarterly so the library can
adopt consensus claim names as they emerge rather than minting our own.

**IETF (oauth@ietf.org, wimse@ietf.org):**
- [`draft-klrc-aiagent-auth`](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/)
  (Kasselman/Lombardo/Rosomakho/Campbell) — "use existing standards"
  individual draft; no NIST 800-63 hook today.
- [`draft-araut-oauth-transaction-tokens-for-agents`](https://datatracker.ietf.org/doc/draft-araut-oauth-transaction-tokens-for-agents/)
  — Amazon's `agentic_ctx` proposal; closest competitor to our chain
  metadata encoding.
- [`draft-ietf-oauth-identity-chaining`](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-chaining-12)
  — WG-adopted; cross-domain delegation via RFC 8693 + RFC 7523.
- [`draft-ietf-wimse-arch`](https://datatracker.ietf.org/doc/draft-ietf-wimse-arch/)
  + WIMSE WIT/WPT drafts — proof-of-possession workload identity.
- AUDIT BoF (Agent Use of Delegation and Interaction Traceability),
  CATALIST BoF — proposed at IETF May 2026.

**OpenID Foundation:**
- [Identity Management for Agentic AI whitepaper](https://openid.net/wp-content/uploads/2025/10/Identity-Management-for-Agentic-AI.pdf)
  (AI Identity Management Community Group, Oct 2025).
- AuthZEN 1.0 (Final Jan 2026) — PEP↔PDP API; natural fit for
  verifier-side checks.

**Commerce-adjacent:**
- [AP2 spec](https://ap2-protocol.org/specification/) (Google + ~60
  partners) and [GitHub](https://github.com/google-agentic-commerce/AP2).
- [ACP spec](https://www.agenticcommerce.dev/) (Stripe + OpenAI + Meta).
- [Visa TAP](https://github.com/visa/trusted-agent-protocol).
- [Mastercard Verifiable Intent](https://www.mastercard.com/global/en/news-and-trends/stories/2026/verifiable-intent.html)
  — open-sourcing announced May 2026; repo not yet indexed.
- [`draft-meunier-web-bot-auth-architecture`](https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/)
  — Cloudflare → IETF; de facto agent-at-merchant transport identity.

**FIDO Alliance:**
- [Agentic Authentication TWG](https://fidoalliance.org/fido-alliance-to-develop-standards-for-trusted-ai-agent-interactions/)
  (Apr 2026; CVS/Google/OpenAI chairs).

### Adjacent open-source projects

Honest positioning context. See [COMPARISON.md](https://github.com/antspriggs/nist-agent-passport/blob/main/COMPARISON.md)
for the longer write-up.

- [ZeroID (highflame-ai/zeroid)](https://github.com/highflame-ai/zeroid)
  — closest comparable OSS project. Apache-2.0, ~139 stars (May 2026),
  RFC 8693 + `act` chains + scope attenuation, ships as a service. Does
  not propagate NIST 800-63 IAL/AAL/FAL. Worth a GitHub discussion
  proposing an identity-assurance extension; if they decline, that
  validates Agent Passport's distinct positioning.
- [SPIFFE/SPIRE](https://spiffe.io/) — workload identity; complementary,
  not competing. A Passport could ride inside a JWT-SVID as private
  claims.
- [`draft-klrc-aiagent-auth` authors](https://datatracker.ietf.org/doc/html/draft-klrc-aiagent-auth-00)
  (Defakto, AWS, Zscaler, Ping) — the individual draft doesn't address
  identity assurance. A focused contribution adding an IAL/AAL/FAL
  section sourced from NIST SP 800-63-3 would be a natural collaboration.

## Distribution

### Go and TypeScript SDKs

**Value:** multi-language coverage is table stakes for adoption in the
broader AI-agent ecosystem (most agent frameworks are split across
Python and TypeScript today). The other "agent passport" projects in
the namespace (cezexPL/agent-passport-standard, aeoess/agent-passport-system)
already offer multi-language SDKs; we should match.

**Approach:** keep this Python implementation as the reference; auto-
generate or hand-write Go + TypeScript bindings against the same claim
schema and verifier semantics. Test interop with cross-implementation
fixtures.

**Status:** stretch goal; significant effort; should not start until
the Python implementation hits 1.0 and the wire format is frozen.

## Mature → 1.0 prep (when we choose to commit)

The current 0.1.x line is alpha by SemVer convention. Reaching 1.0
requires:

1. **Wire-format freeze** — pin the claim schema; document any extension
   points that adopters can rely on not breaking.
2. **Deprecation discipline** — every breaking change after 1.0 needs at
   least one minor-version notice per the [Versioning policy](https://github.com/antspriggs/nist-agent-passport/blob/main/README.md#versioning--deprecation-policy).
3. **Adoption signal** — at least one external user / integration / test
   confirming the API is usable as documented.
4. **Security review** — an external reviewer (NIST/NCCOE, OpenID
   Foundation, an OSS-security org) walks the library against its
   threat model.

**Status:** premature to schedule. We get there by working through the
strategic + library items above and seeing what real-world feedback
arrives.

## How to contribute to any of these

Pick one, open an issue describing your intended approach, then a PR
per [CONTRIBUTING.md](https://github.com/antspriggs/nist-agent-passport/blob/main/CONTRIBUTING.md).
For larger items (revocation, JWKS hosting, second SDK), discuss in
the issue before writing code — the design space matters more than
the implementation.
