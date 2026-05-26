# How Agent Passport compares

This document is an honest map of the adjacent landscape — what else
exists, where each project fits, and when to reach for Agent Passport
vs. an alternative. The goal is to save you a research afternoon, not to
sell anything.

Snapshot date: **May 2026.** The landscape is moving fast; check the
source links if it's been more than a quarter since this was updated.

## Where Agent Passport uniquely fits

Agent Passport is the only project in the adjacent OSS landscape that:

1. **Propagates NIST SP 800-63-3 IAL/AAL/FAL through the delegation
   chain.** The CSP's `acr` is the source of truth at the root; child
   tokens inherit, never escalate. Downstream verifiers express policy
   in NIST's vocabulary (`require_ial=2`), not vendor-specific trust
   scores. This is the contract the [NCCOE Software and AI Agent
   Identity and Authorization](https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization)
   concept paper asks for under "Access Delegation" and "Logging &
   Transparency" — and no other project in this comparison implements
   it.
2. **Ships as a library, not a service.** No Postgres, no server to
   operate, no SaaS to sign up for. `pip install`, embed in your MCP
   middleware or LangChain tool wrapper, done. The tradeoff is that the
   issuer is in-process by default — if you want a centralized issuance
   service, you have to build it (the primitives are there).
3. **Stays standards-rooted and version-pinned.** RFC 7519 JWT, RFC 7515
   JWS, RFC 8693 token exchange with `act`-claim nesting, OIDC + PKCE,
   discovery-only CSP configuration. New claim names are namespaced
   under `https://agent-passport.org/claims/` so they can be aliased to
   whichever vocabulary the IETF / OpenID Foundation eventually
   standardizes.

If those three properties don't matter to your deployment, one of the
alternatives below probably fits better.

## Compared to [ZeroID](https://github.com/highflame-ai/zeroid)

ZeroID is the closest comparable OSS project: Apache-2.0, Python SDK,
RFC 8693 token exchange, `act`-claim delegation chains, scope attenuation,
explicit MCP middleware, active development from a commercial backer
(Highflame AI).

**Overlap (~80% of surface):**

| Capability | Agent Passport | ZeroID |
|---|---|---|
| OAuth 2.1 + PKCE + OIDC discovery | yes | yes |
| RFC 8693 token exchange | yes | yes |
| `act`-claim delegation chains | yes | yes |
| Scope attenuation | yes (issue + verify) | yes |
| Hermetic test story | mock OIDC provider | (different approach) |
| MCP middleware | example | first-class |
| Python SDK | yes | yes |

**Where Agent Passport is differentiated:**

- **NIST SP 800-63-3 IAL/AAL/FAL propagation.** ZeroID does not cite
  NIST 800-63 or RFC 8485; the `acr`-to-IAL mapping and chain-wise
  monotonicity check are unique here.
- **Library form factor.** ZeroID expects you to run the ZeroID server
  + Postgres (Docker or hosted). Agent Passport runs in-process.
- **Discovery-only CSP adapter.** Adding a new CSP is a configuration
  change (one `.well-known` URL), not code.

**Where ZeroID is ahead:**

- **DPoP / sender-constrained tokens** (RFC 9449) — shipping today.
- **RFC 9396 Rich Authorization Requests** — shipping today.
- **SSF / CAEP real-time revocation** — shipping today.
- **Dynamic Client Registration** (RFC 7591) — shipping today; on our
  roadmap.

**Which to pick:**

- **Choose ZeroID** if you want a centralized issuance service, need
  DPoP / SSF revocation today, or don't need NIST 800-63 IAL/AAL/FAL
  propagation.
- **Choose Agent Passport** if you need a drop-in Python library, want
  NIST-aligned identity assurance carried through the delegation chain,
  or are contributing to NCCOE/NIST work where the SP 800-63 vocabulary
  is load-bearing.
- **Use both** if the two roles in your architecture differ — ZeroID as
  the issuance service, Agent Passport's verifier as the in-process
  library inside an MCP middleware or tool wrapper. The wire format is
  compatible at the RFC 8693 layer; only the namespaced agent claims
  differ.

We've considered whether the right move is to contribute the IAL/AAL/FAL
extension upstream to ZeroID. That conversation is open
([roadmap note](ROADMAP.md#adjacent-open-source-projects)); if the
extension lands there, this comparison stops being useful.

## Compared to [SPIFFE / SPIRE](https://spiffe.io/)

SPIFFE is workload identity — it answers "what workload is this?"
cryptographically (SVIDs, attested). Agent Passport is delegation
identity — it answers "what authority did a user delegate to this
agent, and through what chain?"

The two layers compose:

- A SPIFFE SVID identifies the runtime executing the agent
  ("Pod X in cluster Y belonging to service A").
- An Agent Passport identifies the user-delegated authority
  ("User U authorized agent class C, model M, scope S, on behalf of
  task T, expiring in 15 min").

The NCCOE concept paper names both SPIFFE/SPIRE and OAuth/JWT in the
same paragraph. Agent Passport's roadmap includes accepting
`spiffe://trust-domain/path` URIs in the `agent_id` claim so the two
identifiers can join cleanly.

You wouldn't replace SPIFFE with Agent Passport, or vice versa.

## Other projects in the "agent-passport" namespace

The name "agent passport" is somewhat parallel-discovered. Worth knowing
about:

- **[aeoess/agent-passport-system](https://github.com/aeoess/agent-passport-system)**
  — Solo author (Tymofii Pidlisnyi) with an IETF individual draft
  ([`draft-pidlisnyi-aps-01`](https://datatracker.ietf.org/)). Apache-2.0,
  Ed25519 + RFC 8785 JCS, monotonic narrowing, cascade revoke, commerce
  hooks. Active. Different protocol substrate (not OAuth/OIDC-native).
- **[agentpassportai/agent-passport](https://github.com/agentpassportai/agent-passport)**
  — MIT + Commons Clause (restricts commercial use). Low activity (~21
  commits, 1 star). **The name "Agent Passport" is trademarked by this
  org**; this is a real consideration before doing any branding
  investment.
- **[cezexPL/agent-passport-standard](https://github.com/cezexPL/agent-passport-standard)**
  — Spec-stage; provenance + blockchain anchoring; custom wire format.

This project ([antspriggs/nist-agent-passport](https://github.com/antspriggs/nist-agent-passport))
is the OIDC + RFC 8693 + NIST SP 800-63 implementation. If the trademark
question surfaces, the [package rename to `agent-passport`](ROADMAP.md#package-rename-nist-agent-passport--agent-passport)
already on the roadmap can incorporate a name change.

## Commercial NHI / Agent IAM platforms

This is not the same category — it's worth saying so explicitly so you
don't try to pick between them.

[Aembit](https://aembit.io/), [Astrix](https://astrix.security/),
[Oasis](https://www.oasis.security/), [Token.security](https://token.security/),
[Entro](https://entro.security/), [Natoma](https://natoma.id/),
[Silverfort](https://www.silverfort.com/) — all commercial, all
proprietary, all selling to security teams as a control plane (discovery,
governance, threat detection, hosted policy UI). The Forrester Wave Q2
2026 named Microsoft (Entra Agent ID) and Okta (Cross App Access) as
Leaders; the specialists are consolidating fast (Cisco-Astrix
acquisition, Silverfort-Fabrix acquisition, Oasis Series B).

**What they ship that this library deliberately does not:**

- NHI discovery / scanning of cloud accounts and SaaS apps
- Threat detection ML for agent behavior
- Hosted policy consoles and audit dashboards
- Secret vaulting / per-request credential brokering
- Vendor-specific integrations (Copilot, Bedrock, Vertex, Salesforce
  Agentforce)
- Compliance dashboards and audit-report generators

**What this library ships that they don't:**

- A published, versioned wire format with a reference verifier
- Standards-only chain semantics (RFC 8693 `act` nesting) instead of
  proprietary "lineage" graphs
- NIST SP 800-63-3 IAL/AAL/FAL propagation
- An `Apache-2.0`-licensed Python `pip install` you embed

If you're buying a control plane for a security team, look at the
commercial NHI vendors. If you're a framework author or runtime
maintainer who needs an identity primitive to embed, look here.

## When to reach for which

- **MCP server author** — Agent Passport (today, with the
  `mcp_middleware.py` example) or ZeroID (more turnkey if you want a
  service).
- **LangChain / agent-framework tool author** — Agent Passport, embedded
  in your tool wrapper (see `examples/langchain_tool_wrapper.py`).
- **Centralized issuance for a fleet of agents** — ZeroID, or Agent
  Passport's issuer module wrapped in an HTTP layer you operate.
- **Federal/government agent identity proof-of-concept** — Agent
  Passport. The NIST SP 800-63 framing is the differentiator.
- **Agentic-commerce payment authorization** — neither, today; the
  [Agentic commerce claims roadmap item](ROADMAP.md#agentic-commerce-claims)
  is the path forward, mirroring AP2/ACP field names.
- **Workload identity for the runtime executing the agent** — SPIFFE.
- **Discovery, governance, policy console for a security team** —
  commercial NHI vendor.

## Corrections welcome

If you maintain one of the projects above and this writeup gets your
project wrong, please [open an issue](https://github.com/antspriggs/nist-agent-passport/issues)
or PR. Comparison docs go stale fast; concrete corrections beat
opinionated guesses.
