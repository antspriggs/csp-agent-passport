# Governance

This document describes how decisions are made for `nist-agent-passport`.
It is small on purpose: the project is small, has one maintainer, and
deliberately keeps a narrow surface area.

## Decision-making model: BDFL

The project is governed as a [BDFL](https://en.wikipedia.org/wiki/Benevolent_dictator_for_life)
("benevolent dictator for life") with **[@antspriggs](https://github.com/antspriggs)
as the current BDFL** and sole maintainer (see [MAINTAINERS.md](./MAINTAINERS.md)).

All technical decisions — what to merge, what to reject, what to deprecate,
what version to tag, what RFC interpretation to follow when the spec is
ambiguous — rest with the BDFL.

This model is appropriate **today** because:
- The project is small (one maintainer, narrow scope).
- Decisions favor consistency with the standards baseline (NIST 800-63-3,
  RFC 8693, OIDC + PKCE) over novel design — there's a fixed reference to
  appeal to, not a design space to explore.
- Speed of decision matters more than consensus while the API is alpha.

It will not stay appropriate forever. See "Evolution" below.

## How decisions get made

1. **Routine changes** (bug fixes, doc updates, additional test coverage,
   adding a new CSP-specific `AcrMapping` upstream) — open a PR following
   [CONTRIBUTING.md](./CONTRIBUTING.md). Review criteria are documented
   there. The BDFL decides merge.

2. **Public-API changes** — open an issue first describing the proposal,
   the use case, and the alternatives considered. The BDFL responds with
   a yes/no/let's-iterate. PR follows.

3. **Standards-baseline changes** — anything that deviates from the
   documented standards (e.g. introducing a new namespaced claim,
   changing the wire format, supporting a new algorithm) goes through
   a written justification. The bar is high: "what does the relevant
   RFC / NIST document say, and why is the deviation necessary?"

4. **Security-sensitive changes** — anything touching signature
   verification, scope attenuation, IAL/AAL/FAL propagation, chain
   walking, or PKCE handling gets extra review against the threat model
   in [CLAUDE.md](./CLAUDE.md). The BDFL may delay-and-consult on these
   before merging.

5. **Disputes** — open an issue. Public discussion. The BDFL decides.
   If the BDFL is the disputed party, see "Removing or replacing the
   BDFL" below.

## What's deliberately NOT in scope for the BDFL

Even a BDFL doesn't get to:
- Relicense the project unilaterally (Apache-2.0 contributions can only
  be re-licensed via a formal CLA process the project doesn't have)
- Privately disclose to selected parties only — security disclosure
  follows [SECURITY.md](./SECURITY.md)
- Add code that no committer has actually written under the project's
  DCO sign-off (see [CONTRIBUTING.md](./CONTRIBUTING.md))

## Evolution

This model is intended to evolve with the project:

- **Today** (small, one maintainer): BDFL.
- **When a second active maintainer appears**: BDFL + co-maintainer; the
  BDFL still breaks ties but consensus is expected on most changes.
- **When the project has 3+ active maintainers**: move to a small
  technical steering committee with rotating chair. The BDFL becomes an
  emeritus role.
- **If the project becomes a NIST AI Agent Standards Initiative
  reference implementation**: governance will be re-evaluated in
  alignment with whatever process the initiative requires.

A change in governance model is itself a governance-level change and
requires a written proposal, public comment period (≥14 days), and
documentation in this file.

## Removing or replacing the BDFL

If the BDFL is unresponsive, has abandoned the project, or has acted in
bad faith, contributors can:

1. Open an issue documenting the concern with evidence.
2. If unresolved after 30 days, fork the project. Apache-2.0 explicitly
   permits this; it's the OSS escape valve.

This is intentionally lightweight. The project is small enough that
forking is the right escalation if leadership fails.

## Versioning and deprecation

See [README.md](./README.md#versioning--deprecation-policy).
