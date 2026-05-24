# Security Policy

## Supported versions

Agent Passport is in alpha. Only `main` and the most recent tagged release
receive security updates. The project will document a longer-term support
policy when it reaches a stable 1.0.

| Version | Supported |
|---|---|
| `main` | ✅ |
| Latest tag | ✅ |
| Anything older | ❌ |

## Reporting a vulnerability

**Please report security issues privately**, not as a public GitHub issue.

The preferred channel is GitHub's private security advisory mechanism:

> **[Report a vulnerability →](https://github.com/antspriggs/nist-agent-passport/security/advisories/new)**

Use this form for anything affecting:

- Signature verification (forged, replayed, or malleable tokens that pass
  verification when they should not)
- Scope attenuation bypass (a child token granting more authority than its
  parent)
- IAL/AAL/FAL monotonicity bypass (a child claiming higher identity
  assurance than its parent)
- Chain-walking bypass (a verifier accepting a chain that shouldn't link)
- OIDC ID-token validation bypass (the validator accepting tokens it should
  reject)
- PKCE / state handling bugs in the login flow that could enable CSRF or
  code injection
- Secrets exfiltration (e.g. logging full tokens or signing keys)

If the GitHub form is unavailable, you can email the maintainer (see the
GitHub profile contact methods).

## What to include in your report

- A description of the vulnerability and its security impact.
- The smallest reproducer you can construct — ideally a failing test case
  against the current `main`.
- The version (commit hash or tag) you tested against.
- Whether the issue is already public anywhere.

## What to expect after reporting

| Stage | Target |
|---|---|
| Initial acknowledgement | within **3 business days** |
| Triage + severity assessment | within **7 business days** |
| Fix in `main` for high-severity issues | within **30 days** of confirmed report |
| Coordinated public disclosure | within **90 days** of report, unless mutually agreed otherwise |

The 90-day disclosure window aligns with
[Google Project Zero's standard](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html);
we will negotiate a longer window if a fix is genuinely in-flight and a
shorter window if the issue is being actively exploited.

## What is in scope

The Agent Passport library itself: anything inside `src/nist_agent_passport/`,
the CLI, the mock OIDC provider, and the example code.

## What is out of scope

- Bugs in upstream dependencies (`joserfc`, `httpx`, `pydantic`, `typer`).
  Report those to the upstream projects. We will pin a fixed version once
  upstream patches.
- Misconfiguration issues in a downstream deployment (e.g. using
  `allow_wildcard_scope=True` when you didn't mean to, or trusting a
  compromised CSP). Configuration is the operator's responsibility; we will
  improve documentation if a class of misconfiguration is consistently easy
  to make.
- Findings in CSPs themselves. Report those to the CSP.

## Cryptographic primitives

Agent Passport delegates all signature and JWS operations to
[`joserfc`](https://jose.authlib.org/en/) and uses only the asymmetric
algorithms `RS256`, `ES256`, and `EdDSA`. `alg: none` is rejected by the
`VerificationPolicy` constructor and again at JWS header parse, before any
JOSE-library call (defense in depth).

If you find a vulnerability in `joserfc`'s cryptographic implementation,
please report it to the joserfc maintainers; we will coordinate any
mitigations needed on our side.
