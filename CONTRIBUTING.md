# Contributing to Agent Passport

Thanks for considering a contribution. This is a small, focused security
library; contributions are most welcome when they improve test coverage,
adapter coverage for new CSPs, or compliance with the standards in
[CLAUDE.md](./CLAUDE.md). Larger refactors should start with an issue so we
can agree on direction before code review.

## Quick setup

Requires Python 3.11+.

```bash
git clone https://github.com/antspriggs/nist-agent-passport.git
cd nist-agent-passport
pip install -e '.[dev]'
```

## Running the checks locally (the same set CI runs)

```bash
ruff check .                      # lint
ruff format --check .             # format
mypy                              # --strict on src/ + tests/
pytest                            # hermetic test suite
pytest --cov=nist_agent_passport       # with coverage
```

All four must pass before opening a PR. CI runs the same set across Python
3.11, 3.12, and 3.13.

## Filing an issue

- **Security vulnerability** — do NOT file a public issue. Follow
  [SECURITY.md](./SECURITY.md) to report privately via GitHub Security
  Advisories.
- **Bug** — open a GitHub issue with: what you ran, what happened, what you
  expected, and the smallest reproducer you can create. If it involves a
  specific CSP, include the (sanitized) discovery doc URL and `acr` value.
- **Feature request** — open an issue describing the use case before writing
  code. The library deliberately keeps a small surface; not every feature
  request will be accepted, but every request gets a response.

## Pull requests

### Branching

- Branch off `main`.
- Use a descriptive branch name (`fix/`, `feature/`, `docs/`, `ci/` prefix
  is helpful but not required).

### What we look for in review

1. **Tests for every changed code path.** The test suite is hermetic (mock
   OIDC provider runs in-process) so adding tests is cheap. Coverage floor
   is 80%; we currently sit above that and would like to stay there.
2. **`mypy --strict` clean.** No `# type: ignore` without a comment
   explaining why the type-checker can't see it.
3. **Security-relevant changes get extra scrutiny** — anything touching
   signature verification, scope attenuation, IAL/AAL/FAL propagation, or
   chain walking will be reviewed against the standards cited in CLAUDE.md
   before merge.
4. **Public-API changes need a CHANGELOG entry** under `[Unreleased]`,
   formatted per [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
   Breaking changes go under `### Changed (breaking)`.
5. **No vendor-specific code in the core library.** CSP-specific behavior
   (ACR mappings, scope semantics) lives behind the `AcrMapping` /
   `OIDCClient` seams. The core stays generic OIDC + PKCE.

### Merging

The `main` branch is protected: PRs are required, CI must be green on the
3.11/3.12/3.13 matrix, the branch must be up to date, and conversations
must be resolved before merge. Merges use squash or rebase only (linear
history is required) — no merge commits.

The maintainer (currently @antspriggs) is the only one who can merge.
External contributors should expect feedback rather than direct push access.

## Developer Certificate of Origin (DCO)

By contributing, you certify the contents of the
[Developer Certificate of Origin 1.1](https://developercertificate.org/) for
each commit. Add a sign-off line to every commit:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <your-email@example.com>` trailer
which states you wrote (or have the right to submit) the code under the
project's Apache-2.0 license. We do not use a separate CLA.

## Standards baseline

Agent Passport composes existing standards rather than inventing new ones.
Before proposing a new claim, signature scheme, or protocol behavior:

1. Read [CLAUDE.md](./CLAUDE.md)'s "Standards baseline" section.
2. Check whether an existing RFC or NIST document covers the case.
3. If introducing a new namespaced claim, it must be under
   `https://agent-passport.org/claims/` and documented in the claim model.

The project is a deliberate contribution to the
[NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative);
deviations from NIST 800-63-3 or RFC 8693 vocabulary will be rejected
without strong justification.

## Code style

`ruff format` is the source of truth. If `ruff format --check` passes, the
style is correct by definition.
