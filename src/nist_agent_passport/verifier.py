"""Agent Passport token verifier.

Security-critical. Implemented before the issuer (per CLAUDE.md step 3) so the
verification contract is nailed down without bending it to the issuer's bugs.

Flow for a leaf token:
  1. Parse the JWS header explicitly. Reject `alg: none`, unknown algs, and
     headers missing `kid` *before* invoking the JOSE library.
  2. Resolve the public key via the injected `KeyStore`.
  3. Verify the JWS signature with `joserfc`, restricted to the policy's
     allowed-algorithm set (defense in depth — joserfc also checks alg).
  4. Decode the payload into a `Passport` (Pydantic validation).
  5. Apply universal checks (iss allowlist, time window with clock skew).
  6. Apply leaf-only checks (audience, IAL/AAL/FAL floors, wildcard, scope).

For chained tokens (leaf has `parent_jti`), the caller passes the parent
chain root-first. Each parent gets the JWS + universal checks but skips
leaf-only checks (they were applied when each was the leaf of its own
verification). The chain walk then re-verifies attenuation, IAL/AAL/FAL
monotonicity, and `parent_jti` linkage — defense in depth against an issuer
that minted a child too broadly.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from itertools import pairwise

from joserfc import jwt as joserfc_jwt
from joserfc.errors import BadSignatureError, JoseError
from pydantic import ValidationError

from nist_agent_passport._clock import NowCallable, default_now
from nist_agent_passport._jose import parse_jws_header
from nist_agent_passport._scope import scope_attenuates, scope_covers_required
from nist_agent_passport.claims import Passport
from nist_agent_passport.errors import (
    AALInsufficient,
    AlgorithmNotAllowed,
    AudienceMismatch,
    ChainBroken,
    Expired,
    FALInsufficient,
    IALInsufficient,
    InvalidSignature,
    InvalidToken,
    MalformedClaims,
    NotYetValid,
    ScopeViolation,
    UntrustedIssuer,
    WildcardScopeNotAllowed,
)
from nist_agent_passport.keys import KeyStore
from nist_agent_passport.policy import VerificationPolicy


@dataclass(frozen=True)
class VerifiedPassport:
    """A `Passport` that has passed signature, time, and policy checks.

    Authorization decisions should consume `VerifiedPassport`, not raw `Passport`
    instances, so the type system distinguishes verified tokens from arbitrary
    payloads.

    `chain` is empty for root tokens. For a chained leaf, it holds the parent
    Passports root-first (matching the order the caller supplied them).
    """

    passport: Passport
    chain: tuple[Passport, ...] = field(default_factory=tuple)


class Verifier:
    """Verify Agent Passport tokens against a `VerificationPolicy`.

    Instantiate once per (policy, key store) pair and reuse. Thread-safe so
    long as the underlying `KeyStore` is.
    """

    def __init__(
        self,
        policy: VerificationPolicy,
        key_store: KeyStore,
        now: NowCallable = default_now,
    ) -> None:
        self._policy = policy
        self._key_store = key_store
        self._now = now
        self._allowed_algorithms = sorted(policy.allowed_algorithms)

    def verify(self, token: str, chain: Sequence[str] = ()) -> VerifiedPassport:
        """Verify a Passport, optionally with its parent chain.

        `chain` is the parent tokens, ordered root → immediate-parent (so
        `chain[-1]` is the leaf's direct parent, `chain[0]` is the chain root).
        Empty chain is required for root tokens; non-empty for tokens carrying
        `parent_jti`. Mismatch raises `ChainBroken`.
        """
        leaf = self._decode_and_check_signature(token)
        self._enforce_universal(leaf)
        self._enforce_leaf_only(leaf)

        parents: list[Passport] = []
        if leaf.agent.parent_jti is not None:
            if not chain:
                raise ChainBroken(
                    f"leaf jti={leaf.jti!r} has parent_jti={leaf.agent.parent_jti!r} "
                    "but no parent chain was provided"
                )
            for parent_token in chain:
                p = self._decode_and_check_signature(parent_token)
                self._enforce_universal(p)
                parents.append(p)
            self._enforce_chain_attenuation(leaf, parents)
        elif chain:
            raise ChainBroken("leaf is a root token (no parent_jti) but a chain was provided")

        return VerifiedPassport(passport=leaf, chain=tuple(parents))

    # ----- internals --------------------------------------------------- #

    def _decode_and_check_signature(self, token: str) -> Passport:
        """Header check, key resolution, signature verification, claim decode."""
        header = parse_jws_header(token)

        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self._policy.allowed_algorithms:
            raise AlgorithmNotAllowed(
                alg if isinstance(alg, str) else None,
                self._policy.allowed_algorithms,
            )

        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise InvalidToken("JWS header missing 'kid'")

        key = self._key_store.get(kid)

        try:
            decoded = joserfc_jwt.decode(token, key, algorithms=self._allowed_algorithms)
        except BadSignatureError as e:
            raise InvalidSignature(str(e)) from e
        except JoseError as e:
            raise InvalidToken(f"JOSE decode failed: {e}") from e

        try:
            return Passport.from_jwt_claims(decoded.claims)
        except (ValidationError, KeyError, TypeError, ValueError) as e:
            raise MalformedClaims(str(e)) from e

    def _enforce_universal(self, p: Passport) -> None:
        """Checks that apply to every token in a chain."""
        policy = self._policy
        if p.iss not in policy.issuers:
            raise UntrustedIssuer(p.iss, policy.issuers)
        now = self._now()
        if now > p.exp + policy.clock_skew:
            raise Expired(p.exp, now)
        if now < p.nbf - policy.clock_skew:
            raise NotYetValid(p.nbf, now)

    def _enforce_leaf_only(self, p: Passport) -> None:
        """Checks that apply only to the leaf (audience, floors, scope policy).

        IAL/AAL/FAL are skipped when the policy's requirement is 0 (the default
        — scope-driven auth doesn't need identity assurance). When required >=1,
        the token MUST carry the claim AND meet the floor; a token with `None`
        is rejected.
        """
        policy = self._policy
        if p.aud != policy.audience:
            raise AudienceMismatch(policy.audience, p.aud)
        if policy.require_ial > 0 and (p.ial is None or p.ial < policy.require_ial):
            raise IALInsufficient(policy.require_ial, p.ial if p.ial is not None else 0)
        if policy.require_aal > 0 and (p.aal is None or p.aal < policy.require_aal):
            raise AALInsufficient(policy.require_aal, p.aal if p.aal is not None else 0)
        if policy.require_fal > 0 and (p.fal is None or p.fal < policy.require_fal):
            raise FALInsufficient(policy.require_fal, p.fal if p.fal is not None else 0)
        if not policy.allow_wildcard_scope and "*" in p.agent.tool_scope:
            raise WildcardScopeNotAllowed(
                "token claims '*' but policy does not opt in to wildcard scope"
            )
        if policy.required_scope is not None and not scope_covers_required(
            p.agent.tool_scope, policy.required_scope
        ):
            raise ScopeViolation(policy.required_scope, p.agent.tool_scope)

    def _enforce_chain_attenuation(self, leaf: Passport, parents: list[Passport]) -> None:
        """Walk leaf → immediate-parent → ... → root, checking each link.

        `parents` is ordered root-first, so the immediate parent of `leaf` is
        `parents[-1]` and the chain root is `parents[0]`.
        """
        # Top-down: leaf, then parents in reverse (immediate-parent first).
        chain_top_down = [leaf, *reversed(parents)]
        for child, parent in pairwise(chain_top_down):
            if child.agent.parent_jti != parent.jti:
                raise ChainBroken(
                    f"parent_jti mismatch: child {child.jti!r} claims parent "
                    f"{child.agent.parent_jti!r} but actual parent has "
                    f"jti {parent.jti!r}"
                )
            if not scope_attenuates(child.agent.tool_scope, parent.agent.tool_scope):
                raise ChainBroken(
                    f"scope attenuation violated: child {child.agent.tool_scope} "
                    f"is not a subset of parent {parent.agent.tool_scope}"
                )
            # IAL/AAL/FAL must be monotonic non-increasing. `None` values
            # ("not asserted") propagate forward only: a child cannot claim
            # an assurance level its parent doesn't have, because the agent
            # can't manufacture identity assurance the CSP didn't attest.
            for dim, c_val, p_val in (
                ("IAL", child.ial, parent.ial),
                ("AAL", child.aal, parent.aal),
                ("FAL", child.fal, parent.fal),
            ):
                if c_val is None:
                    continue  # child doesn't claim anything new — fine
                if p_val is None:
                    raise ChainBroken(
                        f"{dim} appeared in chain: child claims {c_val} "
                        "but parent does not assert it"
                    )
                if c_val > p_val:
                    raise ChainBroken(f"{dim} increased in chain: child={c_val}, parent={p_val}")
        if parents[0].agent.parent_jti is not None:
            raise ChainBroken(
                f"chain root has parent_jti={parents[0].agent.parent_jti!r}; "
                "root tokens must not claim a parent"
            )
