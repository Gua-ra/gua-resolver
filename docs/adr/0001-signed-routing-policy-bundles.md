# ADR 0001: Signed Routing Policy Bundles

Date: 2026-07-03

## Status

Accepted for incremental implementation.

## Context

Before this change, resolver trust was centered on the signed homeserver roster. Routing behavior came from
two places:

- claim predicates embedded in roster entries,
- Java placement rules.

That made the roster carry both membership and routing authority. It also made fallback routing partly
opaque because one rule used runtime randomness.

## Decision

Introduce a separate signed routing-policy bundle:

- `RoutingPolicyBundle`
- `DelegationZone`
- `RoutingPolicyRule`
- `CanonicalRoutingPolicy`
- `RoutingPolicySigner`
- `RoutingPolicyVerifier`
- `RoutingPolicyValidator`
- `RoutingPolicySource`
- `FileRoutingPolicySource`

The routing policy is canonicalized and Ed25519-signed independently of the running resolver. A resolver
may serve and execute a policy only after signature and validation checks pass. Policy validation checks
that every target homeserver is active in the signed roster and that every rule is bounded by an explicit
delegation zone.

## Consequences

Positive:

- Policy can be mirrored independently of a resolver node.
- Delegated authority is explicit and auditable.
- Routing changes no longer require code changes for every institution/carrier.
- Clients and homeservers can eventually verify policy artifacts offline.

Negative:

- Operators now manage another artifact lifecycle.
- Policy and roster versioning must be coordinated.
- Until client verifiers exist, resolver nodes still perform most verification on behalf of clients.

## Rollout

The new model is guarded by `gua.resolver.policy.enabled`. Existing roster claims and fallback placement
continue to work when policy is disabled.
