# ADR 0002: Deterministic Placement And Decision Traces

Date: 2026-07-03

## Status

Accepted and implemented.

## Context

The resolver README described placement as deterministic, but `WeightedFallbackRule` used
`ThreadLocalRandom`. That meant two resolver nodes could answer differently for the same new user context
and roster snapshot.

The API also returned only the homeserver reference. Operators had no safe way to ask "why did this route
happen?" without reproducing code paths manually.

## Decision

Replace random fallback with stable hashing over:

- placement context,
- roster version,
- candidate homeserver ids,
- candidate weights.

Introduce `PlacementDecision` and `PlacementEngine.decideWithTrace`. Add opt-in `/resolve` request field
`trace: true`, returning rule, rule id, reason, policy id/version, delegation zone, assignment policy, and
homeserver id.

## Consequences

Positive:

- Multiple resolver instances can produce reproducible answers.
- Auditors can inspect route decisions.
- Debug trace stays off by default for privacy and compatibility.

Negative:

- Stable hashing is less adaptive than per-request randomness.
- Large shifts in roster version or weights can move fallback placement for not-yet-created accounts.

## Compatibility

Legacy clients still send `{"phone": "..."}`. The `trace` response field is omitted unless requested.
