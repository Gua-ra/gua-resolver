# ADM-003: Private identifier lookup

> **Status: Proposed, not frozen.** It closes when independent cryptography and distributed-systems reviewers answer Q1 to Q9 in writing and spikes P1 to P5 pass.

## Context

ADM-001 fixed the shape and left the construction open.

- L14 locks a stable logical PRF key with proactive threshold-share refresh. It chooses no construction; S1 marks the construction CRYPTO REVIEW REQUIRED.
- L15 forbids raw phone numbers and email addresses in replicated federation state.
- L16 forbids `/resolve` from being a cheap unrestricted enumeration oracle. No control may assume an account session.
- O4 preserves the fork between plain RFC 9497 and an updatable construction, to close before implementation.
- S1 asks whether threshold OPRF with proactive refresh is sound and verifiable. S4 asks which enumeration controls work.

Facts on `main` [CODE]. Directory rows and the checkpoint use HMAC-SHA256 over `"phone:" || E.164`, keyed by a pepper shared with identity-service. Anyone holding both inverts them offline (L15). L16's interim per-client, global and ingress rate limits are live. `/resolve` still answers `exists` for a raw E.164.

## Scope

In: the routing-key function and its evaluators, rotation and re-keying, client verification, and production gates.

Out: wire encoding (O2), the authenticated dictionary (O1), `k` per identifier type (O3), pinning rules (O10). Address-book contact discovery needs its own record.

## Requirements

1. Replicated state holds routing keys, never raw identifiers or pepper-keyed hashes (L15).
2. Deriving a routing key needs an online evaluation the evaluator meters without learning the input (L16; 10⁹ to 10¹⁰ candidates per plan, L15).
3. Routine operator or share rotation leaves every routing key unchanged (L14).
4. Once a second evaluator trust domain exists, no single party holds the logical key (L14, standing rule).
5. The client learns the evaluation key from the pinned chain, not the evaluator (L10, appendix).
6. All clients see one public key per generation, so the evaluator cannot partition them (L12).
7. Generations only move forward; clients refuse rollback (S1).
8. Per-identifier uniqueness holds across a generation change (L14; rationale R1, attack A2).
9. Emergency re-keying uses only parties already holding the identifier: the account's client or an accredited verifier (L7).
10. The construction runs in Java, Swift and Kotlin against published test vectors (product fact: Java resolver, native clients).

## Options considered

**A. RFC 9497 VOPRF, single evaluator.** [LIT] VOPRF mode proves evaluation with a DLEQ proof against one server key. A meets 1, 2, 5, 6, 7 and 10. It fails 4, and meets 3 only by never rotating. `Finalize` hashes the raw input, so outputs cannot be re-keyed without it (O4).

**B. Threshold 2HashDH evaluation yielding the RFC 9497 output.** [LIT] In 2HashTDH (Jarecki, Kiayias, Krawczyk, Xu, "TOPPSS", ACNS 2017) Lagrange-combining the per-share partials yields the single-key evaluation. Proactive refresh (Herzberg et al., CRYPTO 1995) and dynamic committees (Maram et al., "CHURP", CCS 2019) change shares without changing the secret. B keeps A's output and adds 3. It adds 4 only for a key born from a distributed key generation, because resharing preserves whatever the dealer knew. Verifiability under refresh is the gap Baecker et al. address, "A Fully-Adaptive Threshold Partially-Oblivious PRF" (CRYPTO 2025, ePrint 2025/1433). Emergency re-keying keeps A's limitation.

**C. Updatable, Pythia-style.** [LIT] Pythia (Everspaugh et al., USENIX Security 2015) outputs a pairing target-group element, updatable in bulk by a token Δ = k′/k. C satisfies 9 with no party holding identifiers. In Gua every replica and witness must apply Δ, so Δ is effectively public. An attacker with the compromised k then computes k′ = Δ·k. Pythia needs pairings, has no RFC, and fails 10.

**D. HSM-held pepper behind an HMAC service.** The service sees every raw identifier, failing 2. Rejected.

**Limits shared by all options.** The log is append-only, and full-replay witnesses need routing keys to recompute state (L11). Compromising a generation's key exposes every identifier bound under it to anyone holding the log. Rotation protects future state only (Decision 5).

## Decision or narrowed choice

1. **Output.** Routing key = RFC 9497 VOPRF-mode output over `identifierType || canonical identifier`. P1 picks the ristretto255-SHA512 or P256-SHA256 suite.
2. **Evaluation.** Option B, output byte-identical to A. n = 1 is a declared degenerate stage while one operator exists. Resharing from n = 1 to t-of-n preserves every routing key, satisfying 3. It does not satisfy 4. The founding operator therefore holds the logical key unless an unverifiable erasure is trusted. Meeting 4 needs a DKG-born key, which is a new generation and fails 3. Requirements 3 and 4 conflict at the n = 1 stage. Q4 decides which gives way.
3. **O4 narrowed to non-updatable.** C is rejected on the Δ argument, subject to Q7.
4. **Routine rotation.** Proactive refresh keeps the logical key, its public key and every routing key. New share public keys enter the log as governance-signed sequenced inputs (L11).
5. **Emergency re-keying.** Governance signs g+1, freezes new bindings under g, and the evaluator serves both for a stated window. Each g+1 re-binding carries verifier attestations over (rk_g, rk_g+1) satisfying `IdentifierProofPolicy` (L8). The sequencer rejects a g+1 binding whose rk_g is bound to another account. The evaluator holds no link table, but the append-only log becomes one. A holder of k_g inverts rk_g offline and reads rk_g+1 beside it. Every re-bound identifier therefore stays linkable under g+1. Only identifiers first bound after re-keying gain protection. Bindings not re-bound by close stop resolving; accounts survive and re-verify (L3).
6. **Client verification.** The client takes the public key, share keys, threshold and generation from a checkpoint chained to pinned `FederationGenesis` (L10). It verifies the proof against those keys and refuses a generation below its pinned one. It then checks its routing key against `stateRoot` (O1) and caches it per generation.
7. **Metering.** Replicated state lets anyone test a routing key locally, so the evaluator is the only metering point (L16).


## Blockers for production

Expert questions:

- Q1. Is t-of-n 2HashTDH evaluation, fed into RFC 9497 VOPRF-mode `Finalize`, a secure VOPRF under the RFC's assumptions?
- Q2. Do per-share DLEQ proofs against committed share keys, plus a client check that their Lagrange combination equals the public key, suffice against t−1 malicious evaluators? Or is a joint proof required?
- Q3. Does dynamic-committee refresh composed with 2HashTDH preserve obliviousness and verifiability against a mobile adversary? Does the CRYPTO 2025 construction map onto the RFC 9497 output?
- Q4. Is a GJKR DKG (Gennaro, Jarecki, Krawczyk, Rabin, EUROCRYPT 1999) required for the first t-of-n generation, given that a single dealer's key survives resharing?
- Q5. We propose each checkpoint commit (public key, share public keys, t, generation, previous-generation hash). Does that stop rollback to a compromised generation and per-client key partitioning? RFC 9576 frames key consistency. These five fields are an addition to ADM-005 decision 4's checkpoint body.
- Q6. Is verifier-attested linking of (rk_g, rk_g+1) sound for per-identifier uniqueness? Does publishing the pair let a holder of k_g link each re-bound identifier's g+1 records?
- Q7. Confirm or refute: a bulk-update token applied by public replicas, combined with the compromised old key, yields the new key.
- Q8 (distributed systems). We propose 2-of-3 evaluators across at least two trust domains, with `/resolve` failing closed below t and no single-key fallback (L8). Does that keep lookup available at target rates?
- Q9. We propose L16's live limits plus session-free anonymous rate-limit tokens (RFC 9576), given the national-scale crawls of deployed contact-discovery limits (Hagen et al., NDSS 2021). Do those bound online evaluation to the P5 threshold, with the residual stated per unit of attacker cost (S4)?

Spikes:

- P1. Performance. Pass: at least 2,000 evaluations per second per core with proof generation. Client blind, verify and finalize under 20 ms p95 on the oldest supported devices.
- P2. Conformance. Pass: Java, Swift and Kotlin match every RFC 9497 test vector for the chosen suite.
- P3. Threshold equivalence. Pass: a 2-of-3 dev deployment matches single-key output on 10⁶ inputs, and always detects and excludes a wrong partial.
- P4. Rotation drill. Pass: after refresh replacing one member, stored routing keys verify unchanged and old shares fail to combine. In a generation drill, no checkpoint shows two ACTIVE bindings for one identifier, and clients refuse a rolled-back generation.
- P5. Enumeration. Pass: the measured cost to test 10⁶ candidate numbers exceeds a threshold that product and security set before the spike.

## Implementation implications

- **Services.** The evaluator is its own process with its own key custody. The resolver and sequencer never hold shares. identity-service drops the pepper once bindings carry routing keys.
- **Data.** Binding records carry `(generation, routingKey)`. Existing HMAC rows are never inverted. identity-service, the first accredited verifier (Phase 5), recomputes routing keys for numbers it verifies.
- **Order.** A spike prototype runs in dev to execute P1 to P4. No evaluator or VOPRF client code ships in a client build until Q1 to Q5 are answered in writing. Phase 6 shadow mode covers chain verification, not VOPRF. Phase 8 production waits for Q1 to Q9 and P1 to P5. No pepper-keyed record replicates to a second operator.
- **Tests.** Platform test vectors, negative tests (bad proofs, stale generations, share mismatch), and a cross-generation uniqueness test.
- **Rollback.** Before a second operator replicates state, fall back to the read-only HMAC directory. Afterwards the only lever is freezing new bindings.

## Relationship to ADM-001

Touches L14 (shape implemented, construction unfrozen), L15, L16, O4 (narrowed, not closed), S1 and S4 (questions added, nothing answered), O1 and Phase 8. RFC 9497 is cited only for single-server evaluation. No locked decision is reopened.
