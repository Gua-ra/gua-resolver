# ADM-005: Federation state replication, witnesses and ordering

> **Status: Proposed, not frozen.** It closes when the Blockers questions are answered, spikes S2, S7 and S8 pass, S3 resolves, and a second operator's witness co-signs a production checkpoint.

## Context

L10 roots witness identities in `FederationGenesis` through `WitnessRegistry`. L11 and L12 apply as written: assertion checkpoints, two witness classes, sequenced inputs with time, five properties, intersecting quorums, two BFT triggers.

ADM-001 left O1, O7, O10 and O12 open. S2 and S3 lack pass criteria.


## Scope

In: replication model, checkpoint and dissent structure, quorum rule, time policy, replica bootstrap, BFT trigger, O1.

Out: O2 encodings; O10's key-chain-change rule; S1; O13; recovery.

## Requirements

1. Every accepted or rejected input is logged as full canonical bytes (L11).
2. Transitions read only sequenced inputs, deterministic and versioned (L11).
3. One checkpoint commits both roots at one size (L11).
4. A log-only co-signature never reads as a state attestation (L11).
5. Disagreement yields checkable signed dissent (L11).
6. Witness identities verify from genesis before counting (L10).
7. Any two acceptable quorums share an honest trust domain (L12, L8).
8. Replicas hold no counted key (O12).
9. Clients verify non-membership (O1; `exists=false` is unsigned today).
10. Sequenced time is monotonic; replay reads no local clock (L11).
11. No cheaply invertible identifier reaches an external operator (L15).
12. Nothing is claimed before a second operator holds witness keys (O7).

## Options considered

**Replication model.**
- A. Distinguished sequencer plus witnesses. Meets 1 to 8. CT is a single-sequencer log checked by monitors (RFC 6962, RFC 9162); witness co-signing is Syta et al. (IEEE S&P 2016) and C2SP `tlog-witness`.
- B. BFT now. One Byzantine orderer with liveness needs four independent domains (Castro and Liskov, OSDI 1999). Gua has one. BFT ordering alone adds no integrity.

**Witness scope.** C2SP `tlog-witness` co-signs after a consistency proof, without replay, comparing only root hashes at equal sizes. A replay class therefore needs its own signed header to meet 4.

**Time.** Local clocks fail 10; witness-median time needs consensus. Sequencer-stamped `seqTime` meets 10.

**Authenticated dictionary (O1).** Each candidate is a log-backed map whose root enters every checkpoint, as draft-ietf-keytrans-protocol does. Trillian's map mode is deprecated, with no maintained Java implementation; facebook/akd (Rust) is nearest.
- D1. Sparse Merkle tree over 256-bit keys, the CONIKS prefix-tree family (Dahlberg, Pulls, Peeters, NordSec 2016; Melara et al., USENIX Security 2015). Non-membership discloses no other key. Compressed proofs run near 0.9 KB at 2 × 10^8 keys.
- D2. Sorted-neighbour indexed Merkle tree, R2's withdrawn lock. Non-membership discloses two neighbouring keys. No peer-reviewed treatment found (unverified).

## Decision or narrowed choice

**Proposed now, gated by the blockers below.**

1. **Model.** One distinguished sequencer, Gua's `AUTHORITY` resolver. Witnesses are `WitnessRegistry` identities with class `LOG` or `REPLAY` and a trust domain. Those in the sequencer's domain count zero. Class and trust domain are governance-attested at admission, never self-asserted (L8, L10; ADM-004 D3 applies the same rule).
2. **Entries.** `(index, seqTime, type, canonicalInput, inputSignatures, outcome)`, rejections included. A governance-signed `RULES` entry changes `transitionVersion`. After Phase 2, a governance-signed `STATE_GENESIS` entry carries full registry state, and the hash-only prefix stays unreplayed. Break `STATE_GENESIS` contents by: the governance threshold.
3. **State.** `stateRoot` hashes fixed sub-roots: four L10 registries, bindings, placements.
4. **Checkpoint.** Origin, size, `logRoot`, `stateRoot`, last `seqTime`, `transitionVersion`, sequencer signature, C2SP framing (O2). A stock witness would co-sign two bodies at one size differing only in `stateRoot`. Gua `LOG` witnesses therefore refuse a second body at a size they already co-signed. Their cosignatures count only toward equivocation resistance (L11's two-class sentence, L12 row 2), never toward L11's admissibility rule. `REPLAY` witnesses sign a separate header after full L11 replay. Clients reject `REPLAY` signatures from `LOG`-accredited witnesses.
5. **Dissent.** Origin, witness, class, kind, last agreed checkpoint, disputed body hash, first bad index, evidence. `EQUIVOCATION` is self-proving only as two sequencer-signed bodies of one size that differ; different sizes need the full log. `INVALID_ENTRY` is self-proving only for state-free checks: canonical encoding, and signatures under keys the entry carries. Accreditation, policy and uniqueness checks need proofs against the previous `stateRoot`, raising `STATE_MISMATCH`, which replay checks. The sequencer logs published dissent. Clock skew is never dissent; the witness withholds. Self-proving dissent halts clients above the last agreed size until governance resolves it.
6. **Quorum rule.** The baseline `WitnessPolicy` in `PolicyRegistry` sets domains `W`, tolerance `f`, threshold `q` with `2q - |W| >= f + 1`, `REPLAY` count `r`, and maximum age `A`. Any two quorums share `f + 1` domains, one honest (Malkhi and Reiter, Distributed Computing 1998). A client `WitnessRequirement` may only require named domains already in `W`, raise `q` or `r`, or lower `A`. Every client quorum is then a baseline quorum. Witness-set changes need old and new quorums jointly (Ongaro and Ousterhout, USENIX ATC 2014).
7. **First step.** One external domain, `q = 1`, `f = 0`. Equivocation breaks with the sequencer plus that operator.
8. **Pinning (O10, checkpoint part).** Clients pin the last accepted checkpoint per federation, not per account, advancing only by consistency proof and quorum.
9. **Time policy.** `seqTime` is non-decreasing, and every expiry, freshness and delay rule reads it. A `TICK` entry lands at least every 60 seconds. `TICK` and full-entry logging move the log size continuously, so the L6 [CODE] fallback seed must stop reading roster version. ADM-008's PT1H interval no longer bounds that churn. Witnesses co-sign only within 120 seconds of their own clock. Skew per window endpoint is bounded by checkpoint interval plus 120 seconds. Placement-record validity windows read `seqTime` once placements enter `stateRoot`; ADM-008's own-clock admission holds only before that.
10. **Censorship evidence.** Accepted inputs get signed inclusion promises with a maximum merge delay, as RFC 6962 SCTs do. An unmet promise proves censorship.
11. **Replica bootstrap (O12).** Obtain genesis out of band, comparing fingerprints over two channels. Verify governance transitions and `WitnessRegistry` before any checkpoint. Replay from `STATE_GENESIS`, or accept a snapshot whose recomputed root matches a checkpoint carrying `r` `REPLAY` signatures, then replay to head. On a fork, freeze and relay evidence.
12. **BFT trigger.** L12's two triggers stand as written. Governance-signed `SEQUENCER_CHANGE`, which fixes any handover size, is the interim response to a failing sequencer, not a substitute. The live candidate is a time-critical input, such as recovery cancellation, blockable inside its window.
13. **O1 narrowed to D1**, keyed by `H(tag || type || routingKey)`. `tag` is a domain-separation tag, not a trust domain. `routingKey` is L15's blinded key, the Phase 8 output, never a raw identifier. D2 is the fallback if D1 fails S2.

**Stays open.** Who runs the second witness (S5). External `REPLAY` of bindings waits for Phase 8: re-keying rewrites every binding, and today's HMAC is invertible by pepper holders (L15). Replicas run by another operator wait for Phase 8.

## Blockers for production

Cryptography reviewer:
- C1. Does domain separation of leaf, internal and empty-subtree hashes prevent second-preimage and cross-key reuse?
- C2. Are checkpoint, cosignature, promise and dissent signatures separated so none verifies in another role or federation?
- C3. Under ADM-003's proposed construction (S1 unanswered), does a `REPLAY` witness holding binding inputs and the full dictionary learn anything beyond pseudorandom routing keys, and does that weaken L16?
- C4. Can a proof against a stale sub-root pair with a fresh `stateRoot`?

Distributed-systems reviewer:
- D1. Is `2q - |W| >= f + 1` by domain sufficient when clients pin different sizes?
- D2. Is joint-quorum overlap until every client with age at most `A` has pinned past the change size sufficient?
- D3. With one external domain, should clients fail closed when its witness exceeds `A`?
- D4. Does the skew bound constrain manipulation of L13 windows and `HostingAcceptance` expiry?
- D5. Are promises sufficient evidence for time-critical inputs, or is that class the L12 trigger?
- D6. Must `REPLAY` witnesses run an independent transition implementation, since shared bugs yield consistent wrong roots?
- D7. Is snapshot bootstrap weaker than full replay beyond trusting `REPLAY` witnesses?
- D8. Can a client verify every halting dissent kind with proofs against the last agreed checkpoint alone?

Spikes. Unmeasured target: 2 × 10^8 keys, 100 writes per second.
- S2. Pass: proofs at most 2 KB combined; verification at most 10 ms on 2021 mid-range phones; 500 updates per second.
- S3. Pass: an 8 vCPU witness replays the target within 24 hours, holds within 60 seconds of head at five times the write rate, and closes a 24-hour gap within 2 hours. Fail: the external party stays `LOG`, integrity unclaimed.
- S7. Fork the sequencer toward two client groups. Pass: `LOG` witnesses refuse the second body, `REPLAY` witnesses dissent within one interval, clients and replicas freeze.
- S8. Skew `seqTime` past 120 seconds. Pass: every witness withholds.

## Implementation implications

Services: the `AUTHORITY` resolver becomes the sequencer. A witness service runs `LOG`, enforcing one body per size, or `REPLAY`. Replica mode replaces `MIRROR`.

Data: `transparency_log` gains entry bytes and `seq_time`. New tables hold checkpoints, cosignatures, promises, dissents, dictionary nodes. `directory_entry` stays outside `stateRoot`, labelled unwitnessed.

Order: full-entry logging; `STATE_GENESIS` after Phase 2; `stateRoot`; a same-operator `LOG` witness claiming nothing (O7); Phase 6 shadow checks; external `LOG`; external `REPLAY` and replicas after S3 and Phase 8; enforcement after decision 8's pinning rule; O10's key-chain-change rule stays open and does not gate it.

Tests: cross-implementation root equality; S7 and S8 in CI; snapshot bootstrap equals full replay. Rollback: every step is additive, enforcement a flag.

## Relationship to ADM-001

Touched: L10, L11, L12 applied; O1 narrowed; O7 answered narrowly; O10 pinning only; O12 procedure; S2 and S3 criteria; Phase 9 sequenced. Nothing locked is reopened.
