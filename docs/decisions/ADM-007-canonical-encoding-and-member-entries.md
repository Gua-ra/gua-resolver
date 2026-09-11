# ADM-007: Canonical encoding and self-signed member entries

> **Status: Accepted for implementation, 2026-09-11.** Scoped to O2 for roster, member and governance objects; revisable by implementation evidence under the same rule as ADM-001.

## Context

[ADM-001](ADM-001-identifier-binding-placement-trust.md) L4 locks one encoding rule as a security property: every signed object has exactly one canonical byte representation, decoders reject non-canonical encodings, and signatures cover those bytes. It does not choose the framing; that is **O2**, which also covers integer widths, Base32 prefixing and entropy lengths. L4 also records why the shipped `CanonicalRoster` must not be copied: it joins fields with a raw `0x1F` that is assumed rather than enforced to be absent from values, nests unescaped delimiters, and collapses null and empty to the same bytes.

L10 puts member, verifier and witness identities one layer below the registry roots, each self-signed, with governance able only to admit or revoke. Phase 1 of the [migration plan](../migrations/gua-resolver-migration-plan.md) is the first step of that: the authority alone can no longer rewrite a member's address or key. It was blocked on O2, because a self-signed entry cannot be built before the bytes it signs are decided.

This record decides the smallest set of questions that unblocks Phase 1, and nothing beyond it.

## Decision

1. **Encoding: `gua-lp.v1`.** A length-prefixed framing used by every signed object introduced from here on. A byte string is a `u32` big-endian length then the bytes; a string is the byte string of its exact UTF-8 bytes with no normalization, and invalid input is rejected rather than replaced; an int64 is 8 bytes big-endian two's complement, and timestamps are epoch milliseconds; a bool is one byte; an optional is a presence byte then the value, so absent and empty differ; a list is a `u32` count then its elements, and a set is that list sorted by unsigned UTF-8 byte order with duplicates rejected; an enum is its canonical name as a string. Every object starts with its schema tag as a string, then its fields in the documented order, none omitted. A signature covers all those bytes, and the object hash is SHA-256 over the same bytes, carried as lowercase hex. Transport stays JSON: verifiers re-derive the canonical bytes from the parsed fields, and the signed sub-object is parsed by a dedicated strict reader that rejects unknown fields, duplicate keys and trailing content, so a signature can never cover fewer fields than a consumer sees. Canonical JSON (RFC 8785) was rejected for its number and escaping corner cases and its weaker support on the client platforms. `CanonicalRoster`'s delimiter form is never reused.

2. **What a member signs.** `gua-member-entry.v1` covers id, serverName, baseUrl, masIssuer, alg, signingKey, keyId, sequence, notBefore, notAfter, region, searchVisibility and searchGroups. `weight`, `acceptsNew` and `claims` are placement and governance attributes and stay authority-signed until a governance-signed membership epoch carries them. An entry's maximum lifetime is 400 days.

3. **Rotation.** A member rotates by publishing the next entry, with a strictly higher sequence, naming the new key and signed by both the new and the previous key. A lost key has no self-signed path: the entry is revoked and the operator is admitted afresh, which is a new identity to clients.

4. **Log leaves.** A new leaf type `MEMBER_ATTEST` carries the SHA-256 of the member's canonical bytes. `ADMIT` and the status leaves are unchanged, so each admission that carries a member block now appends two leaves.

5. **Transition flag.** `gua.resolver.roster.require-member-signature`, default false. While it is false an unattested entry is served as today and counted; when it is true an ACTIVE entry without a valid member signature is excluded from `/roster`, from placement and from existing-account resolution.

6. **Admission retains the genesis key.** The possession-proven public key an applicant registers is kept as the anchor of its attestation chain instead of being proved once and never used again.

## Consequences

The authority can no longer silently rewrite a member's `baseUrl`, `masIssuer`, `signingKey` or search policy: any substitution invalidates the member signature, and the log commits to the accepted entry. That is one compromise term removed from the roster path, not independence: the same operator still runs the resolver, holds the only authority key and admits members, so the ADM-001 standing rule is unchanged.

`gua-roster.v1` bytes stay byte-identical, so mirrors and clients that verify the authority signature today keep verifying; the member block is additive JSON and absent from entries that have none.

The flag is a real cutover, not a feature toggle. Flipping it before every ACTIVE member is attested removes those members from resolution, which for a production homeserver means its returning users cannot log in. The deploy order is therefore fixed: ship with the flag false, attest, verify, then flip; the rollback is the flag, not a rollout.

Sequenced time is only partly addressed. The acceptance time recorded in the `MEMBER_ATTEST` leaf is the authoritative one, but the resolver still stamps leaves with its own clock and evaluates validity windows against it, so replay stays structurally impossible until log leaves carry payloads (ADM-001 L11).

Clients do not verify member signatures yet. Until they do, the guarantee holds against a resolver that rewrites its own database, and not against one that serves a client a roster it never logged.

## Phase 2 objects

> Added 2026-09-11, when Phase 2 implementation needed the field sets this record had deferred. Same scope rule: this fixes the bytes and the smallest custody decision that unblocks the phase, and nothing more.

7. **Four governance objects, all `gua-lp.v1`.** `gua-federation-genesis.v1` carries the schema tag, federationLabel, createdAt, hashSuite, threshold, the keys sorted by keyId (each keyId, alg, publicKey, operatorId) and the registry names as a set, which fixes the encoding and not the transport order: the canonical bytes sort them, so a JSON list carrying the four names in any order is the same object with the same `genesisId`, while a duplicate name is refused; `genesisId` is the SHA-256 of those bytes and the human fingerprint is its first 16 hex characters in groups of four. `gua-governance-transition.v1` carries genesisId, index, previousHash, issuedAt, newThreshold and newKeys. `gua-registry-epoch.v1` carries the registry name, genesisId, epoch, previousEpochHash (empty at epoch 1), issuedAt and contentHash, and serves all four registries. `gua-homeserver-registry-content.v1` carries the members sorted by homeserverId, each with status, memberEntryHash, weight, acceptsNew and its claim predicates. Signatures sit outside the canonical bytes in every case.

8. **Thresholds count operators.** Every governance key records an `operatorId`, and a governance threshold counts distinct operators, never key ids (ADM-001 L8). A threshold higher than the number of distinct operators is refused at load, because it can never be met honestly. The shipped `RosterVerifier` and `RoutingPolicyVerifier` keep their per-key counting for the operational roster snapshot and the policy envelope, and neither may be reused for a threshold that has to mean independence.

9. **Governance admits, it does not redefine.** An epoch commits to each member's `memberEntryHash`, the hash of the entry that member signed, not to the member's fields. And the resolver rebuilds the pending membership from its own state and refuses an epoch whose content hash is anything else. So the operational key proposes and governance ratifies or refuses: neither can change a served membership alone, which is narrower and more honest than "governance controls membership".

10. **Registry scope in v1.** The four registry names are fixed. Only `HomeserverRegistry` has a code path; `VerifierRegistry` and `WitnessRegistry` are shapes whose content must stay empty until Phase 5 and Phase 9. `PolicyRegistry` content is the existing `gua-routing-policy.v1` envelope verified under the genesis governance keys, not a separate epoch object. A PolicyRegistry epoch, which would bind `genesisId` into the bundle bytes and therefore mint a `gua-routing-policy.v2` tag, is deferred and must land before Phase 5 puts `IdentifierProofPolicy` in the same registry.

11. **Governance key custody, minimally (S5-min).** Governance private keys are generated and used only on an operator-controlled machine outside the cluster, stored encrypted at rest with an offline backup, and never placed in a Kubernetes Secret in any resolver namespace. Signing is a manual step with the offline tool. Dev and prod get separate keys and separate genesis objects. `k = 1` with one `operatorId` is what ships, and the documents say plainly that this separates processes and custody, not principals. Loss or compromise is handled by a new genesis and a client re-pin; no in-band recovery is claimed.

12. **Transition flag.** `gua.resolver.governance.required`, default false. While it is false, admission and status changes take effect directly, exactly as before. When it is true, an admission lands `PENDING`, a status change records intent only, and only a governance-signed membership epoch moves an entry to ACTIVE, SUSPENDED or REVOKED. A `PENDING` entry is not in the roster the authority signs and serves, so the status never reaches the wire, and the claim non-overlap gate counts it, which is what stops two homeservers claiming the same accounts from both waiting for the epoch that would make the overlap real. A status change that records intent appends a `STATUS_INTENT` leaf, so a request governance never ratifies is still auditable.

13. **The governance key chain is pinned by its head.** `expected-id` pins the genesis and nothing else, and a truncated or removed transitions file is a well formed chain, so a resolver could be walked back to an older key set and reinstate a key that was rotated out. `gua.resolver.genesis.expected-chain-head` pins how far the chain has run, the resolver refuses to start on anything else, and the head is published at `/.well-known/gua-federation` as `chainHead` so it can be compared out of band like the fingerprint. That closes the downgrade path on the resolver side; what a client does about genesis version skew is still **O8** and still open.

## Not decided here

The wider O2 protocol specification: Base32 prefixing, entropy lengths, hash-suite identifiers and signature encodings beyond the Ed25519 and SHA-256 used here. Client identity-change behaviour when a key chain change is indistinguishable from a takeover stays **O10**, so what a client does with a rotated member key is open. **S5** stays open as a spike: what is decided above is the minimum custody rule that lets governance signing leave the resolver process, not the answer to whether a governance key set can be operated in a genuinely different trust domain, by whom, and with what recovery. Catastrophic loss of the whole governance key set stays **O13**. Clients do not verify the genesis chain before Phase 6.

## Relationship to ADM-001

Nothing locked is reopened. This record chooses the framing L4 deliberately left to implementation and applies it to the first object L10 requires, under the O2 label. The `RosterVerifier` "one vote per authority key" shape is untouched and is not reused for any threshold that L8 governs. Where this record and ADM-001 disagree, ADM-001 governs, and implementation evidence from Phase 1 is the way back into it.
