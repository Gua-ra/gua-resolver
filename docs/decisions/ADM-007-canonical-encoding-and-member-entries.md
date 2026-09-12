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

## Not decided here

The wider O2 protocol specification: Base32 prefixing, entropy lengths, hash-suite identifiers and signature encodings beyond the Ed25519 and SHA-256 used here. The governance objects (`gua-federation-genesis.v1`, `gua-governance-transition.v1`, `gua-registry-epoch.v1`) will use `gua-lp.v1`, but their field sets are Phase 2 and are not fixed by this record. Client identity-change behaviour when a key chain change is indistinguishable from a takeover stays **O10**, so what a client does with a rotated member key is open. Governance key custody stays **S5**, and nothing here moves signing out of the resolver process.

## Relationship to ADM-001

Nothing locked is reopened. This record chooses the framing L4 deliberately left to implementation and applies it to the first object L10 requires, under the O2 label. The `RosterVerifier` "one vote per authority key" shape is untouched and is not reused for any threshold that L8 governs. Where this record and ADM-001 disagree, ADM-001 governs, and implementation evidence from Phase 1 is the way back into it.
