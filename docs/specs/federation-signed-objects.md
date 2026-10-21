# Signed federation objects

The byte formats and verification rules for the objects the resolver signs, serves and verifies: homeserver roster entries signed by their own homeserver, and the governance objects that define who may change federation membership. An implementation in another language must reproduce these bytes exactly.

Reference implementation: `global.gua.resolver.crypto.CanonicalEncoder`, `roster.CanonicalMemberEntry` and the `governance.Canonical*` classes. Golden vectors: [`gua-lp-v1-vectors.json`](gua-lp-v1-vectors.json) and [`gua-governance-v1-vectors.json`](gua-governance-v1-vectors.json). How a client uses these objects is in the [verification protocol](../verification/gua-resolver-verification-protocol.md).

## Rules for every signed object

1. A signed object has exactly one canonical byte representation. A decoder rejects any other encoding of the same values.
2. A signature covers the canonical bytes. An object hash is SHA-256 over the same bytes, written as lowercase hex.
3. Transport is JSON. A verifier parses the JSON, rebuilds the canonical bytes from the parsed fields and verifies against those. The signed part is parsed by a strict reader that rejects unknown fields, duplicate keys and trailing content, so a signature never covers fewer fields than a consumer reads.
4. Signatures sit outside the canonical bytes.
5. Keys and signatures are Ed25519.

The older roster, policy and claims encodings (`CanonicalRoster`, `CanonicalRoutingPolicy`, `CanonicalDelegatedRules`, `CanonicalRoutingClaims`) are still verified as served and are described in the verification protocol. `CanonicalRoster` joins fields with a raw `0x1F` byte and encodes null and empty identically, so it is never used for a new object. Its `gua-roster.v1` bytes must stay byte-identical so that deployed verifiers keep working. `CanonicalRosterUnchangedTest` enforces that.

## The `gua-lp.v1` encoding

Length-prefixed, no delimiters, no escaping.

| Type | Bytes |
| --- | --- |
| byte string | `u32` big-endian length, then the bytes |
| string | the byte string of its exact UTF-8 bytes. No normalization. Invalid Unicode is rejected, not replaced |
| int64 | 8 bytes, big-endian, two's complement |
| timestamp | int64 of epoch milliseconds |
| bool | one byte, `0x00` or `0x01` |
| optional | one presence byte (`0x00` absent, `0x01` present), then the value. Absent and empty are different bytes |
| list | `u32` count, then the elements in order |
| set | a list sorted by unsigned UTF-8 byte order. A duplicate is rejected |
| enum | its canonical name as a string |

Every object starts with its schema tag as a string, followed by its fields in the order given below. No field is omitted. Account objects use a separate fixed layout, and [the two cannot be confused](account-identifiers-and-placement-records.md#rules).

## Homeserver roster entry signed by the homeserver

Schema tag `gua-member-entry.v1`. This is the part of a roster entry that the homeserver controls and signs with its own key, so the resolver operator cannot rewrite a homeserver's address, issuer, key or search policy unnoticed.

| # | Field | Type |
| --- | --- | --- |
| 1 | `id` | string |
| 2 | `serverName` | string |
| 3 | `baseUrl` | string |
| 4 | `masIssuer` | string |
| 5 | `alg` | string, `Ed25519` |
| 6 | `signingKey` | string |
| 7 | `keyId` | string |
| 8 | `sequence` | int64, at least 1 |
| 9 | `notBefore` | timestamp |
| 10 | `notAfter` | timestamp |
| 11 | `region` | optional string |
| 12 | `searchVisibility` | enum |
| 13 | `searchGroups` | set of strings |

Not covered, because the resolver operator or governance decides them: `weight`, `acceptsNew`, `claims`, `admittedAt`, `status`.

Rules:

- `notAfter - notBefore` is at most 400 days (`gua.resolver.roster.member-max-lifetime`).
- The key an operator proves possession of at admission is kept as the first key of its entry chain.
- A new entry for the same homeserver has a `sequence` that does not go backwards, and one sequence names one entry.
- A changed `signingKey` needs a strictly higher sequence, a new `keyId`, and signatures by both the new key and the previous key.
- A lost key has no self-signed way back. The entry is revoked and the operator is admitted again as a new identity.
- Each accepted entry appends a `MEMBER_ATTEST` leaf to the transparency log carrying the SHA-256 of its canonical bytes.

`gua.resolver.roster.require-member-signature` (default `false`) decides whether an `ACTIVE` entry without a valid homeserver signature is served. When `true`, such an entry is left out of `/roster`, out of new-account placement and out of existing-account resolution. Turning it on before every active homeserver has signed its entry stops that homeserver's users from signing in. The procedure is in the [member attestation runbook](../runbooks/member-attestation.md).

## Governance objects

Governance keys decide federation membership. They are held outside the resolver process and are separate from the operational key the resolver signs its roster with.

### Federation genesis

Schema tag `gua-federation-genesis.v1`. The root of trust: a threshold and the governance keys it applies to.

| # | Field | Type |
| --- | --- | --- |
| 1 | `federationLabel` | string |
| 2 | `createdAt` | timestamp |
| 3 | `hashSuite` | string, `SHA-256` |
| 4 | `threshold` | int64 |
| 5 | `keys` | list, sorted by `keyId`, no duplicates. Each key is four strings: `keyId`, `alg`, `publicKey`, `operatorId` |
| 6 | `registries` | set of strings |

- `genesisId` is the SHA-256 of these bytes. The fingerprint people compare is its first 16 hex characters in groups of four.
- `registries` is a set, so the JSON order of the names never changes the `genesisId`. The four names are fixed: `HomeserverRegistry`, `VerifierRegistry`, `PolicyRegistry`, `WitnessRegistry`. Only `HomeserverRegistry` has a code path. The content of the others must stay empty. Routing policy is the existing `gua-routing-policy.v1` bundle verified under the governance keys, not a registry epoch. A policy registry epoch would bind the `genesisId` into the bundle bytes, which needs a new `gua-routing-policy.v2` tag. It must land before the identifier proof policy shares that registry.
- A genesis is signed by the keys it lists, so fetching it proves nothing. It becomes a trust root only when its fingerprint has been compared over an independent channel and pinned.

### Governance key change

Schema tag `gua-governance-transition.v1`.

| # | Field | Type |
| --- | --- | --- |
| 1 | `genesisId` | string |
| 2 | `index` | int64, starting at 1 |
| 3 | `previousHash` | string. The `genesisId` for index 1, then the hash of the previous transition |
| 4 | `issuedAt` | timestamp |
| 5 | `newThreshold` | int64 |
| 6 | `newKeys` | list, sorted by `keyId`, same four strings per key as in the genesis |

A transition must meet the threshold of the outgoing key set and of the incoming key set.

The chain head is the `genesisId` when no transition has been applied, otherwise the hash of the last applied transition. `gua.resolver.genesis.expected-chain-head` pins it. The resolver refuses to start on any other head, so a truncated transitions file cannot bring back a key that was rotated out. The head is served as `chainHead` at `GET /.well-known/gua-federation`.

### Membership epoch

Schema tag `gua-registry-epoch.v1`. One governance-signed statement of the full membership.

| # | Field | Type |
| --- | --- | --- |
| 1 | `registry` | string, the registry name |
| 2 | `genesisId` | string |
| 3 | `epoch` | int64, starting at 1 |
| 4 | `previousEpochHash` | string, empty at epoch 1 |
| 5 | `issuedAt` | timestamp |
| 6 | `contentHash` | string |

Schema tag `gua-homeserver-registry-content.v1`, the content an epoch commits to:

| # | Field | Type |
| --- | --- | --- |
| 1 | members | list, sorted by `homeserverId`, no duplicates |

Each member, in order: `homeserverId` (string), `status` (enum), `memberEntryHash` (optional string), `weight` (int64), `acceptsNew` (bool), `claims` (list, in the order that was signed).

Each claim, in order: `country`, `mccmnc`, `carrier` (optional strings), `phonePrefixes` (set), `affiliation` (optional string), `attributeMatch` (list of key and value string pairs, sorted by key), `remoteClaimUrl` (optional string), `priority` (int64).

Each accepted epoch appends a `MEMBERSHIP_EPOCH` leaf carrying the epoch hash and is served at `GET /registry/homeservers/epoch/current` and `/epoch/{n}`.

### Rules governance verification depends on

- **A threshold counts operators, never keys.** Every governance key records an `operatorId`. Two valid signatures from keys with the same `operatorId` count once. A threshold above the number of distinct operators is refused at load.
- **Governance admits or removes a homeserver. It does not redefine one.** An epoch commits to each member's `memberEntryHash`, the hash of the entry that homeserver signed, not to the member's fields.
- **An epoch ratifies, it does not originate.** The resolver rebuilds the pending membership from its own state and refuses an epoch whose `contentHash` differs. The operational key proposes, governance ratifies, and neither changes served membership alone.
- **The roster and policy verifiers count per key.** `RosterVerifier` and `RoutingPolicyVerifier` keep that behaviour for the operational roster snapshot and the policy envelope. Neither may be reused where a threshold has to mean independent parties.
- **Trust roots fail closed.** A verifier with no configured trusted keys verifies nothing. It never falls back to another key set. The client-side reference verifier applies this unconditionally. The resolver applies it once `gua.resolver.governance.required` is on.

### The `gua.resolver.governance.required` switch

Default `false`. It is one switch for three things, so no trust root narrows just because new code was deployed, and one flip back restores all three.

| | `false` | `true` |
| --- | --- | --- |
| Admission | takes effect directly | lands `PENDING`, absent from the served roster, until an epoch admits it |
| Suspend or revoke | takes effect directly | records a `STATUS_INTENT` leaf. Only an epoch changes status |
| Routing policy bundle | verified under configured policy keys, with the earlier fallback to authority keys | verified under the governance keys only |
| Routing claims envelope | earlier fallback to policy or authority keys | verified under `claims.trusted-keys` only. An unset list rejects every envelope |

A `PENDING` homeserver still counts toward the check that two homeservers do not claim the same accounts.

Key custody, the signing tool and the order of operations are in the [governance keys runbook](../runbooks/governance-keys.md).

## Transparency log leaf types

These names are fixed on the wire.

| Leaf | Payload hash covers |
| --- | --- |
| `ADMIT` and the status names | an admission or a direct status change |
| `MEMBER_ATTEST` | the canonical bytes of a homeserver-signed entry |
| `MEMBERSHIP_EPOCH` | a governance-signed membership epoch |
| `STATUS_INTENT` | a status change requested while governance is required |
| `POLICY_PUBLISH` | the canonical bytes of a published routing policy bundle |
| `DIRECTORY_CHECKPOINT` | the Merkle root of the legacy directory |
| `PLACEMENT_CHECKPOINT` | the Merkle root of stored placement records |

## Limits

- One operator runs the resolver, holds the operational key and holds the governance keys. These rules separate processes and key custody. They do not yet separate parties.
- No client verifies homeserver-signed entries, the genesis or the membership epochs. Until one does, these rules protect against a resolver whose database was rewritten, not against a resolver that serves a client something it never logged.
- The resolver stamps log leaves with its own clock and checks validity windows against it.
- What a client should do when a homeserver's key changes, or when a governance key set is lost beyond its own rotation rule, is not decided. Loss of the governance keys today means a new genesis and new client builds.
