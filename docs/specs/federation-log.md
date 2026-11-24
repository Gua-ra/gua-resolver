# Federation log

The formats for a federation log that anyone can replay:

- its entries,
- the state they produce,
- the checkpoints the resolver signs,
- the governance-signed list of keys that sign checkpoints,
- witness signatures.

Nothing serves or reads these objects yet. The resolver still runs the log described in the [verification protocol](../verification/gua-resolver-verification-protocol.md).

Encoding, signatures and JSON transport follow the [rules for every signed object](federation-signed-objects.md#rules-for-every-signed-object). A list sorted by an id uses unsigned UTF-8 byte order, as a set does.

- Reference implementation: the `federationlog` package and `governance.CanonicalWitnessRegistryContent`.
- Golden vectors: [`gua-federation-log-v1-vectors.json`](gua-federation-log-v1-vectors.json). Regenerate them with `./gradlew federationLogVectors`.

## Two checks

A verifier runs two separate checks on every new checkpoint, and it accepts the checkpoint only if both pass.

- **History check.** The checkpoint extends the last checkpoint the verifier accepted, and every entry is included under its root. This shows the history was only appended to since that checkpoint. It cannot show that nobody else was given a different history. Only comparing checkpoints with others, directly or through witnesses, shows that.
- **State check.** Every entry is verified and replayed in order, and the resulting state hash equals the checkpoint's. This shows the state follows from the history. It says nothing about whether others saw the same history.

## Log entry

Schema tag `gua-log-entry.v1`.

| # | Field | Type |
| --- | --- | --- |
| 1 | `genesisId` | string |
| 2 | `index` | int64, from 0 |
| 3 | `loggedAt` | timestamp |
| 4 | `type` | enum |
| 5 | `objectHash` | optional string, absent only for `TIME` |
| 6 | `signatures` | list sorted by `keyId`, no duplicates. Each is a `keyId` (string) and the raw 64-byte Ed25519 signature (byte string). JSON carries the signature as `signatureB64` |

| `type` | `objectHash` names | `signatures` are by |
| --- | --- | --- |
| `GENESIS` | the genesis, so it equals `genesisId` | the genesis keys |
| `GOVERNANCE_TRANSITION` | a `gua-governance-transition.v1` object | the outgoing and incoming governance keys |
| `REGISTRY_EPOCH` | a `gua-registry-epoch.v1` object for `HomeserverRegistry` or `WitnessRegistry`. Its content object travels with it | the governance keys |
| `MEMBER_ENTRY` | a `gua-member-entry.v1` object | the homeserver's key, plus its previous key on a key change |
| `TIME` | nothing | nobody |

Rules:

- **Position.** Entry i has index i and carries the pinned `genesisId`. Entry 0 is the genesis, and no other entry is.
- **Hashing.** The leaf hash is the RFC 6962 leaf hash of the entry's canonical bytes. The tree and its inclusion and consistency proofs follow RFC 9162.
- **Objects.** The object an entry names, and a registry epoch's content, travel beside the entry. They must hash to the values committed in the log.
- **Signatures.** Every signature an entry carries must verify, and must come from a key the rules for that object allow. The keys in force are those that hold after the entries before this one. Signatures from one key appear once, and governance signatures meet the threshold.
- **Key changes.** A key change never gives an existing `keyId` to a different key. Otherwise one signature list could not satisfy both the outgoing and the incoming key set.
- **Rejected entries.** An epoch for `VerifierRegistry` or `PolicyRegistry` fails replay. A log containing any entry that breaks these rules fails the state check.
- **Ed25519.** Every listed key follows the [key rules](federation-signed-objects.md#rules-for-every-signed-object), which refuse small-order keys, so every implementation reaches the same state.

## Time

- `loggedAt` is the time the resolver logged the entry. It never decreases from one entry to the next.
- Replay uses only logged time. Every time rule, such as a homeserver entry's validity window, is evaluated at the `loggedAt` of the entry being replayed. No replay step reads a clock.
- When nothing else is logged, the resolver appends a `TIME` entry, so entries are at most 60 seconds apart. It also signs a checkpoint at least every 60 seconds. A longer gap is an availability problem, not a replay failure.
- A witness compares the checkpoint's logged time with its own clock before it signs (see below). Together with the 60 second checkpoint interval, this limits how far logged time can drift from real time. A difference between clocks is never evidence of tampering. Logged time going backwards is.

## State

Schema tag `gua-federation-state.v1`. The state after replaying entries 0 to n-1.

| # | Field | Type |
| --- | --- | --- |
| 1 | `genesisId` | string |
| 2 | `governanceChainHead` | string. The `genesisId` until a key change, then the hash of the last key change |
| 3 | `homeserverEpochHash` | optional string, the current `HomeserverRegistry` epoch |
| 4 | `memberEntries` | list sorted by `homeserverId`, no duplicates. Each is a `homeserverId` and the `entryHash` of that homeserver's latest accepted entry |
| 5 | `witnessEpochHash` | optional string, the current `WitnessRegistry` epoch |

The state hash is the SHA-256 of these bytes.

- **Homeserver entries.** A homeserver can update its own address or key without a new membership epoch, so the state names each homeserver's latest entry as well as the epoch.
- **Routing policy.** It is not part of this version, because it has no `gua-lp.v1` encoding yet.

## Checkpoint

Schema tag `gua-checkpoint.v1`, signed by the resolver.

| # | Field | Type |
| --- | --- | --- |
| 1 | `genesisId` | string |
| 2 | `size` | int64, at least 1 |
| 3 | `rootHash` | string, the tree hash of entries 0 to `size` - 1 |
| 4 | `stateHash` | string, the state after those entries |
| 5 | `lastLoggedAt` | timestamp, the `loggedAt` of entry `size` - 1 |

- **Validity.** A checkpoint is valid when a `RESOLVER` key from the witness list in its own state signs it. So the resolver issues checkpoints only once the log holds a witness list naming its key.
- **One per size.** The resolver signs at most one checkpoint per size.

## Witness list

The content of a `WitnessRegistry` epoch, schema tag `gua-witness-registry-content.v1`. Governance signs the epoch in the same way it signs a membership epoch.

| # | Field | Type |
| --- | --- | --- |
| 1 | `requiredWitnesses` | int64 |
| 2 | `keys` | list sorted by `keyId`, no duplicates. Each is a `keyId`, `alg`, `publicKey`, `operatorId` (strings), `role` (enum `RESOLVER` or `WITNESS`) and `url` (optional string) |

Rules:

- **Keys.** The list names at least one `RESOLVER` key. It names each public key once, compared after decoding.
- **Which signatures count.** A witness signature counts only when its key has the `WITNESS` role and its operator holds no `RESOLVER` key. All signatures from one operator count once.
- **Required number.** `requiredWitnesses` is 0, or more than half of the operators that count and no more than their number. More than half means any two accepted sets of signatures share a witness. To also tolerate faulty witnesses, governance sets a higher number.
- **Witnessed.** A checkpoint is witnessed when valid witness signatures for it exist from `requiredWitnesses` operators that count, wherever the verifier fetched them. While `requiredWitnesses` is 0, no checkpoint is witnessed, and a verifier reports it as not independently verified.
- **Which list is used.** A verifier counts signatures against the witness list of the last checkpoint it accepted. It uses the checkpoint's own list only when it has accepted none. A checkpoint whose state changes the witness list needs the required signatures under both the old list and the new one, so a history forked before the change cannot pick its own witnesses.
- **Addresses.** `url` is where a witness publishes its signatures, or where the resolver serves its log.

Every witness in this version replays the log. A witness that checks only history is not part of this version.

## Witness signature

Schema tag `gua-witness-signature.v1`. The signature travels beside the bytes as `signatureB64`.

| # | Field | Type |
| --- | --- | --- |
| 1 | `checkpointHash` | string, the SHA-256 of the checkpoint's canonical bytes |
| 2 | `keyId` | string |
| 3 | `signedAt` | timestamp from the witness's own clock |

A witness signs a checkpoint only when all of these hold:

- the checkpoint passes the history check against the last checkpoint the witness signed,
- the witness replayed every entry and reached the checkpoint's state hash,
- `lastLoggedAt` is within 120 seconds of the witness's clock (otherwise the witness withholds its signature),
- the witness has not signed another checkpoint of the same size.

The witness publishes its signatures at its own `url`, so a verifier never depends on the resolver to pass them on.

## Freshness

Freshness tells a verifier how recent its view of the log is. It is judged from checkpoints. Governance-signed objects carry no expiry, and no key signs anything new to provide it.

- **Age.** The age of the newest accepted checkpoint is the verifier's clock minus its `lastLoggedAt`. Witness `signedAt` values do not enter the calculation.
- **Witness quorum.** Once `requiredWitnesses` is above 0, only a witnessed checkpoint counts. Each witness in the quorum compared `lastLoggedAt` with its own clock within 120 seconds before signing, so no single witness can make a checkpoint look newer. While `requiredWitnesses` is 0, the age rests on the resolver's signature alone and is reported as not independently verified.
- **Clock.** The verifier's clock is the only reference. Witness signatures do not correct it: a clock running behind makes a stale checkpoint look fresh, and one running ahead makes a fresh one look stale. A `lastLoggedAt` more than 5 minutes ahead of the verifier's clock is reported as `clock_skew`.
- **Elapsed time.** After accepting a checkpoint, a verifier may add monotonic time elapsed since acceptance to the age it computed then, so later wall-clock changes do not affect the result. Monotonic time does not survive a restart, after which the wall clock is used again.
- **Bootstrap.** A verifier that has accepted no checkpoint has no reference beyond its clock and the pinned genesis. The first checkpoint it accepts becomes the reference.
- **Result.** `fresh` when the age is within the configured limit, `stale` beyond it, `clock_skew` as above. The limit is a deployment parameter. The first evaluation reports only, with a limit of 15 minutes.
- **Enforcement.** Not part of this version. If enforced later, a stale or unwitnessed view blocks only operations that change trust: placing a new account, trusting a homeserver the verifier has not seen before, accepting a homeserver key change, and moving an account. Existing sessions and ordinary messaging never depend on the resolver being reachable or fresh.
- **Limits.** A fresh checkpoint shows that the resolver signed this view recently. It does not show that no entries were withheld or that others see the same history. Those are detected through conflicts and witnesses, not through freshness.

## Conflicts

- **Two histories.** Two checkpoints of the same size, both validly signed by the resolver, with different roots or different state hashes, prove that the resolver signed two histories. Anyone who holds both can show it.
- **History that does not extend.** A checkpoint of size n that does not extend an accepted checkpoint of size m is refused. The evidence is both checkpoints plus the first m entries under the larger root, with their inclusion proofs. Their tree hash differs from the smaller root.
- **Wrong state.** A checkpoint whose state hash differs from replay is refused. The evidence is the checkpoint and its entries, which anyone can replay.
- **After a conflict.** A verifier that finds any of these stops advancing and keeps the evidence. It keeps serving the last checkpoint that passed both checks.

There is no signed format for publishing a disagreement yet.
