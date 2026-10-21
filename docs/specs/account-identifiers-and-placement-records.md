# Account identifiers and placement records

The byte formats for the permanent account identifier (`accountId`), the objects it is derived from, and the signed record of which homeserver holds an account. identity-service, the resolver and both apps implement these and must agree byte for byte.

Reference implementations: identity-service `account.genesis` (`AccountGenesisCodec`, `BootstrapGenesisCodec`, `AccountId`, `GenesisProofs`, `PlacementRecordCodec`), the resolver's `placement.record` package, and the `AccountGenesis` types in each app. Golden vectors: [`genesis-vectors.v1.json`](https://github.com/Gua-ra/identity-service/blob/main/docs/specs/genesis-vectors.v1.json) in identity-service, copied into each app's tests.

## Status

- Every account has an `accountId`. Every account today is a bootstrap account: its identifier commits no key.
- The `accountId` is the WebAuthn user handle for passkeys. Nothing else reads it: not routing, not login, not a token claim.
- identity-service accepts key-rooted registrations (`POST /account/genesis`) and the attach step below. No shipped app sends one, because the signup profile step runs in a web view that cannot reach the app's key. The app-side flags stay off.
- Placement records are signed, published and compared when their flags are on. All of those flags default to off, and no routing answer reads a record.

## Rules

1. All objects are fixed-layout, big-endian byte strings with no delimiters. The placement record has one variable field with a one-byte length prefix. They cannot be confused with a [`gua-lp.v1`](federation-signed-objects.md#the-gua-lpv1-encoding) object: that opens with a `u32` length whose first byte is `0x00`, and these open with ASCII `GUA`.
2. A decoder rejects an unknown version, suite or framework, a wrong length, an all-zero key, equal authority and recovery keys, and a key that fails Ed25519 point decoding.
3. The server hashes and stores the bytes it received. It never re-encodes before hashing.
4. No object here contains a phone number, a phone hash, a username or a Matrix ID.
5. An `accountId` is permanent. It is kept when an account is deactivated and is never reassigned.
6. An `accountId` never appears in `preferred_username`, `sub` or any field a Matrix localpart is derived from. `AccountIdNotReadGuardTest` in identity-service fails the build if it reaches the routing, login or claim path.
7. Possession of a phone number never attaches a key to an account.

## Account genesis, key-rooted (87 bytes)

Created on the device at signup. It commits the account's first authority key and its recovery key.

| Field | Bytes | Value |
| --- | --- | --- |
| magic | 4 | ASCII `GUAG` |
| version | 1 | `0x01` |
| suite | 1 | `0x01`: Ed25519 keys, SHA-256 |
| authority public key | 32 | raw Ed25519 |
| recovery framework | 1 | `0x01`: one committed recovery key |
| recovery public key | 32 | raw Ed25519, different from the authority key |
| entropy | 16 | from a CSPRNG |

Keys stay on the device, in the platform keychain or keystore, and are not synced. The suite byte leaves room for other key types.

The genesis fixes the first recovery authority and the rules under which the recovery policy may later change. It does not freeze the policy for the life of the account.

Recovery framework `0x01` commits no waiting period in the bytes, and its recovery key sits in the same device store as the authority key. identity-service therefore refuses framework `0x01` unless `identity.genesis.production-issuance` is on, which is for development only. Identifiers minted that way are disposable: there is no path from a framework `0x01` identifier to a later framework.

## Account genesis, bootstrap (22 bytes)

Minted by the server for an account that has no key. It commits nothing but randomness.

| Field | Bytes | Value |
| --- | --- | --- |
| magic | 4 | ASCII `GUAB` |
| version | 1 | `0x01` |
| suite | 1 | `0x00`: no key |
| entropy | 16 | from a CSPRNG, never derived from the phone number or Matrix ID |

## The `accountId`

```
accountId = "ga1" || base32( 0x01 || class || SHA-256(genesis bytes) )
```

| Part | Size | Value |
| --- | --- | --- |
| prefix | 3 characters | ASCII `ga1`, outside the base32 |
| format version | 1 byte | `0x01` |
| class | 1 byte | `0x01` key-rooted, `0x00` bootstrap |
| digest | 32 bytes | SHA-256 of the genesis bytes as received |
| encoding | 55 characters | RFC 4648 base32, lowercase, no padding |

The result is 58 characters. The 34 raw bytes are 272 bits and 55 characters carry 275, so the last character holds three unused bits and can only be `a`, `i`, `q` or `y`. A parser matches `^ga1[a-z2-7]{54}[aiqy]$`, then decodes, re-encodes and compares, so one account has exactly one spelling.

Example from the vectors: `ga1aeatmvszaxoxcnsrkzpzbvaust6jcdhcapmia7snhqrspmukdojzkgq`. Every identifier starts with `ga1aea`. The next character is `a` to `p` for a bootstrap account and `q` to `7` for a key-rooted one, so the two can be told apart from the identifier alone.

The class byte records how the identifier was derived. It does not say whether the account holds a key today.

## Registering a key-rooted genesis

`POST /account/genesis` carries the genesis bytes and a registration proof: an Ed25519 signature by the authority key over

```
"gua-account-genesis-proof.v1" (28 ASCII bytes) || genesis bytes
```

The server returns the `accountId` and a one-time attach handle. It stores only a hash of the handle, keys the pending row by handle and never by phone, and expires it after `identity.genesis.pending-ttl` (30 minutes).

## Attaching it to a new account

The app starts sign-in with `login_hint = "gua:phone=<E.164>;genesis=<handle>"`. The auth service forwards the hint unchanged.

A handle alone attaches nothing, because anyone can compose a sign-in URL carrying their own handle and someone else's number. At the profile step the server issues 32 random bytes bound to that login session. The app signs

```
"gua-account-attach-proof.v1" (27 ASCII bytes) || 32 challenge bytes || 34 raw accountId bytes
```

with the committed authority key. The server:

- verifies the signature against the key in the stored genesis and derives the `accountId` itself, reading none from the request;
- verifies inside the transaction that creates the account;
- issues the challenge once per profile step, never accepts it from the client as a lookup key, and burns it only on a successful attach. The challenge expires with the login session, which never outlives the 30 minute handle.

A handle that fails to attach fails the signup. There is no silent fallback to a bootstrap account. A malformed hint, an unknown or repeated key, and a missing, expired or invalid proof fail the same way. A signup with no handle gets a bootstrap account, which is a normal account and not an error. The reserved hint value `passkey` keeps its own meaning. The `gua:` grammar applies only to hints with that prefix.

## Placement record (66 + n bytes)

A homeserver's signed statement that it holds an account.

| Field | Bytes | Value |
| --- | --- | --- |
| magic | 4 | ASCII `GUAP`. Also the signature domain |
| version | 1 | `0x01` |
| generation | 1 | `0x01` |
| accountId | 34 | the raw bytes under the base32 |
| origin | 1 | `0x00` bootstrap, `0x01` key-rooted. Must equal the class byte inside the accountId |
| n | 1 | length of the homeserver id, 1 to 64 |
| homeserver id | n | printable ASCII roster id, never the Matrix server name, never containing a vertical bar |
| issuedAt | 8 | epoch milliseconds, unsigned |
| notBefore | 8 | epoch milliseconds, unsigned |
| notAfter | 8 | epoch milliseconds, unsigned, later than `notBefore` |

The Ed25519 signature travels beside the bytes, not inside them. The envelope carries the record and the signature as unpadded base64url.

The resolver accepts a record only when all of these hold:

- the homeserver it names is `ACTIVE` in the roster, and the signature verifies under that homeserver's roster key. A signature by any other homeserver is rejected;
- `notAfter - notBefore` is at most 400 days (`gua.resolver.placement.max-validity`), and the record is inside its window allowing for clock skew;
- `issuedAt` is not in the future beyond the clock skew, so a far-future value cannot block later re-issues;
- no record for the same account names a different homeserver. A conflicting record is rejected and the held one is kept;
- a re-issue from the same homeserver has a later `issuedAt`.

The resolver stores the received bytes unchanged. It appends a `PLACEMENT_CHECKPOINT` leaf to the transparency log at most once per `gua.resolver.placement.checkpoint-interval` (one hour), and only when the Merkle root of the stored records changed.

identity-service issues a record valid for 400 days and re-issues at 300. The roster key that signs placement records must sign nothing else whose bytes a caller chooses.

An account that has never completed a sign-in through its homeserver's auth service has no committed evidence of where it lives, so no record is published for it.

## Limits

- A placement record is the homeserver's own assertion. With one operator signing for every homeserver, it adds an audit trail, not an independent check.
- A key-rooted genesis shows that whoever registered it held the key and was present in the sign-in session. It does not show that the person who received the SMS code owns that key.
- The registration proof carries no freshness. Anyone who captures a registration request can send it again while it is pending. `AccountGenesisService.register` then replaces the attach handle and restarts its expiry, so the handle the real app holds stops working and its signup fails.
- The resolver checks validity windows against its own clock.
- A record for a deactivated account is not retracted. How to retract one is undecided.
