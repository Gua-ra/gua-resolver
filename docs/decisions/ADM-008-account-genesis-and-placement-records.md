# ADM-008: Account genesis, bootstrap identity and placement records

> **Status: Accepted for implementation, 2026-09-11.** Scoped to O2 for account and placement objects; revisable by implementation evidence under the same rule as ADM-001.
>
> **Implementation note, 2026-09-12.** Decision 6's attach step is not implementable in the deployed sign-in flow, so native accounts are bootstrap-only. See "Implementation status and direction" below. No decision here is changed.

## Context

ADM-001 L4 fixes what `AccountGenesis` commits: the initial authority key, algorithm identifiers, and the initial recovery authority and framework. It holds no identifier and no homeserver, locks two encoding rules, and leaves the wire format to O2. L5 makes account authority mandatory for new first-party accounts.

Phase 3 gives new accounts an on-device genesis and every account an `accountId`, without changing routing or login. Phase 4 records where each account really lives, in comparison mode only. Only each MAS's `upstream_oauth_links` records true placement today (S6).

This record accepts the brief's proposals, with three corrections. The attach step needs a second possession proof. Framework 0x01 reaches production only once ADM-002 D1 fixes its delay bounds. An accountId has one canonical spelling.

## Decision

1. **Canonical bytes.** `AccountGenesis` (suite 0x01), `BootstrapGenesis` (suite 0x00) and `PlacementRecord` are fixed-layout, big-endian byte strings with no delimiters. The placement record's one variable field carries a one-byte length prefix. Decoders reject an unknown version, suite or framework, and a wrong length. They also reject an all-zero key, equal authority and recovery keys, and a key failing Ed25519 point decoding. The server hashes only the bytes it received.

2. **accountId.** `accountId = "ga1" || base32(0x01 || class || SHA-256(canonical bytes))`. The prefix bytes are the format version 0x01 and the class byte: 0x01 genesis-rooted, 0x00 bootstrap. Base32 is RFC 4648, lowercase and unpadded, giving a 58-character id, 55 of them base32.

   The string also has a canonical form. The 34 input bytes are 272 bits while 55 characters carry 275, so the last character holds three unused bits. Only `a`, `i`, `q` and `y` can end a well-formed id. A decoder otherwise accepts eight spellings of one account, which L4 forbids. Parsers match `^ga1[a-z2-7]{54}[aiqy]$`, then re-encode and compare.

3. **Entropy and proof.** Every genesis carries 16 bytes of CSPRNG entropy, so distinct accounts get distinct ids. Registration adds an Ed25519 signature by the authority key over the ASCII domain `gua-account-genesis-proof.v1` and the canonical bytes. It proves possession and is not part of the genesis. An MXID in the preimage would put an identifier into the id.

4. **Recovery framework.** Framework id 0x01 commits one recovery authority key, generated on device and distinct from the authority key. Recovery-policy transitions are those ADM-002 will define under L13. Each must be authorized under the genesis-committed threshold, as L13 requirement 1 and L4 both demand. None is valid until that record lands. A `BootstrapGenesis` commits nothing, but makes no L4 claim: its id is the L5 bootstrap marker.

   Framework 0x01 commits less than the ADM-002 draft requires. Its D1, for framework 0x02, commits the framework version, a factor-set hash commitment, the threshold, and bounds on both delays. ADM-002 D1 runs framework 0x01 accounts under its rules at `t = 1` on that one key, and its migration order has Phase 3 proceed under 0x01. Only a 0x02 object waits for the 0x02 freeze. Production issuance under 0x01 is therefore gated on ADM-002 D1 fixing the 0x01 bounds on both delays, not on the 0x02 freeze. It is also gated on the independence reason below. identity-service rejects `recoveryFrameworkId = 0x01` at `POST /account/genesis` while `identity.genesis.production-issuance` is off, which is its default outside dev. Dev mints 0x01 ids behind `identity.genesis.enabled` and treats them as disposable, with no migration path from a 0x01 id to a 0x02 one.

   Under 0x01 the recovery key shares the device store with the authority key, so it is not independent of the key it would veto. L13 requirement 3 wants cancellation that is not the possibly stolen active key. Production issuance waits for both reasons. ADM-002 Q6 decides the second.

5. **Authority key.** Suite 0x01 is Ed25519 with SHA-256. Keys stay device-only and non-synced in the platform keychain or keystore. The suite byte reserves room for a hardware-resident P-256 suite.

6. **Attach handle.** The client registers its genesis at `POST /account/genesis` and receives a one-time attach handle, stored only as a hash. It sends `login_hint = "gua:phone=<E164>;genesis=<handle>"`, which MAS forwards verbatim through `forward_login_hint` with no MAS or SDK change. The handle is single-use, expires after 30 minutes, and attaches only inside the OTP-verified profile step. Pending rows are keyed by handle, never by phone.

   A handle alone does not attach. Any party can compose an authorize URL, so the hint is attacker-controlled in both directions. The dangerous one carries the attacker's own genesis in a URL prefilling the victim's number, which their OTP then passes.

   The profile step therefore issues server-chosen bytes bound to that login session. The client signs the domain `gua-account-attach-proof.v1`, those bytes and the accountId with the committed authority key. identity-service verifies it against the registered genesis, inside the transaction that creates the account. The bytes are 32 CSPRNG bytes, issued once per profile step, held against the server-side login session, and never accepted from the client as a lookup key. They are single use, burned only by the successful attach, and expire with that session at or under the 30-minute handle TTL. The preimage is fixed length: the 27 ASCII bytes of the domain, then those 32 bytes, then the 34 raw accountId bytes. identity-service derives that accountId from the stored genesis and reads none from the request. The attach binds to the party that registered the genesis.

   A handle that fails to attach fails the signup, with no silent downgrade. An unparsable hint, an unknown or duplicated key, a malformed `genesis` value, and a missing, expired or non-verifying attach proof fail the same way. A signup that presents no handle at all takes the bootstrap branch, which is not a failure. The accountId never enters `preferred_username`, `sub` or any localpart-derived field. The value `passkey`, reserved in identity-service `main`, keeps its meaning, and the `gua:` grammar applies only to prefixed hints.

7. **Placement records.** A generation-1 record binds one accountId to one roster homeserver id. The holding homeserver's roster membership key signs it, and the record magic is the signature domain. identity-service holds that key for each homeserver it provisions. Phase 1 genesis keys and Phase 2 registries later replace it without changing the format. Validity is 400 days, re-issued at 300, and `notBefore` must precede `notAfter`.

   The resolver verifies the signature under the roster key of the homeserver the record names, which must be ACTIVE, and stores received bytes verbatim. A signature by any other member is rejected. It accepts a newer record from the same homeserver and rejects one naming another. An `issuedAt` beyond the accepted clock skew is rejected, so a far-future value cannot freeze a slot. It appends a checkpoint leaf at most once per PT1H interval, only when the root changed. No other use of a membership key may sign caller-chosen bytes, because admission's possession proof carries no prefix.

8. **Accounts without evidence, and the bootstrap end.** An account that never completed a delegated login has no MAS link, the only committed placement evidence. It publishes nothing until it does. Web signups get bootstrap ids, because no web genesis design exists.

   L5 calls B1 a bootstrap path with a defined end. The web client is first-party, so that end is unmet. No phase after 4 may propose reading a placement record for routing until web signups mint genesis or stop creating accounts.

9. **Shadow mode.** Records are computed, published and compared daily against each MAS's `upstream_oauth_links`. No routing path reads them. A later phase may propose reading them only once every criterion in the list below holds, with decision 8's gate. Production publishing also waits on the L16 review.

10. **Order and subject.** The S6 trap fix lands first. `routeExistingUser` takes `preferred_username` from the directory username. Its only fallback is a strictly parsed MXID localpart; otherwise it refuses. `sub` stays the MXID, and MAS link subjects are not rewritten. A guard test fails if any claim matches the canonical accountId pattern.

## Shadow-mode exit criteria

The list is closed and taken verbatim from the Phases 3 and 4 brief. All must hold before any later phase proposes reading a placement record for routing, which is not part of Phases 3 or 4.

- Every account has an `account_genesis` row and the missing-genesis alert has been silent for 14 days.
- The reconciler ran daily for at least 14 consecutive days in dev and 14 in prod with `record_disagrees = 0`, `mas_multiple = 0`, `mas_username_mismatch = 0`, `directory_stale` only on allowlisted testbed placements, and `mas_none` explained (accounts listed, not guessed).
- Resolver `placement_conflicts_total = 0` and `orphaned_by_roster = 0` over the window; a full re-verification sweep passes against the current roster.
- Effective `on_conflict` is `fail` on every MAS and `mas_none = 0` (the merge path is closed only once nobody still needs it).
- The clients ship with genesis and `require-for-native` is on.
- Per-request comparison inside `/resolve` is impossible until an identifier can be resolved to an accountId, which is the Phase 5 binding record; the exit for Phase 4 explicitly does not include it.

The fifth criterion needs production issuance under decision 4. ADM-002 D1 fixing the 0x01 bounds therefore sits on this path, together with the independence reason, which ADM-002 Q6 decides.

## Encoding tables

**AccountGenesis, suite 0x01**

| Field | Size (bytes) | Notes |
|---|---|---|
| magic | 4 | ASCII `GUAG`, domain separation |
| genesisVersion | 1 | 0x01 |
| suite | 1 | 0x01: Ed25519 authority, Ed25519 recovery, SHA-256 |
| authorityPublicKey | 32 | raw RFC 8032 Ed25519 public key |
| recoveryFrameworkId | 1 | 0x01: one committed recovery authority key |
| recoveryAuthorityPublicKey | 32 | raw Ed25519, must differ from the authority key |
| entropy | 16 | CSPRNG |
| total | 87 | any other length is rejected |

**BootstrapGenesis, suite 0x00**

| Field | Size (bytes) | Notes |
|---|---|---|
| magic | 4 | ASCII `GUAB` |
| version | 1 | 0x01 |
| suite | 1 | 0x00: no authority key |
| entropy | 16 | CSPRNG, never derived from the MXID or phone |
| total | 22 | stored so the id stays re-derivable and auditable |

**accountId**

| Field | Size | Notes |
|---|---|---|
| prefix | 3 characters | ASCII `ga1`, outside the base32 |
| format version | 1 byte | 0x01 |
| root class | 1 byte | 0x01 genesis-rooted, 0x00 bootstrap |
| digest | 32 bytes | SHA-256 of the canonical bytes as received |
| encoded | 55 characters | 34 bytes in RFC 4648 base32, lowercase, unpadded |
| total | 58 characters | `ga1` plus the 55 |
| canonical form | rule | the last character holds 3 unused bits, so it is one of `a`, `i`, `q`, `y`; `^ga1[a-z2-7]{54}[aiqy]$`, then re-encode and compare |

**PlacementRecord, version 0x01**

| Field | Size (bytes) | Notes |
|---|---|---|
| magic | 4 | ASCII `GUAP`, also the signature domain |
| version | 1 | 0x01 |
| generation | 1 | 0x01 |
| accountId | 34 | raw bytes under the base32, starting at offset 6 |
| origin | 1 | 0x00 bootstrap, 0x01 genesis; must equal the class byte at offset 7 |
| n | 1 | homeserverId length, 1 to 64 |
| homeserverId | n | ASCII roster id, never the Matrix domain |
| issuedAt | 8 | epoch milliseconds, unsigned; rejected beyond the accepted clock skew |
| notBefore | 8 | epoch milliseconds, unsigned |
| notAfter | 8 | epoch milliseconds, unsigned; must exceed notBefore, by at most 400 days |
| total | 66 + n | the Ed25519 signature travels beside the bytes, not inside them |

## Consequences

- Authority keys are device-only and unescrowed, so a lost device loses authority.
- Generation-1 records are homeserver-asserted and do not improve the compromise condition (L5). One signer for every homeserver is one operator, able to produce roster-level proofs for each key.
- The accountId to roster id mapping is new public state without identifiers (L15), and the L16 review gates publishing.
- Each checkpoint leaf reseeds new-account fallback placement (L6 [CODE]). The interval bounds that churn only until ADM-005 decision 9's continuous logging lands; the L6 seed must then stop reading roster version.
- The attach handle is a routing hint, not a capability. A stolen handle attaches nothing; a planted one fails at the proof step.
- The proof shows that the party which registered this genesis held its key and was present in this session. It does not show that the human who passed the OTP owns that genesis, so L7's residual is unchanged.
- The resolver checks validity windows against its own clock. That is admission, not a replayable transition (L11). It holds only until placements enter `stateRoot`, when ADM-005 decision 9 moves those windows to `seqTime`.

## Not decided here

- The MAS read path: the admin API with identity-service as an admin client, or a read-only SQL role.
- The `on_conflict` timeline: when each environment moves from `add` to `fail`.
- The flip criterion for requiring genesis on native signups.
- Retraction of records for deactivated accounts; their placement persists until defined.
- Recovery mechanics, cancellation authority and key rotation. These sit in ADM-002, drafted but not frozen.

## Implementation status and direction, 2026-09-12

Recorded after acceptance, to state what the code reached and why. This section adds status and direction only. It changes no decision above, and decision 6 stands as written.

Native accounts are bootstrap-only today. Every native signup takes decision 6's bootstrap branch, so no native account holds an account authority key. The genesis scaffolding is present and disabled on both halves.

**1. Decision 6's attach step is not implementable in the deployed flow.** The account authority private key is generated and held by the native app in the platform keystore. The profile step that would carry the attach proof executes inside the sign-in web page. On iOS that is an `ASWebAuthenticationSession`, and on Android a Chrome Custom Tab. The page has neither the genesis material nor any channel to the native signer. Redirecting out to the app's own scheme would end the OIDC session. Decision 6 assumed the party completing the profile step holds the key, and it does not.

**2. An OTP-authorized attachment was designed, reviewed and rejected.** The design sealed a genesis to the phone number with an OTP before the OIDC flow. It then attached by comparing the sealed phone digest against the number the login session had verified in page.

The adversarial review found a concrete exploit. An attacker registers their own genesis against a victim's number. The server sends a code to the victim's phone. The attacker reads that one code once and seals the row. They then lure the victim to an ordinary authorize URL carrying the attacker's handle. The victim passes their own login OTP normally. The victim's new account is then permanently rooted in the attacker's authority key, and under recovery framework 0x01 the recovery key too.

There is no repair. An accountId is permanent under ADM-001 L3, `account_genesis.origin` is immutable, `user_id` is UNIQUE, and `ADOPT_ROOT` is unresolved under ADM-001 O9.

A second, independent defect: the registration proof carries no freshness. A captured registration body can be replayed to rotate the handle and burn a victim's genesis.

Under decision 6 as written the first attack is cryptographically impossible. Attaching requires a signature over server-chosen bytes that never leave the server-side login session. The amendment would have traded impossible for one intercepted SMS.

**3. Native accounts remain bootstrap-only for now.** A bootstrap account is a valid, normal user account. It is not degraded, and it is not a holding state a user can perceive. The client and server genesis scaffolding stays present and disabled, with every flag defaulting off. On the server those are `identity.genesis.enabled`, `identity.genesis.production-issuance` and `identity.genesis.require-for-native`. Each client carries its own off-by-default flag. Shadow-mode exit criterion 5, the clients shipping genesis with `require-for-native` on, is therefore not reachable yet.

**4. A secure `ADOPT_ROOT` is deferred** to a dedicated account-authority lifecycle iteration. It is not being designed here. ADM-001 O9 stays open, and nothing in this section narrows it.

### Direction for that iteration, not a decision

The shape below is preserved so the next iteration starts from it. It is direction, not a decision, and it is not a design.

A bootstrap account, then a completed normal OAuth login, then control returns to the native app. Then a fresh strong step-up, with a passkey preferred. Then the native app generates and proves a candidate authority key. Then an account-bound one-time challenge, then a pending `ADOPT_ROOT` transition, then notification and opposition where required. Then the authority becomes active.

SMS possession by itself must never authorize this transition. That is the whole lesson of the rejected design.

The future design must also cover each of these explicitly:

- a second phone;
- QR or trusted-device approval;
- a lost or replaced phone;
- recovery;
- web login;
- browser sessions that may use the account but are not automatically account-authority devices.

## Relationship to ADM-001

- L3: an accountId is permanent, kept on deactivation.
- L4: the layouts satisfy both encoding rules, and an accountId has one canonical spelling.
- L5: genesis for new native accounts, bootstrap marked. The web path's end is unmet, gated in decision 8.
- L6: records are homeserver-asserted; the five-step transaction is not built here.
- L9: a conflicting record is rejected, never migrated.
- L11: checkpoints are assertions, and no witness co-signs them.
- L13: the framework commits a key and requires the genesis-committed threshold for each transition.
- L15: no identifier, phone hash or MXID appears in any record.
- O2: narrowed for these objects; the wider specification stays open.
- O5 and O6: untouched beyond the committed key.
- S6: its trap is fixed first, and subjects do not change.

Nothing locked is reopened. L5's defined end for the web path is recorded as unmet, not narrowed.

## Relationship to ADM-007

ADM-007 is not drafted yet. This section states the encoding it is expected to carry, from the Phases 1 and 2 brief. Treat it as pending.

ADM-007 covers roster, member and governance objects under `gua-lp.v1`. That encoding prefixes each field with a u32 length and opens each object with a schema tag. Account objects instead have no optional fields, sets or free strings. The accountId is a permanent hash, so the hashed bytes must be the bytes that crossed the wire.

Both families obey the same two L4 rules: one canonical byte representation, and signatures over those bytes. They cannot be confused: a `gua-lp.v1` object opens with a u32 length starting 0x00, account objects with ASCII `GUA`.
