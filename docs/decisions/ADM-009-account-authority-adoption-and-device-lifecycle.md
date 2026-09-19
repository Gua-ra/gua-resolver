# ADM-009: Account authority adoption and the device lifecycle

> **Status: Proposed, 2026-09-19.** A focused follow-up to ADM-008 under ADM-001 L13 and O9. It closes O9 and decides the device lifecycle ADM-008 listed as unaddressed. It reopens nothing in ADM-001.

## Context

ADM-001 L5 makes account authority mandatory for new first-party accounts and leaves one path unbuilt: how an account that already exists, and whose id commits no key, gains authority at all. O9 rejected the sketch that existed and set the bar: *"It needs a fresh possession proof and a delay with notification, or it must be removed."*

ADM-008 shipped the objects and stopped at that line. Its decision 6 attaches a genesis during signup, which is the only moment the native app holds the flow. Every account created since is bootstrap: `account_genesis.origin = BOOTSTRAP`, class byte `0x00`, no key committed. Two replacements were considered and rejected. Attaching from the web profile step cannot work, because that step runs inside a web view with no channel to the native signer (ADM-008:143). Authorizing the attachment with an OTP cannot work, because identifier possession is not account authority (ADM-008:169).

ADM-008 also lists what it does not answer: a second phone, approval by a trusted device or QR, a lost or replaced phone, and revocation. Those are not separable from adoption. A design that roots an account on one device and says nothing about the second device has only moved the failure.

This record decides one protocol covering adoption and the whole device lifecycle, and says what each transition costs an attacker.

## What this is not

It is not a recovery ADM. ADM-002 still owns recovery policy, and its D1 still gates production issuance of framework `0x01`. This record uses recovery as an input and constrains what recovery may do to authority; it decides nothing about recovery's own factors or waits.

It is not a federation record. Nothing here enters `stateRoot`, and no witness is a prerequisite (ADM-005 decision 3). The authority chain is homeserver-local state with a log leaf reserved, and waits run on service time under ADM-002 R8's second sentence until witnesses exist.

## Decision

### 1. Adoption does not change the accountId, and the class byte keeps its meaning

An `accountId` is permanent (L3). Its class byte is inside the hashed prefix, so a bootstrap id cannot become a genesis-rooted id without becoming a different account. Adoption therefore leaves `accountId`, `account_genesis.account_id` and `account_genesis.origin` exactly as they are.

The class byte records **how the id was derived**, not whether the account holds authority today. `0x01` means the id commits the account's first authority key; `0x00` means it commits entropy alone. After adoption a `0x00` account holds authority that its id does not commit, and a verifier that needs to know reads the authority chain, never the class byte. This is the one reading ADM-008:19 and :149 leave ambiguous, and it is settled here rather than by implementation.

The cost is real and is accepted: an adopted account's authority is not self-certifying from its id. A relying party must fetch the chain and verify it against the account's homeserver. A genesis-rooted account keeps its stronger property. This is why L5 still requires genesis for new accounts, and why adoption is a repair for the existing population rather than a second way to create accounts.

### 2. The authority chain

Each account has an append-only chain of signed records. The chain is the authority. There is no ambient "the account's key" outside it.

Every record shares one envelope, fixed-layout, big-endian, no delimiters, canonical under L4:

| off | len | field |
| --- | --- | --- |
| 0 | 4 | magic, ASCII, one per record type, and the signature domain |
| 4 | 1 | version, `0x01` |
| 5 | 1 | suite, `0x01` = Ed25519 with SHA-256 |
| 6 | 34 | `accountId` raw bytes, exactly the 34 bytes `AccountId.rawBytes()` returns |
| 40 | 32 | `prevHash`, SHA-256 over the canonical bytes of the previous record, or 32 zero bytes in the first record |
| 72 | 8 | `seq`, unsigned, `1` in the first record and exactly one more than the previous |
| 80 | .. | body, fixed per type |

The record's own hash is SHA-256 over its canonical bytes. Signatures are detached and are never part of the hashed bytes. A record is verified against a preimage of the magic followed by the canonical bytes, so no record can be replayed as another type, and none can be replayed into another account: the accountId is inside every signature.

Record types and bodies:

| magic | type | body |
| --- | --- | --- |
| `GUAA` | `AdoptRoot` | deviceKey (32), recoveryFrameworkId (1), recoveryAuthorityKey (32), entropy (16) |
| `GUAD` | `DeviceGrant` | deviceKey (32), flags (1), label (16, UTF-8, zero-padded) |
| `GUAX` | `DeviceRevoke` | deviceKey (32), reason (1) |
| `GUAR` | `AuthorityRecovery` | deviceKey (32), recoveryAuthorityKey (32), entropy (16) |

Decoders reject an unknown magic, version, suite, framework or reason, a wrong length, an all-zero key, a key that fails Ed25519 point decoding, a `recoveryAuthorityKey` equal to a `deviceKey` in the same record, and a label with a non-zero byte after the first zero. The server hashes the bytes it received and never re-encodes, as in ADM-008 decision 1.

### 3. One head, one order, no races

The server stores exactly one `head` per account: the hash of the last accepted record, with its `seq`. A submitted record is accepted only if its `prevHash` equals the stored head and its `seq` is exactly one more. Acceptance is a compare-and-set inside one transaction.

Two devices acting at once therefore produce one winner and one refusal carrying the current head, and the loser re-reads and decides again with the winner's record in view. There is no merge, no last-writer-wins and no state in which two chains exist. This is what makes "device-add and device-revoke races" a solved case rather than a policy argument.

### 4. Adoption

The sequence, and nothing may be skipped:

1. The account completes a normal login or OAuth flow. Control returns to the **native app**. A session that is still inside the web view cannot start adoption, which is the ADM-008:143 problem stated as a rule.
2. The app requires a **fresh strong step-up**: a user-verifying passkey assertion, or the PIN where policy allows it. Freshness is the existing step-up, not a remembered assurance. `POST /account/authority/adopt/start` refuses a session whose step-up is older than the adoption window.
3. The app generates the device authority key and the recovery authority key on device, non-synced, in the platform keychain or keystore, per ADM-008 decision 5.
4. The server issues an **adoption challenge**: 32 CSPRNG bytes, minted once, held server-side against that account and that stepped-up session, single use, burned on acceptance and on refusal, expiring with the session and at or under 15 minutes.
5. The app signs the preimage `"GUAA"` followed by the canonical `AdoptRoot` bytes, with the device key it just generated. The challenge is not in the body; it is bound by being the only thing the server accepts the record against, and the server reads it from its own session state, never from the request. This is the shape ADM-008 decision 6 already uses for the attach proof, for the same reason.
6. The server records a **pending adoption** and notifies every channel the account has: every signed-in device, and the account's number through the existing notification path, never as an authorization. The notification names the device label and the time the adoption will complete.
7. After the **opposition window** the adoption completes and the record joins the chain at `seq = 1`.

During the window the adoption is cancelled by any signed-in session of the account through `POST /account/authority/oppose`, which needs no factor beyond the session. Opposition is deliberately cheap: at `seq = 1` the account holds no authority to weigh, so the only honest veto is "someone who can already read this account's notifications says no".

Abandonment is defined at every step. A challenge that is never spent expires with the session. A pending adoption that is opposed is cancelled and its challenge burned. A pending adoption whose window passes with no opposition completes, because the alternative is an adoption that silently does nothing. A client that crashes between generating keys and submitting has produced nothing the server has seen; its keys are garbage and it generates new ones next time. Nothing in the flow leaves the account half-rooted: the chain either has a `seq = 1` record or it does not.

**Opposition window.** 72 hours in production. The window is the whole security of the transition (O9), so it is not configurable below 24 hours outside a testing flag, and it runs on service time until witnesses exist (ADM-002 R8).

### 5. The device set

After adoption the account's authority is the set of device keys the chain leaves active. `AdoptRoot` activates one. `DeviceGrant` activates another. `DeviceRevoke` deactivates one. `AuthorityRecovery` replaces the set with one.

**Adding a device.** The new device generates its own key and never receives another device's key. An existing active device signs a `DeviceGrant` over it. A grant takes effect on acceptance, because it only adds, and its holder is **quarantined** until the opposition window passes: a device may not sign a `DeviceGrant`, a `DeviceRevoke` or an authority-sensitive approval while its own grant is inside its window. A stolen unlocked device can therefore add a device, and gains nothing by it for as long as the window the owner is being notified through.

Copying one key to every device is rejected. It makes revocation meaningless, since the revoked device still holds the key the account is defined by, and it turns any single device compromise into a permanent account compromise with no way back short of recovery. A per-device key costs one record and gives revocation an effect.

**Removing a device.** `DeviceRevoke` signed by an active device. Revoking **another** device takes effect after the opposition window and is notified; any other active device may oppose it, and the account's stable identity never changes. Revoking **itself** takes effect immediately, because a device removing its own authority reduces what an attacker holding it could do, and delaying that helps nobody.

The chain refuses a revocation that would leave no active device. An account with one device that wants to remove it revokes through `AuthorityRecovery` instead, which installs the replacement in the same record.

**QR and device linking.** Today's QR flow (MSC4108, through the Matrix SDK) links a Matrix session. It authenticates nothing about account authority: the payload carries no signature, the trust root is a browser cookie and a two-digit human code, and MAS records which browser session approved, not which device. This record does not change that protocol and does not put authority material in it. Instead the grant runs **alongside** it: when the existing device is an active authority device, the app offers to sign a `DeviceGrant` for the device it has just linked, and binds the two by showing the same check code the QR flow already displays. The user sees one ceremony; the account gets a signature. Nothing about authority is trusted because the QR succeeded.

### 6. The browser holds no authority, ever

A browser login grants account access. It never enters the device set, and no browser-held material may sign an authority record. This is a rule, not a default: there is no flag that lets a web session sign one.

Authority-sensitive actions reachable from the web create a `PendingApproval` carrying the accountId, the action digest and a 32-byte server challenge. The browser displays a four-character action code. An active authority device fetches the pending approval, shows the same code and the action in the reader's own words, and signs the domain `gua-authority-approval.v1`, the accountId, the pending id, the action digest and the challenge. The browser never learns a key and never proxies one. An approval is single use, expires in 10 minutes, and its challenge is burned on refusal as well as acceptance.

A malicious page can therefore start an approval the user never wanted, which is exactly what the code and the device-side description defend: the approval names the action on a screen the page does not control.

### 7. Losing the device

Two paths, and which one applies is decided by what the account still holds.

**Another active device survives.** The surviving device signs a `DeviceGrant` for the replacement and a `DeviceRevoke` for the lost one. No wait beyond the revocation window, no recovery, no SMS.

**No active device survives.** `AuthorityRecovery` installs a new device key and a new recovery authority key in one record. It is authorized in exactly one of two ways, and they are not equal:

- **Signed by the committed recovery authority key.** This is the L13.1 genesis-committed threshold at `t = 1` under framework `0x01`. It is notified and takes effect after the opposition window. An active device cannot cancel it, because L13.3 forbids making the possibly stolen active key the veto. An active device's opposition extends the window once and raises the notification, and nothing more.
- **Through account recovery**, the delayed path ADM-002 owns and identity-service ships, for an account that no longer holds its recovery authority key. This one **is** vetoable by any active device, immediately, because there the surviving device is the stronger evidence. It runs after recovery's own dormancy and wait, and then the authority opposition window on top.

**Deterministic priority (L13.2).** While an `AuthorityRecovery` signed by the recovery authority key is pending, the chain accepts no `DeviceGrant` and no other-device `DeviceRevoke`. Self-revocation stays accepted. That freezes the thief-rotate flood. The denial-of-service this creates is bounded rather than argued away: one pending recovery per account, a fixed window, and a cooldown of one window before another may be opened by the same key.

**Unrecoverable is a permitted answer (L13.4).** An account that loses every device and its recovery authority key keeps its accountId, its login and its data, and never regains authority. It may not adopt again: a second adoption authorized by login factors alone is precisely the seizure O9 rejected, and an attacker who reaches the login factors of a rooted account must not be handed its authority. Because that end state is permanent, adoption **requires** the user to take the recovery artifact: the recovery authority key is shown once, the app confirms the user has stored it, and adoption is refused without that confirmation.

### 8. What recovery may and may not do to authority

Completing an account recovery resets login factors. It does **not** move authority on its own, it does not revoke devices, and it does not mint a device key. Its only reach into this chain is the second authorization path in decision 7, and only for an account with no active device.

A rooted account under recovery therefore has two independent clocks, and the design keeps them independent on purpose: an attacker who owns the phone number drives the recovery clock and reaches the login factors, and still holds nothing the chain accepts.

### 9. SMS possession authorizes nothing here

No record in this chain is accepted on the strength of a phone code, in any combination, at any step, including adoption. The phone's only role is as one notification channel among several. Enforcement is a guard test in the source, in the shape identity-service already uses: no authority endpoint may reference the OTP services, and `AuthFactor.PHONE_OTP` may not appear in any accepted set for an authority operation.

### 10. State and transitions

| state | meaning | leaves by |
| --- | --- | --- |
| `BOOTSTRAP` | class `0x00`, chain empty | adoption start |
| `ADOPTION_PENDING` | `AdoptRoot` held, window running | completion, opposition, expiry |
| `ROOTED` | chain non-empty, at least one active device | grant, revoke, recovery |
| `RECOVERY_PENDING` | `AuthorityRecovery` held, window running | completion, veto where permitted, expiry |
| `AUTHORITY_LOST` | rooted, no active device, no recovery key | nothing. Terminal by decision 7 |

Genesis-rooted accounts (class `0x01`) start at `ROOTED` with the genesis authority key as the first device key, and use the same chain from `seq = 1`.

### 11. Compromise conditions

What an attacker must hold for each transition to succeed, stated so that a review can attack the claim rather than the prose:

| transition | requires | and survives |
| --- | --- | --- |
| adopt | a live session, a fresh step-up factor, and the device that generates the key, held for the whole opposition window without the owner opposing | nothing else. The phone number alone fails at step 2, the web view fails at step 1, a captured challenge fails because it is bound to the session that was stepped up |
| grant | an active, unquarantined device key | a stolen unlocked device wins this and gains a quarantined device, which can do nothing until the owner has been notified for a full window |
| revoke other | an active device key, and the window without opposition from another active device | an account with one device cannot be locked out this way, because the chain refuses the last revocation |
| revoke self | the device's own key | by design, no delay |
| recovery by recovery key | the committed recovery authority key, and the window | a thief holding every device cannot cancel it. A thief holding the recovery artifact and nothing else wins the account after the window, which is why the artifact is treated as account-equivalent in the copy the user is shown |
| recovery by account recovery | the login factors, recovery's own dormancy and wait, the authority window, and no active device to veto | a SIM swap plus a factor reset reaches this only for an account that has already lost every device |
| approval from a browser | an active device's signature on that exact action digest | a malicious page reaches the pending approval and not the signature |

### 12. Reserved, and deliberately not decided here

A `ACCOUNT_AUTHORITY` log leaf type is reserved for the chain head, so a later phase can commit it without a format change. Nothing writes it yet, and no verifier reads it. Witness-sequenced time for these windows is ADM-005's to deliver; until then the waits are service time and the record says so.

The hardware-resident P-256 suite that ADM-008 reserved is not defined here. Framework `0x02` is ADM-002's. Multi-party thresholds above `t = 1` are not decided: every rule here is written so that a threshold larger than one narrows it rather than reshaping it.

## Implementation gates

1. No endpoint in this record ships enabled. Server and both clients gate on their own off-by-default flags, as Phase 3 does.
2. Production adoption stays refused while ADM-002 D1 leaves framework `0x01` delay bounds open, for the same reason ADM-008 decision 4 refuses production issuance. Dev may adopt behind the testing flag and treats those accounts as disposable.
3. The guard tests named in decision 9 exist before the first endpoint does.
4. This record closes O9 only when its adoption path is implemented and reviewed. Until then O9 stays open and this is its proposed answer.
