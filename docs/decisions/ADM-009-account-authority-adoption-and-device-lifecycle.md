# ADM-009: Account authority adoption and the device lifecycle

> **Status: Proposed, 2026-09-19.** A focused follow-up to ADM-008 under ADM-001 L13 and O9. It proposes the answer to O9 and decides the device lifecycle ADM-008 listed as unaddressed. It reopens nothing in ADM-001. O9 stays open until the path here is implemented, reviewed and published under the leaf of decision 12, because O9's stated adversary includes the homeserver.
>
> **Revision 2, 2026-09-19, after adversarial review.** Seven independent attacks were run against revision 1. The chain, the single head, the per-device keys and the browser rule survived every one. Sixteen holes were found. Four were critical: account recovery laundered phone possession into the adoption step-up, the notification channel the windows depend on does not exist in the code, a borrowed unlocked phone could strip the owner's authority in two records with no delay, and the device named in a revocation could veto its own removal.
>
> **Revision 7, 2026-09-24, on what publishing the head actually bought.** The `ACCOUNT_AUTHORITY` leaf decision 12 reserved is now built on both sides, and building it settled how far it gets. A head is published in the log and a verifier can check inclusion against a signed checkpoint, so a head can no longer be invented for a reader who checks. What it does not buy is the third property O9 needs: the publishing key is the chain-storing homeserver's own roster membership key, and one deployment holds every homeserver's membership key, so publisher and chain-storer are one trust domain. Decision 12 now says that rather than implying the leaf closes O9.
>
> **Revision 6, 2026-09-24, defining the channel the gate depends on.** Gate 2 demanded an out-of-band notification channel and never said what one is. Three implementations then built one and invented a signed object, `gua-authority-notification.v1`, that this record did not define, which is the same mistake revision 4 was written to correct. Decision 13 defines it: the installation identity, what survives a recovery, the preimage, how a destination may be replaced, who may remove one, how long it lives, and what it costs an attacker. The rule the code review established, that a fresh post-recovery session cannot remove or repoint another installation's registration, is the property the decision is built around.
>
> **Revision 5, 2026-09-23, on SDK evidence.** Decision 5 said Android's check-code validation was a stub that returns true. True about the method, misleading about the protocol: the code is compared inside the secure channel's confirm step and a wrong one fails the ceremony. The sentence is corrected in place, because someone was going to read it as "a wrong code is accepted" and design around a hole that is not there.
>
> **Revision 4, 2026-09-19, on implementation evidence.** Building the server and both clients found two things this record asks for and never defined, which is the trigger ADM-001 names for revising a record. It told an active device to oppose a grant, a revocation and a recovery, and gave it no object to oppose with; the server correctly refused to accept that claim from a bearer session, because a stolen session could then veto the owner's own revocation of the thief's device. And it told a new device to generate its own key and an existing device to sign a grant over it, without saying how the public key crosses between them. Decision 2 gains a fifth record and decision 5 gains the candidate step. Nothing else changes.
>
> **Revision 3, 2026-09-19, after re-reviewing revision 2.** Eleven of the sixteen closed. Three of revision 2's own fixes opened new holes, two of them worse than what they replaced, and one fix was written for `AdoptRoot` alone while `AuthorityRecovery` kept every property it was meant to remove. Revision 3 applies one rule to every record type instead of patching them one at a time: every record signs a server challenge, every authority-granting record carries the same step-up and hold, and conflicts resolve by ADM-002 D2's existing rank and backoff rather than by a freeze this record invented. The review's findings are named inline where they changed a decision.

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

The cost is real and is accepted: an adopted account's authority is not self-certifying from its id, and until the log leaf of decision 12 exists it is an assertion by the account's homeserver. A genesis-rooted account keeps its stronger property. This is why L5 still requires genesis for new accounts, and why adoption is a repair for the existing population rather than a second way to create accounts.

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

The record's own hash is SHA-256 over its canonical bytes. Signatures are detached and are never part of the hashed bytes.

**One preimage rule, for every type.** A record is verified against `magic || the 32 bytes of the server challenge minted for that transition || the canonical bytes`. The magic is the signature domain, so no record can be replayed as another type; the accountId is inside the canonical bytes, so none can be replayed into another account; and the challenge is inside every signature, so no record is precomputable on other hardware, transferable to another party, or resubmittable after it was opposed. Revision 2 fixed this preimage for `AdoptRoot` alone and deleted the general rule, which left `DeviceGrant`, `DeviceRevoke` and `AuthorityRecovery` as exactly the unbound blobs the review had objected to. Every transition therefore begins by asking the server for a challenge, and the server holds it against the account and the acting session and burns it on acceptance and on refusal.

| magic | type | body | total |
| --- | --- | --- | --- |
| `GUAA` | `AdoptRoot` | deviceKey (32), recoveryFrameworkId (1), recoveryAuthorityKey (32), label (16), entropy (16) | 177 |
| `GUAD` | `DeviceGrant` | deviceKey (32), flags (1), label (16), authorizingKey (32) | 161 |
| `GUAX` | `DeviceRevoke` | deviceKey (32), reason (1), authorizingKey (32) | 145 |
| `GUAR` | `AuthorityRecovery` | deviceKey (32), recoveryAuthorityKey (32), label (16), entropy (16), authorization (1), authorizingKey (32) | 209 |
| `GUAO` | `Oppose` | opposedRecordHash (32), authorizingKey (32) | 144 |

`authorizingKey` names the key whose signature authorizes the record, inside the bytes that are hashed, so a later log leaf commits **who** authorized each transition and not only that someone did (review finding 12). It must equal the verifying key, which the server checks rather than infers. `AuthorityRecovery.authorization` is `0x01` for the committed recovery authority key or `0x02` for the account-recovery path; under `0x02`, and only then, `authorizingKey` is all zero, and a decoder enforces that pairing in both directions.

`Oppose` is how an active device objects, and revision 4 adds it because revisions 1 to 3 asked devices to oppose without giving them anything to sign. It names the hash of the record it opposes, carries the same envelope and the same preimage, and is accepted only from a key the chain has active and unquarantined at that moment. It takes no slot and starts no window: it cancels the record it names, or it is refused. A session with no device behind it may oppose an **adoption** and nothing else, which is decision 4's rule and the one case where no device can exist yet. Accepting a session's word for the others would let a stolen session veto the owner's revocation of the thief's device, which is the inversion decision 5's exclusion exists to prevent.

Labels are 16 bytes of UTF-8, zero-padded, and are what a notification is allowed to name. `AdoptRoot` carries one for the same reason a grant does (review finding 13).

Decoders reject an unknown magic, version, suite, framework, reason or authorization, a wrong length, an all-zero key outside the one pairing above, a key that fails Ed25519 point decoding, a `recoveryAuthorityKey` equal to a `deviceKey` in the same record, and a label with a non-zero byte after the first zero. The server hashes the bytes it received and never re-encodes, as in ADM-008 decision 1.

### 3. One head, one order, no races

The server stores exactly one `head` per account: the hash of the last accepted record, with its `seq`. A submitted record is accepted only if every one of these holds, checked in one transaction:

1. its `prevHash` equals the stored head and its `seq` is exactly one more;
2. its `accountId` equals the account the server resolved from its own session state, never a value read from the request (review finding 5);
3. its type is permitted at that position and on that class of account:
   - `AdoptRoot` only on an empty chain of a class `0x00` account, and never otherwise (review finding 16);
   - `AuthorityRecovery` only on an account that already holds a committed authority, which for a class `0x01` account is its genesis key and for a class `0x00` account is a completed `AdoptRoot`. It is never a bootstrap account's first record;
   - `AuthorityRecovery` with `authorization = 0x02` is refused outright on a class `0x01` account. A genesis-committed authority is replaced only by the key the genesis committed for that purpose, which is what L13.1 means by a genesis-committed threshold;
   - `DeviceGrant` and `DeviceRevoke` only on an account holding at least one unquarantined active device key;
4. its signature verifies against the preimage decision 4 fixes for that type, under the key the type names.

Acceptance is a compare-and-set. Two devices acting at once therefore produce one winner and one refusal carrying the current head, and the loser re-reads and decides again with the winner's record in view. There is no merge, no last-writer-wins and no state in which two chains exist.

**A pending record holds the slot, and conflicts resolve by rank.** A record inside an opposition window has already taken its `seq` (review finding 7). Without that, every delayed transition loses to an immediate one and an attacker holding any active device starves every revocation aimed at them, one cheap record per window.

Revision 2 made the freeze absolute, which was worse than the hole it closed: one intruder device could then keep an account frozen forever by cycling a grant and a revocation, and the rule blocked the owner's own escape hatch. The resolution is not new machinery. ADM-002 D2 already decides how competing transitions resolve, and this chain adopts it:

| rank | record |
| --- | --- |
| 2 | `AuthorityRecovery` signed by the committed recovery authority key |
| 1 | any record signed by an active device key |
| 0 | `AuthorityRecovery` authorized through account recovery |

A higher-rank record is accepted while a lower-rank one is pending, and cancels it. An equal-rank record is refused while one is pending. A lower-rank record is refused. Each cancelled initiation doubles the backoff of the key set that opened the cancelled one, which is ADM-002 D2's last sentence and is what stops the cancel itself becoming the attack. A `DeviceGrant` takes effect on acceptance and reserves no slot; its quarantine is a property of the granted device, not a pending record.

Rank 2 is therefore always reachable. That is the point: the one record the owner can always land is the one signed by the key they committed for exactly this, and it is not a key an intruder holding devices has.

### 4. Adoption

The sequence, and nothing may be skipped:

1. The account completes a normal login or OAuth flow. Control returns to the **native app**. A session that is still inside the web view cannot start adoption, which is the ADM-008:143 problem stated as a rule.
2. The app requires a **fresh strong step-up**, scoped to adoption and no older than the challenge in step 4, which is 15 minutes: a user-verifying passkey assertion, or the PIN where policy allows it. A step-up performed for a phone change or a PIN change does not carry over; O9 asks for a possession proof of *this* transition (review finding 10). The factor presented must itself be **past the fresh-factor hold** identity-service already enforces, measured on the credential's own creation time, and adoption is refused outright while the account's last completed account recovery is inside that hold (review finding 1). Without that clause the shipped recovery path mints an attacker-chosen PIN and adoption accepts it days later as proof of possession. The hold gates **starting** a transition and never **opposing** one: an owner who has just changed their PIN to lock a thief out must not be the one disarmed by it.
3. The app generates the device authority key and the recovery authority key on device, non-synced, in the platform keychain or keystore, per ADM-008 decision 5.
4. The server issues an **adoption challenge**: 32 CSPRNG bytes, minted once, held server-side against that account and that stepped-up session, single use, burned on acceptance and on refusal, expiring with the session and at or under 15 minutes.
5. The app signs the preimage **`"GUAA"` || the 32 challenge bytes || the canonical `AdoptRoot` bytes** with the device key it just generated. The challenge is inside the signature, not merely checked beside it (review finding 5). Revision 1 cited ADM-008 decision 6 and then dropped both halves of what makes it work, which reproduced the freshness defect ADM-008:151 already records against the genesis registration proof: a record signed with no server input is a precomputable, transferable artifact that proves possession of a key and nothing about when or where its holder was. The server builds the accountId in those canonical bytes from its own session state and reads none from the request, exactly as `GenesisProofs.attachProofPreimage` and `verifyAttachProof` do today.
6. The server records a **pending adoption** and notifies every channel the account has. At least one channel must be one that an account recovery cannot empty, and a log line is not a channel (review findings 1 and 2). The notification names the device label and the time the adoption will complete.
7. After the **opposition window** the adoption completes and the record joins the chain at `seq = 1`.

During the window the adoption is cancelled by any signed-in session of the account through `POST /account/authority/oppose`, which needs no factor beyond the session. Opposition is deliberately cheap the first time: at `seq = 1` the account holds no authority to weigh, so the honest veto is "someone who can already read this account's notifications says no".

**Bounds, so neither side can starve the other** (review finding 6). One pending adoption per account. An opposition cancels every pending adoption on that account, not only the one it names. A cooldown of one window before another adoption may be opened. A second and later opposition requires the opposing session to pass a step-up, on any factor the account holds and at any age, so a stolen bearer session cannot veto the account out of ever gaining authority while remaining account-equivalent itself, and an owner whose only factor is fresh can still object. An account holding no factor at all therefore gets one opposition and no more, which is harmless: adoption itself needs a step-up, so nobody can adopt that account either until it holds something.

Abandonment is defined at every step. A challenge that is never spent expires with the session. A pending adoption that is opposed is cancelled and its challenge burned. A pending adoption whose window passes with no opposition completes, because the alternative is an adoption that silently does nothing. A client that crashes between generating keys and submitting has produced nothing the server has seen; its keys are garbage and it generates new ones next time. Nothing leaves the account half-rooted: the chain either has a `seq = 1` record or it does not.

**Opposition window.** 72 hours in production. The window is the whole security of the transition (O9), so it is not configurable below 24 hours outside a testing flag, and it runs on service time until witnesses exist (ADM-002 R8).

### 5. The device set

After adoption the account's authority is the set of device keys the chain leaves active. `AdoptRoot` activates one. `DeviceGrant` activates another. `DeviceRevoke` deactivates one. `AuthorityRecovery` replaces the set with one.

**Adding a device.** The new device generates its own key and never receives another device's key. It registers that public key as a **candidate** under its own authenticated session, and the server hands back a short fingerprint of it. The granting device reads the account's candidates, shows the fingerprint, and signs a `DeviceGrant` over the candidate the user confirms. The fingerprint is what binds the key to the person holding the other phone, and it is the only thing crossing between the two devices that a human has to compare. Revision 4 adds this step because revisions 1 to 3 fixed both ends of the transfer and left the middle undefined, which left every client with a key it could not get to the signer.

An existing active device signs a `DeviceGrant` over it. A grant takes effect on acceptance, because it only adds, and its holder is **quarantined** until the opposition window passes: a device may not sign a `DeviceGrant`, a `DeviceRevoke` or an authority-sensitive approval while its own grant is inside its window. A quarantined device also **does not count** toward the active device a revocation must leave behind (review finding 3). A grant is opposable on the same terms as any other window, by any active device other than the one the grant names, and opposing it revokes the granted device immediately. Without that clause a borrowed unlocked phone grants a device and then self-revokes, which is two records, no delay and nothing to oppose, and the owner's own phone is left with no authority.

Copying one key to every device is rejected. It makes revocation meaningless, since the revoked device still holds the key the account is defined by, and it turns any single device compromise into a permanent account compromise with no way back short of recovery. A per-device key costs one record and gives revocation an effect.

**Removing a device.** `DeviceRevoke` signed by an active device. Revoking **another** device takes effect after the opposition window and is notified; any other active device may oppose it, **except the device the record names**, which may not veto its own removal (review finding 4). Without that exclusion an intruder who reached one grant keeps co-authority indefinitely against an owner who does everything right.

That exclusion has one carve-out, because revision 2's unconditional version handed the mirror-image power to the intruder: on an account with two active devices, where accepting the revocation would leave the **signer** as the only active device, the named device may oppose. A standoff between two devices is a worse outcome for nobody; an eviction the owner is forbidden to object to is a takeover. The standoff is broken by the rank-2 record of decision 3, which no pending revocation can block and no device can cast. Revoking **itself** takes effect immediately, because a device removing its own authority reduces what an attacker holding it could do, and delaying that helps nobody.

The chain refuses a revocation that would leave no unquarantined active device. An account with one device that wants to replace it goes through `AuthorityRecovery`, which installs the replacement in the same record.

**QR and device linking.** Today's QR flow (MSC4108, through the Matrix SDK) links a Matrix session. It authenticates nothing about account authority: the payload carries no signature, the trust root is a browser cookie and a two-digit human code, and MAS records which browser session approved, not which device.

Revision 5 corrects one sentence revisions 1 to 4 carried, because reading the SDK rather than the comment showed it was misleading. The check code **is** enforced: the secure channel compares it when the ceremony confirms, and a wrong code fails the whole ceremony with `InvalidCheckCode`. What the pinned SDK has no API for is a non-destructive local pre-check, and the client method that appeared to be one always returned true. So the binding the grant stands on is real, the method claiming to test it was a lie, and the fix is to delete the lie and read the ceremony's outcome, not to invent a check the protocol does not have. The cost of having no pre-check is that a typo and an attack are indistinguishable to the user, and both cost a fresh QR. This record does not change that protocol and does not put authority material in it. The grant runs alongside it, in **one direction only**: the authority device offers to sign a `DeviceGrant` only when it generated the QR itself and its user typed the check code displayed on the new device, and never when it merely scanned a code and displayed one (review finding 9). In the other direction the code binds a channel rather than a peer, and the key the authority device would be signing is whatever came up that channel.

### 6. The browser holds no authority, ever

A browser login grants account access. It never enters the device set, and no browser-held material may sign an authority record. This is a rule, not a default: there is no flag that lets a web session sign one.

Authority-sensitive actions reachable from the web create a `PendingApproval` carrying the accountId, the action digest and a 32-byte server challenge. The browser displays a four-character code from an unambiguous alphabet with no look-alike characters. Codes are unique among an account's live approvals, an account holds at most three at once, and an authority device refuses to present one while another is live (review finding 14). An active authority device fetches the pending approval, shows the same code and the action in the reader's own words, and signs the domain `gua-authority-approval.v1`, the accountId, the pending id, the action digest and the challenge. The browser never learns a key and never proxies one. An approval is single use, expires in 10 minutes, and its challenge is burned on refusal as well as acceptance.

A malicious page can therefore start an approval the user never wanted, which is exactly what the code and the device-side description defend: the approval names the action on a screen the page does not control.

### 7. Losing the device

**Another active device survives.** The surviving device signs a `DeviceGrant` for the replacement and a `DeviceRevoke` for the lost one. No wait beyond the revocation window, no recovery, no SMS.

**Otherwise, `AuthorityRecovery`** installs a new device key and a new recovery authority key in one record. It is authorized in exactly one of two ways, and they are not equal:

- **Signed by the committed recovery authority key** (`authorization = 0x01`). This is the L13.1 genesis-committed threshold at `t = 1` under framework `0x01`. It is notified and takes effect after ADM-002 D1's Δr for framework `0x01`, not the adoption window (review finding 15). An active device cannot cancel it, because L13.3 forbids making the possibly stolen active key the veto. An active device's opposition extends the window once and raises the notification, and nothing more.
- **Through account recovery** (`authorization = 0x02`), the delayed path ADM-002 owns and identity-service ships. This one **is** vetoable by any active device, immediately, because there a surviving device is the stronger evidence. It runs after recovery's own dormancy and wait, and then the authority opposition window on top.

**Both paths carry adoption's controls.** Revision 2 bolted every new control to `AdoptRoot` and left this record as it was, which meant one magic byte reached the same seizure by a shorter route. `AuthorityRecovery` is submitted from the native app, against a server challenge inside its preimage, after a step-up scoped to that operation and no older than the challenge, on a factor that is itself past the fresh-factor hold, and it is refused while the account's last completed account recovery is inside that hold. Path `0x02` additionally cannot exist on a class `0x01` account at all, by decision 3 rule 3.

Neither path is gated on the account having no active device. Revision 1 gated the second one that way, which left the ordinary lost-phone case with no path at all, because a lost phone stays active in the chain until something revokes it, and made a remote wipe terminal (review finding 8). The immediate active-device veto is what protects that path, and it does not need a precondition the chain cannot observe.

**Deterministic priority (L13.2).** While an `AuthorityRecovery` is pending, decision 3's slot rule already freezes the chain. Between the two paths the order is fixed and not a race: a recovery signed by the committed recovery authority key **outranks and cancels** one authorized through account recovery, at any point before that one completes (review finding 11). The weaker path must never preempt the key the account committed for exactly this purpose. The cancel is bounded the way ADM-002 D2 bounds it rather than left free: each cancelled initiation doubles the backoff of the key set that opened the cancelled one, and a recovery-key holder who cancels repeatedly pays that backoff on their own next initiation. One pending recovery per account, a fixed window, and a cooldown of one window before the same key may open another.

**Unrecoverable is a permitted answer (L13.4).** An account that loses every device and its recovery authority key keeps its accountId, its login and its data, and never regains authority. It may not adopt again: a second adoption authorized by login factors alone is precisely the seizure O9 rejected, and an attacker who reaches the login factors of a rooted account must not be handed its authority. Because that end state is permanent, adoption **requires** the user to take the recovery artifact: the recovery authority key is shown once, the app confirms the user has stored it, and adoption is refused without that confirmation. The copy that shows it says plainly that whoever holds it, together with a way into the account, can take it after a wait.

### 8. What recovery may and may not do to authority

Completing an account recovery resets login factors. It does **not** move authority on its own, it does not revoke devices, and it does not mint a device key. Its only reach into this chain is the second authorization path in decision 7.

The two clocks **compose rather than run independently**, and revision 1 was wrong to claim otherwise (review finding 1). Account recovery deletes every passkey, sets a caller-chosen PIN and revokes the account's sessions in one transaction. That is the same transaction that empties the signed-in-session channel the adoption window relies on and leaves the phone as the only surviving channel. Decision 4 step 2's fresh-factor hold and step 6's channel requirement exist because of that composition, and they are what keep the total cost of a SIM swap at recovery's own clocks plus the hold plus a window on a channel the attacker does not hold.

### 9. SMS possession authorizes nothing here

No record in this chain is accepted on the strength of a phone code, in any combination, at any step, including adoption. The phone's only role is as one notification channel among several.

The guard has to be wider than the adoption endpoint, because the laundering path in decision 8 never presents an OTP to an authority endpoint at all. Enforcement is three rules in the source: no authority endpoint may reference the OTP services; `AuthFactor.PHONE_OTP` may not appear in any accepted set for an authority operation; and no authority-granting record is accepted on a factor inside the fresh-factor hold, or while the account's last completed account recovery is inside it.

The third rule is the one that carries the weight, and it is stated on the account rather than on the session on purpose. A session's completing factor is server-side login state that a bearer-authenticated endpoint cannot observe, and the attack re-logs in normally anyway, so a rule written about `SessionFactor.RECOVERY` would be inert. The account needs a `recovery_completed_at` stamp for this, which it does not have today: `pin_reset_requested_at` is cleared on completion and `pin_set_at` cannot tell a recovery from an ordinary PIN change.

### 10. State and transitions

| state | meaning | leaves by |
| --- | --- | --- |
| `BOOTSTRAP` | class `0x00`, chain empty | adoption start |
| `ADOPTION_PENDING` | `AdoptRoot` held, window running, slot reserved | completion, opposition, expiry |
| `ROOTED` | at least one unquarantined authority key, committed by the accountId or activated by a record | grant, revoke, recovery |
| `RECOVERY_PENDING` | `AuthorityRecovery` held, window running, slot reserved | completion, veto where permitted, supersession by the recovery-key path, expiry |
| `AUTHORITY_LOST` | rooted, no active device, no recovery key | nothing. Terminal by decision 7 |

A class `0x01` account is `ROOTED` from creation with an empty chain: its genesis authority key is its first device key, committed by the accountId itself rather than by a record, and its chain starts at `seq = 1` with its first `DeviceGrant` or with an `AuthorityRecovery` signed by its committed recovery key. `AdoptRoot` is refused on such an account, and so is the account-recovery path, both by decision 3 rule 3. That pair is what stops a genesis-committed authority being replaced on login factors alone (review finding 16). `ROOTED` is therefore a statement about keys rather than about chain length, which is how a verifier tells a class `0x01` account with an empty chain from a bootstrap one.

### 11. Compromise conditions

What an attacker must hold for each transition to succeed, stated so that a review can attack the claim rather than the prose:

| transition | requires | and survives |
| --- | --- | --- |
| adopt | a live native session, a step-up scoped to adoption, minted more than the fresh-factor hold ago, on an account whose last recovery is also outside that hold, the device that generates the key, the server's challenge inside the signature, and a full window with no opposition | a SIM swap now costs recovery's dormancy and wait, then the fresh-factor hold, then a window. Whether the owner hears about that window depends entirely on gate 2: with only the channels the server has today, a SIM-swap attacker holds the phone and recovery emptied the sessions, so the window is unwitnessed. That is why gate 2 blocks production rather than being an aspiration. A captured request body is useless: the challenge is burned and bound to one stepped-up session. A record built for another account is refused by decision 3 rule 2 |
| grant | an active, unquarantined device key | a stolen unlocked device wins this and gains a quarantined device, which can do nothing, counts for nothing, and cannot be used to strip the owner |
| revoke other | an active device key, and the window without opposition from an active device other than the target | the target cannot veto its own removal, and an account cannot be left with no unquarantined device |
| revoke self | the device's own key | by design, no delay, and it cannot be the last unquarantined device |
| recovery by recovery key | the committed recovery authority key, a session of that account to submit under, a scoped step-up on a factor outside the hold, and ADM-002 D1's Δr | a thief holding every device cannot cancel it, and it cancels a weaker recovery aimed at the same account. The artifact alone is not enough, which is narrower than revision 2 claimed |
| recovery by account recovery | the login factors, recovery's own dormancy and wait, the authority window, and no active device choosing to veto | a SIM swap plus a factor reset reaches this only against an owner with no device left to say no |
| approval from a browser | an active device's signature on that exact action digest | a malicious page reaches the pending approval and not the signature |

### 13. The security notification channel

Gate 2 says a pending transition must reach the account holder out of band. This is what that means.

**Why not the obvious channels.** The account's phone number is the channel a SIM-swap attacker holds. A signed-in session is what account recovery revokes: completing one ends every session of the user, so a Matrix pusher, which exists only under a session, dies in the same transaction that mints the attacker's PIN. A log line reaches nobody. The channel therefore has to be a registration the identity service owns, tied to the app installation rather than to a session, and delivered by the platform transports.

**Installation identity.** The client generates 128 bits of randomness on first use and keeps it in the keychain or the keystore, never in preferences and never derived from a device identifier the platform also gives to anyone else. It survives sign-out and sign-in, and it identifies the installation, not the person: a reinstall is a new installation and gets a new one.

**What a registration holds.** The account, the installation id, the transport and its destination token, the app identifier that selects the topic or project, a short device label, and optionally the authority device key of the install. The server also keeps a fingerprint of the token so an audit line or a support conversation can name a registration without printing it, when the row was last seen, and a count of consecutive permanent delivery failures. It holds no address, no phone number, no Matrix device id: that id is session-scoped, which is the lifecycle this row exists to escape.

**Binding.** An install that holds an authority device key proves it, rather than claiming it. It signs

    "gua-authority-notification.v1" || accountId (34) || SHA-256(installation id) (32) || deviceKey (32) || challenge (32)

with that key, across a challenge the server minted for the notify purpose and burns on use. The installation id is hashed rather than carried, so the signature binds the install without putting a durable correlator inside a signed object. An install with no authority key may still register, and its row is simply unbound.

**Replacing a destination.** A registration that reports the same token again refreshes freely, which is the ordinary case of an app coming back to the foreground. A registration that reports a **different** token for an installation the account already holds is a destination change, and it is refused unless the binding above is presented over a fresh challenge. Without that rule an upsert on a caller-named installation id silently repoints the owner's alerts at whatever destination the caller likes, which the code review demonstrated. An account that holds no authority device cannot present the binding and must remove the registration and make a new one, which costs what every removal costs.

**Removal.** There is exactly one tier. Removing any registration needs a step-up on a factor that is itself outside the fresh-factor hold, and, where the row carries a device key, a signature by a key the chain has active and unquarantined. There is deliberately no cheaper path for "my own install": a self-asserted installation id is a request-body field, and the review showed that accepting it hands the whole channel to any session. Every removal is announced to the registrations that remain, so stripping the channel is loud until the last row is gone. There is no bulk removal.

**Lifetime.** A row lives while it is seen. Past a configured life, far longer than any window, an unseen row stops being notified and is swept. A destination the transport reports permanently unregistered is retired after a small number of consecutive failures. Deactivating the account removes its rows, because there is no longer anyone to warn.

**Reinstall and lost app data.** Both produce a new installation and a new row, and leave the old one behind until it ages out or its token is reported dead. The account is briefly reachable at two destinations, which is the safe direction: the failure this channel guards against is having none.

**Privacy, stated rather than implied.** This is a durable identifier that ties one account to one physical installation across sign-outs, sitting next to a push token, in a service that until now held neither. It is the cost of a channel a session revocation cannot empty, and it must be named in the product's privacy copy rather than left for someone to discover. Nothing else in the service reads these rows, and no notification body carries an accountId, a phone number or any message content: a label, the transition, and when it completes.

**Compromise condition.** To silence the channel an attacker must pass the same step-up every removal takes, on a factor older than the hold, and where the row is bound also hold an active unquarantined device key. A fresh post-recovery session satisfies none of those: its PIN was minted inside the hold, and the recovery it came from conferred no device. To redirect the channel instead, it must present the binding signature, which needs the same device key. What it can still do is register an install of its own, which adds a destination and removes none.

**What this does not close.** On an account with exactly one installation, that installation is the one performing the transition, so a thief holding the unlocked phone receives the alert about their own transition. The channel makes the owner reachable wherever they still have an install; it cannot invent a second one.

### 12. Reserved, and deliberately not decided here

An `ACCOUNT_AUTHORITY` log leaf carries the chain head. A settled head, never one inside an opposition window, is published as a signed `gua-account-authority-head.v1` object, the log commits the hash of its canonical bytes, and a verifier checks an audit path against a checkpoint the roster signature covers. A head that the log does not carry is refused, as is one under another account and one from a homeserver that is not the account's publisher.

**What that buys, and what it does not.** A head can no longer be invented for a reader who checks, and the log cannot be rewritten under a client that keeps its own checkpoint. Three things remain open, and O9 does not close on any of them:

- *One trust domain.* The publishing key is the chain-storing homeserver's own roster membership key, and one deployment holds the private half of every homeserver's membership key. A dishonest homeserver can publish a head it made up for an account it holds and every check passes. The leaf makes that act permanent and attributable rather than deniable, which is worth having and is not the same as preventing it.
- *Equivocation.* The log's root is recomputed over live rows with no witness co-signature and no checkpoint gossip, so two readers can be served two self-consistent views. That is ADM-005's to fix and is out of scope here.
- *Withholding.* Nothing compels publication, and with no non-membership proof an omitted head is indistinguishable from an account that never transitioned.

So a class `0x00` account's authority is now an assertion by its homeserver that is **committed and checkable**, rather than one a reader must simply accept. Until the three above are answered, no copy in any client and no README may say more than that.

Decision 3 rule 2 needs one implementation note, because `AccountIdNotReadGuardTest` fails the build if the login session, the security controller or the claim builders so much as name an accountId. The server resolves it from the authenticated user id through `account_genesis`, inside a new file added to that test's allowed set, and the login path still never learns one.

The hardware-resident P-256 suite that ADM-008 reserved is not defined here. Framework `0x02` is ADM-002's. Multi-party thresholds above `t = 1` are not decided: every rule here is written so that a threshold larger than one narrows it rather than reshaping it.

## Implementation gates

1. No endpoint in this record ships enabled. Server and both clients gate on their own off-by-default flags, as Phase 3 does.
2. **No endpoint ships at all until pending authority transitions have the channel decision 13 defines, running on a real transport.** `DeviceNotificationService` has one implementation today and it writes a log line, which is not a channel (review finding 2). The phone is not sufficient either, because it is the channel the SIM-swap attacker holds, and sessions are not, because recovery revokes them in the same transaction that mints the factor. Every window in this record is theatre without a channel that survives both, because the owner is never told.
3. Production adoption stays refused until ADM-002 Q6 answers the independence question, which is also ADM-008 decision 4's gate. D1 fixes `Δr` and `Δp` at 7 days for framework `0x01`, so the bounds are no longer what is open. Dev may adopt behind the testing flag and treats those accounts as disposable.
4. The three guard rules named in decision 9 exist before the first endpoint does, and the `recovery_completed_at` stamp the third one needs is added with them.
5. Two capabilities the shipped code lacks are prerequisites rather than nice-to-haves. The account must be able to remove **one** passkey credential: today `PasskeyService` exposes only `removeAllForUser`, so an owner locking a thief out of a stolen device has to wipe every credential, which is what puts their own remaining factor inside the hold. And the account holder must be able to read their own `accountId`, which no endpoint returns today, because the client signs over its 34 bytes.
6. This record closes O9 only when its adoption path is implemented, reviewed, published under the leaf of decision 12, and checkable by a party that is not the homeserver storing the chain. The first three are done or in progress; the fourth is not, for the reasons decision 12 now states, so O9 stays open and this is its proposed answer.
