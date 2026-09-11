# ADM-006: Matrix identity portability

> **Status: Proposed, not frozen.** It closes when the product owner signs off H0 and its promise. The H1 promise stays draft, gated on the blockers below.

## Context

ADM-001 fixed:

- L3: an identifier is an account attribute; superseding it transfers nothing.
- L9: no native Matrix operation preserves device keys, cross-signing, membership, history attribution or key backup across homeservers. Placement and identity migration are separate, and any Gua tooling claim needs its own demonstration.
- L5 and L6: account authority buys migration authorization; placement never commits without `HostingAcceptance`.

ADM-001 left open O9 (`ADOPT_ROOT`), S6 (OIDC subject migration) and the L13 recovery mechanism. The migration plan puts identity migration out of scope.

Facts:

- F1. An MXID embeds its server name, and events carry that server's signature in `sender`. MAS usernames are write-once (L9 [CODE]).
- F2. Room version 12 ships in spec v1.16. MSC4289 makes creator power unlowerable; MSC4291 derives room IDs from the create event.
- F3. `POST /rooms/{roomId}/upgrade` names the whole `additional_creators` set up front, so creators are not copied. The upgrading user becoming creator is standard but unverified.
- F4. MSCs 1228 and 4014 are open and need a new room version. Open draft MSC2787 changes sender, signatures and auth rules. MSC2783, the migration format, is abandoned.
- F5. Gua UI strips the homeserver from handles and avoids Matrix vocabulary. The OIDC subject is the full MXID.

## Scope

In: what a move means per horizon, the user promise, tooling constraints, placement claims, and the first step.

Out: identifier change (L3), recovery (L13, O5), whole-homeserver relocation, and Synapse or MAS forks.

## Requirements

1. No Gua record, tool or copy claims Matrix-level continuity across a move (L9).
2. A move changes no binding and no `accountId` (L3, L4).
3. Only the account authority authorizes a move (L5). Bootstrap accounts cannot move until O9 closes, since an operator-initiated move is the seizure O9 describes.
4. A move is a sequenced generation g+1 placement, never a session grant (L2, L11). The destination accepts it through the L6 anti-orphan job, applied to g+1.
5. The destination authenticates the person from scratch (L2).
6. Tooling runs on the user's devices over the client-server API, with no admin API (L2). It assumes no cross-operator trust (standing rule).
7. User copy uses no server, room or Matrix ID vocabulary (F5).
8. The old MXID is never reissued to another person (F1, L3).
9. A move can be abandoned without loss until the source deactivates (product fact: a failed move must not cost conversations).

## Options considered

**A. No per-account move.** Placement stays at generation 1. Capacity changes relocate whole servers, keeping every MXID and key. Satisfies all nine until a cross-operator, regional or legal need appears.

**B. New MXID with re-establishment tooling.** The destination creates a new account for the same `accountId`. Device-side tooling recreates conversations, roles, account data and readable history. Designed to satisfy all nine; Q1 to Q7 and SP1 to SP5 must confirm it. Residuals: peers re-verify, and old messages keep the old sender. Version 12 rooms keep the old creator unless upgraded, and each upgrade moves every member to a new room id. Spec key exports bind no user or device, so keys import into a new account.

**C. Rename, or share one server name.** Sender-server signatures make a renamed sender fail auth. A shared name means shared keys, making two operators one principal. Rejected under 1 and 6.

**D. MSC-based portability.** Real continuity, but it needs a merged MSC, a room version, Synapse and MAS support, and every Gua room upgraded (F4). Not schedulable. AT Protocol portability works because identity is DID-rooted (Kleppmann et al., CoNEXT DIN '24).

## Decision or narrowed choice

**H0, decided now: option A.** Gua offers no per-account move, and no current requirement needs one.

**H1, narrowed, not built: option B.** Triggers: a second operator, or a regional or legal placement requirement.

**H2, watched: option D.** Trigger: a merged portability MSC with Synapse support and an adoptable room version.

**User promise.** H0, for sign-off: moving is unavailable; a user-initiated number change keeps the account, chats and contacts. Recovery onto a number under ADM-002 P4 is not that. H1, draft and conditional on SP1 and SP4: the user keeps their number, account, contacts, chat list and earlier messages on their devices. Contacts confirm the person again. Earlier messages keep their original sender and show as unconfirmed. Never promised: "seamless" or "the same identity".

**Tooling constraints (H1).**

- Device keys are never copied; the new account generates fresh ones.
- Cross-signing starts from a new master key; peer verification does not carry over at H1.
- The old account invites the new one, grants its power level, and in version 12 rooms it created empowers it to upgrade (F3).
- History is never rewritten or re-sent. Attribution stays with the old MXID.
- Pending Q3, the tool exports Megolm sessions on device, imports them, and rebuilds the backup under new secret storage. Imported keys decrypt only what history visibility lets the new account fetch. MSC4268 (merged) shares past keys on invite; Gua relies on it only after an SDK spike (L9).
- Gua strips the homeserver, so old and new MXIDs can share a displayed handle. H1 resets verification, so it cannot separate a successor from an impostor. Disambiguation stays open under SP5.

**Placement record.** Must carry `accountId`, destination member id, generation, predecessor hash, account-authority signature, destination `HostingAcceptance` and sequenced time. Must not carry an MXID; login yields it. Must not claim continuity of keys or verification (Requirement 1), or serve as a rename or credential.

**Succession, narrowed.** Candidates: (i) no statement; (ii) an old-master-key notice in shared conversations, as in XEP-0283; (iii) an account-authority statement in federation state. Proposed: (ii), informational only, with no trust transfer. (iii) would put the old-to-new MXID link into replicated state.

**First step: documentation and a product decision, no code.** The product owner signs off H0 and its promise only. The H1 promise stays draft until SP1 and SP4 report.

## Blockers for production

Questions gating H1:

- Q1 (cryptography). Should peer verification ever carry across a move? Candidate: never at H1.
- Q2 (threat model). A holder of a stolen old master key or account authority could appoint a successor. Is a sequenced delay D, notice to every device of the old account, and veto by the L13 item 3 precommitted authority (never the old master key) sufficient before a successor activates?
- Q3 (cryptography). Does importing Megolm sessions into an account absent when they were used weaken any property peers relied on? Does MSC4268 change that?
- Q4 (distributed systems). Does this ordering never route to an account that cannot sign in: pending g+1 commit with a sequenced expiry, destination first login, sequenced activation, then source deactivation? Is expiry without activation a safe revert to generation g?
- Q5 (distributed systems). The source homeserver keeps creator power in tombstoned version 12 rooms. Can it mislead clients or late joiners with a competing tombstone?
- Q6 (distributed systems). Under L13 item 2, is it correct that a pending recovery blocks move initiation, and that recovery initiation cancels a pending move?
- Q7 (privacy). Who learns the old-to-new link under B? Candidate: every server in a shared room.

Spikes on dev and dev2:

- SP1 (R9, history promise). Move a test account. Pass: the new account joins every prior conversation, messages readable before stay readable in `shared` rooms, and clients mark imported history as unconfirmed. Fail: any silent loss.
- SP2 (F3). Creator handoff. Pass: the new MXID sends the successor's create event, the old MXID is not a creator, and members receive the tombstone.
- SP3 (R4, R9). Ordering. Pass: routing never points to an account that cannot sign in, even after an abandoned move.
- SP4 (history promise). History-visibility defaults on both clients. Pass: documented, and `shared` confirmed or the promise narrowed.
- SP5 (R1). Display. Pass: no client presents old and new MXIDs as one verified person without re-verification.

## Implementation implications

H1 only; H0 changes nothing.

- Services. gua-resolver stores g+1 placements with a predecessor chain and pending state. The destination MAS creates the user at first login, under an upstream link whose subject is not the source MXID (S6). The source deactivates through `POST /account/deactivate`, never the admin API.
- Data. ADM-008 fixes `PlacementRecord` v0x01 at generation 0x01, signed by the holding homeserver's roster key. The g+1 record above is a new version, superseding ADM-008's rule that the resolver rejects a record naming another homeserver.
- Order. Plan Phases 3 and 4, then O9 and S6, then Phase 7, then tooling. Requirement 5 holds only after Phase 7 moves authentication to homeservers. H1 also waits on ADM-008 decisions 8 and 9, since routing must read a placement record.
- Tests. The resolver rejects a g+1 record lacking the account-authority signature, naming a non-member, or with a wrong predecessor hash. Copy review closes R1 and R7; a reissue test closes R8. SP1 to SP3 run end to end.
- Rollback. Before deactivation, a sequenced cancellation revokes the pending placement. Afterwards there is no protocol rollback, so deactivation follows confirmation and a cooling period, both sequenced inputs (L11).

## Relationship to ADM-001

Applied: L9 to claims, L3 and L4 to bindings, L5 and O9 to authorization. L2, L6 and L11 govern the g+1 placement, under O2 and S6. No mechanism is proposed for O9, S6 or L13. ADM-008 is Accepted; only its generation-1 record version and same-homeserver rejection rule would be superseded at H1. Nothing locked is reopened.
