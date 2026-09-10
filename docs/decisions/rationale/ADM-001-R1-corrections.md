# ADM-001-R1: correction pass

Status: **corrections for review.** Not an approved design, and not the human-readable architecture document.
Scope: the eleven defects raised against ADM-001, corrected against the memo and against `main`.
Method: four narrow correction tracks plus one code-verification agent, each attacked adversarially. **All four correction tracks failed review again.** What follows is what survived that second round, plus the residuals named honestly.

Tags: **[CODE]** verified against `main` or live config. **[TARGET]** a property the protocol should guarantee.

---

## 0. Stop the presses: a live authentication bypass

Found while correcting item 11, verified by reading the source myself rather than accepting the agent's claim.

**[CODE]** `GET /oauth2/authorize` has a legacy non-interactive branch. If `phone_number` and `otp_code` are both present it skips the interactive flow entirely and issues an authorization code.

```java
// OidcAuthorizationController.java:92-106
// "Legacy non-interactive flow: credentials supplied directly as query params.
//  Retained for backward compatibility"
if (phoneNumber != null && otpCode != null) { ... issueAuthorizationCode(request) ... }
```

What that path checks, in full:

```java
// OidcAuthorizationService.java:42-67
otpService.verifyOtp(request.phoneNumber(), request.otpCode());
...
String userId = existingEntry.map(DirectoryEntry::getUserId)
        .orElseGet(matrixProvisioningService::generateOpaqueUserId);   // creates an account
directoryService.upsertByDigest(...);
return issueCode(authorization, ...);
```

There is **no PIN check, no passkey check, and no registration guard.** It also provisions an account when none exists.

And it is reachable without a client secret: `/oauth2/**` is `permitAll`, and the `gua-ios` client is declared with no `client-secret` line at all, so `publicClient` is true and `authenticateClient` returns immediately.

> `SecurityConfig.java:35`; `application.yml:144-147`; `OidcClientService.java:43, 106-108`

**Consequence.** Anyone who can receive one SMS for a number obtains an OIDC authorization code for that account. Every factor above SMS possession, PIN, passkey, trusted device, is bypassed, not weakened. PKCE is required for that client but does not help: PKCE binds the code to the requester, and the attacker *is* the requester.

**This is the real I4 violation.** ADM-001 blamed the OTP code for being a bearer secret, which item 11 correctly says is not a violation. The violation is this endpoint converting identifier possession directly into a session grant, with no homeserver in the loop at all.

**Recommendation: delete the branch.** Not deprecate, not gate. It is labelled "retained for backward compatibility" and the clients that shipped since use the interactive flow.

---

## 1. Corrected invariants

**I4 (narrowed, replacing the overreach).**
> A federation-issued identifier-ownership artifact must never be accepted as a login credential or session grant. Ordinary homeserver-local authentication using a short-lived bearer secret, such as an OTP, does not violate this.

The test to apply to a flow, which is what makes this operational rather than a slogan:
1. Was the artifact issued by a federation-scope component?
2. Does any party accept it as evidence that *this human is present now*, rather than as evidence about *who owns an identifier*?
3. Could a party holding only that artifact obtain a session at a homeserver?
4. Does the homeserver still independently authenticate after receiving it?

A "yes" to 3, or a "no" to 4, is a violation. Section 0 fails 3 and 4.

**I5 (restated as a protocol invariant, per identifier, not per routing key).**
> At most one `ACTIVE` binding exists per *identifier*, across all routing-key epochs, established by a deterministic state transition over an ordered log, auditable by any observer from published rejection leaves. Storage constraints are an implementation mechanism, never the security model.

The per-identifier wording is not pedantry. See attack A2 below: stating it per *routing key* is satisfiable while one phone number holds two live accounts.

**I8 (replaced entirely). Trust domains, not key counts.**
> Every guarantee states its compromise condition as one of: different key, different process, different operator or trust domain, governance threshold. Two keys held by one operator are one principal.

**I9 (new).**
> An identifier is an *attribute* of an account, never the account. Supersession removes an attribute; it never transfers an account, its history, its credentials or its placement.

**I10 (new).**
> The account root key is a *continuity authority*. It is not a login credential and not a recovery authority. Loss of the root key must never mean loss of the account.

---

## 2. Corrected protocol and data structures

### 2.1 Initial placement authorization (item 1)

The two candidates are **not alternatives**. Recommendation:

- **B1 ships first and is retained permanently as the floor**: the `IdentifierBinding` commits to an `initialHomeserverId`, inside the verifier's signature.
- **A is the target ceiling**: `accountId = H(rootAlg || rootPublicKey)`, and generation-1 placement requires an account-root authorization *plus* destination acceptance.

**Rule, at every generation:** a homeserver signature alone never creates a placement. Generation 1 requires an authorization from outside the set of homeserver membership keys.

**Honest limitation of B1, which the reviewer found and I am not going to bury.** For a rootless account, `initialHomeserverId` sits inside the binding, so the "two records signed by two different principals" separation does not exist: it is one record, one key, one party. That is 100% of accounts today and most accounts at launch. **B1 makes the claim auditable rather than preventable.** Real prevention needs a root key, which is what makes A the ceiling rather than a nicety.

**A second B1 defect, no attacker required.** Rule ordering is knotted: the binding commits to a destination before that destination has accepted, and acceptance is only required on `MIGRATE`. Worse, the destination drifts: `WeightedFallbackRule` seeds its bucketing with the roster version, and roster version is the transparency-log size, so it increments on every policy publish and every directory checkpoint. The homeserver the engine names at binding time and minutes later are routinely different. **[CODE]** `AuthorityRosterStore.java:67`, `WeightedFallbackRule.java:71`.

So B1 needs either a short binding-to-placement validity window with explicit destination pre-acceptance, or the destination must be chosen by the claimant from a policy-signed candidate set rather than by a drifting engine. **Open, see section 5.**

**`accountId` derivation is now decided:** `accountId = H(rootAlg || rootPublicKey)`, not opaque random. This resolves your explicit hold. The consequence binds increment 4: populate the derived form or populate nothing, because switching random to derived later is a migration of the very identifier introduced to be stable.

### 2.2 Number recycling (item 2)

Resolved by I9 plus I10. Superseding a binding for phone `P` removes an *attribute* from Account A and creates a new binding for Account B. It transfers nothing. Account A keeps its Matrix identity, history, credentials and placement, and simply has one fewer identifier.

For an account **with** a root key, supersession additionally requires either the incumbent's consent or a dispute window with device notification.

For an account **without** a root key, the honest floor: the account is not taken, but it may become unreachable by that identifier, and if the identifier was the only way its contacts found it, that is a real product harm with no protocol remedy. Say so in the product, and push root-key adoption.

### 2.3 Uniqueness, ordering and state (items 3 and 4)

**Target shape:** one distinguished sequencer, replicated read state, independently witnessed checkpoints.

- **Security depends on** the sequencer not equivocating. Independent witness co-signing of `(logRoot, stateRoot)` closes this, *provided witnesses are a different trust domain*.
- **Liveness depends on** the sequencer not censoring. Witnessing does **not** close this. A censoring sequencer is detectable but not routable-around.

**When BFT becomes justified:** only when the federation must accept *conflicting writes without a distinguished sequencer*, that is, when no single party may be trusted even for ordering. Nation-scale traffic alone does not require it; a governance model where members refuse to accept any sequencer does. State that trigger explicitly rather than "when we get bigger".

**Current-state layer:** append-only mutation log **plus** an authenticated map, with a checkpoint carrying `(logRoot, stateRoot, seqTime)` and witness signatures. `/resolve` returns a membership proof, a non-membership proof, a placement proof, and the co-signed checkpoint for freshness.

### 2.4 Registries (item 8)

`verifierAccreditations[]` moves out of `MembershipEpoch`. A verifier rotation must not be conceptually a membership epoch, or rotations become rare and frightening.

```
GovernanceRoot
  ├── HomeserverRegistry    (membership epochs)
  ├── VerifierRegistry      (accreditations, own version line)
  ├── PolicyRegistry
  └── WitnessRegistry
```
Independently versioned, rooted in common checkpoints so a client verifies one registry without fetching all.

### 2.5 Homeserver identity continuity (item 9)

`homeserverId` **references** `hsKeyId`; it is not itself the key hash. Making the id *be* the hash forbids key rotation without changing identity, which is worse.

Continuity rule: admission with a domain/control proof and a **retained** genesis commitment; normal rotation signed by **both** old and new keys; revocation; and re-admission that does **not** restore the old identity or its accounts by default.

**The unresolved hole is lost-key recovery**, and it is exactly where a governance authority could silently substitute a genesis key while keeping the logical member identity. Any recovery path that governance alone can execute reintroduces the attack item 9 asks to close. See section 5.

---

## 3. Attacks that still work

**A1. The live OTP-to-session bypass.** Section 0. Defeats every rung of any assurance ladder below a root key. **Compromise required: none. One SMS.**

**A2. VOPRF epoch rotation defeats uniqueness.** If routing keys are epoch-scoped, one identifier has two routing keys during an overlap. A binding under `rk_8` sees an empty map slot, is accepted, and the `rk_7` binding stays `ACTIVE`. Two clients on different epochs get valid inclusion proofs for different accounts **against the same stateRoot in the same co-signed checkpoint**. Nothing is violated, nothing is detectable, because the invariant was stated over the wrong object. Fixing it needs an in-fold link between `rk_e` and `rk_{e+1}`, and **only the OPRF key holder can compute that link**, which reintroduces exactly the central linkability blinding was meant to remove. **This is a genuine unsolved tension, not an oversight.**

**A3. Revoke, re-admit, re-place against rootless users.** A revoked member's accounts have no root authorization, so nothing binds them to their placement independently of the member. **Compromise required: governance threshold.**

**A4. Everything bottoms out at first use.** The same defect that produced the generation-1 hole recurs at every layer: `GovernanceRoot` v1 has no predecessor and is signed by the very keys it enumerates; the VOPRF public key is anchored to nothing on first contact; witnesses are accredited by the authority, so "w independent witnesses" collapses to the authority. **You cannot bootstrap trust from inside the system.** The architecture must name exactly one out-of-band root, pinned in clients at build time, and derive everything else from it. Pretending each layer adds independence when one operator signs all of them is the error running through both memos.

**A5. Today, every independence guarantee reduces to "compromise Gua."** One operator is the authority, the only verifier, the sequencer, every witness and every homeserver. This belongs in each guarantee line, not in a caveat below it.

---

## 4. Decisions to lock now

1. **Delete the legacy non-interactive `authorize` branch.** Highest priority in either memo.
2. **Delete `POST /directory/entries`.** Unchanged from ADM-001 D1.
3. **I4 in the narrowed form, with the four-question test.** Correct the section 1 table row: the violation is the authorize branch, not the OTP.
4. **I5 stated per identifier, over an ordered log, not as a database constraint.**
5. **I8 replaced by trust-domain reasoning throughout**, with today's honest reduction stated inline.
6. **I9 and I10** as written. These are what make recycling survivable.
7. **`accountId = H(rootAlg || rootPublicKey)`.** Not opaque random.
8. **B1 as the floor, A as the ceiling**, with B1's limitation stated rather than papered over.
9. **Registry separation** under a `GovernanceRoot`.
10. **`homeserverId` references `hsKeyId`**, with rotation co-signed by old and new keys.
11. **Strike from D5:** "Matrix `user_id` becomes derived and mutable." See section 6.
12. **Name the single out-of-band trust root** and pin it in clients. Nothing else in the design has meaning until this exists.

---

## 5. Decisions that remain open

1. **A2, the VOPRF epoch/uniqueness tension.** Either accept per-epoch uniqueness with a linking authority, which concedes central linkability, or do not rotate, which concedes the pepper problem. I do not have a third answer. **This is the most important open question in the memo.**
2. **B1's destination binding**, given policy drift: short validity window with pre-acceptance, or claimant selection from a signed candidate set.
3. **Lost-key recovery for a homeserver**, without giving governance a silent substitution path.
4. **Whether witnesses can be a real trust domain** before a second operator exists. If not, witness machinery is theatre until then and should be deferred rather than built.
5. **Client pinning semantics.** Unchanged from ADM-001, still open, and made sharper by A3.
6. **Recovery for rootless accounts**, which is most accounts.

---

## 6. Minimal diff to ADM-001

**§0**: add section 0 above as a new first item, ahead of the `/directory/entries` finding.

**§1, I4 row**: replace "Violated. The OTP code is a bearer token for the account" with:
> Violated. `GET /oauth2/authorize` converts identifier possession directly into an authorization code with no PIN, passkey or registration check, on a public client. The OTP being a short-lived bearer secret is not itself the violation.

**§1, I5**: replace with the per-identifier wording in §1 above.

**§1, I8**: replace with the trust-domain wording. Add I9 and I10.

**§2, T1/T3/T5/T7**: append to each: today, one operator holds every role, so the condition reduces to compromising Gua. Keep the structural statement as the target.

**§3**: replace the squatting trace's step 4 justification. It currently says placement requires an `ACTIVE` binding; that is necessary and not sufficient. Add: generation-1 placement requires authorization from outside the homeserver membership key set.

**§4**: `accountId` derivation becomes `H(rootAlg || rootPublicKey)`. Add `initialHomeserverId` to `IdentifierBinding`. Move `verifierAccreditations[]` out of `MembershipEpoch` into a `VerifierRegistry` under a `GovernanceRoot`.

**§5, "Compromised federation authority"**: delete "Cannot reassign a binding". Replace with: cannot reassign *if* accreditation is a distinct trust domain; today it is not, so it can.

**§8, D2**: replace "authenticate `/resolve`" with: the resolver must not be a cheap unrestricted enumeration oracle. Controls are layered and none assumes an account session: remove the explicit `exists` signal where the protocol allows, rate-limit on anonymous installation credentials, quota, and blinded lookup. Note the online VOPRF evaluation oracle is a new surface requiring its own quota.

**§8, D5**: becomes:
> Adopt an opaque stable `accountId`, derived as `H(rootAlg || rootPublicKey)`. It severs *Gua account identity* from placement. It does **not** make the Matrix `user_id` mutable: **[CODE]** the MXID is immutable in every layer checked. The spec defines the domain as the allocating homeserver and room auth rules require events be signed by the server denoted by `sender`, enforced by every participating server. MAS has no rename at any level: no `set_username`, five `UPDATE users` statements none touching `username`, a write-once UNIQUE column. Synapse's admin API has no rename or move endpoint. Room version 12 makes the creator's MXID permanent room structure. The only portability MSCs (1228, 2787, 4014) are open and require a new room version; 2783 is abandoned. **Gua account placement migration and Matrix identity migration are therefore separate problems, and the second is unsolved upstream.** A placement move is an export/import into a new Matrix identity, losing device keys, cross-signing, room membership continuity, history attribution and server-side key backup.

**§8, D6**: add the VOPRF corrections: caching makes future *token derivation* offline, not placement or freshness lookup; blinding removes cheap *offline* enumeration and creates an *online* evaluation oracle needing its own abuse model; anchor the VOPRF public key and epoch in verifiable federation state; design so threshold VOPRF can arrive later without a protocol break.

**§9**: insert as increment 0: delete the legacy authorize branch. Renumber.

**§10**: add S6: resolve A2, the epoch/uniqueness tension, before committing to blinded routing keys. This spike gates increment 8.

---

## Appendix: what the second round changed about my confidence

Four correction tracks, all four failed adversarial review. The failures were not random: they were the **same defect recurring at every level of the stack**, which is why A4 is stated as a finding rather than a note. A guarantee that assumes the thing it establishes reads as sound at every layer in isolation and is worthless in composition.

I would treat every remaining guarantee in ADM-001 as provisional until someone has traced it from the pinned root outward, rather than from the middle in both directions.
