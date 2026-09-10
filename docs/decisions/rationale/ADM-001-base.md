# ADM-001: Identifier binding, placement and the federation trust root

Status: **draft for decision**. Not an approved design.
Scope: the separation of identifier ownership, placement and authentication, and what the federation must guarantee at national scale.
Method: six design tracks, each attacked adversarially by an independent reviewer. **All six failed first review.** This memo reports the survivors and the reasons, not the original proposals.

Every claim below is tagged either **[CODE]**, meaning verified against `main` or live configuration, or **[TARGET]**, meaning a property the protocol should eventually guarantee. They are never blended.

---

## 0. The finding that should be read before anything else

**[CODE]** The strengthened invariant you are asking for is violated by a live endpoint today, with no cryptography required to exploit it.

`POST /directory/entries` accepts a write from any homeserver that is `ACTIVE` in the roster. The only checks are that the `homeserverId` names an active entry and that an Ed25519 signature over the constant string `directory-write.v1|<hsId>|<phone>|<username>` verifies against that entry's `signingKey`. There is no check that the phone is already bound to another account. `JdbcDirectoryStore` performs an unconditional upsert.

> `src/main/java/global/gua/resolver/api/DirectoryController.java:44-67`

So a legitimately admitted member claims any previously unseen identifier, and re-claims any *already bound* one, by asserting it. That is precisely the thing this memo exists to prevent, and it is not a design gap: it is a shipped endpoint.

It also ships the raw E.164 inside the signed canonical string, which contradicts the requirement that raw identifiers stay out of replicated federation state.

**Every one of the six design tracks failed review at least partly because none of them removed this path.** They layered proof requirements, accreditation registries and assurance ladders on top of an endpoint that bypasses all of it. The first decision in this memo is therefore a deletion, not an addition.

---

## 1. Invariants

The three concepts, kept structurally separate:

- **I1: Ownership.** A binding `identifier -> accountId` is created only by a proof produced by a party whose key is **not** a homeserver membership key. A homeserver's own assertion can never create a binding. **[TARGET]**
- **I2: Placement.** `accountId -> homeserverId` is a separate signed record with a separate lifecycle. An identifier change touches only the binding; a migration touches only the placement. **[TARGET]**
- **I3: Authentication is local.** The target homeserver decides whether a login is allowed. No federation component stores login credentials, verifies login attempts, or issues Matrix sessions. **[TARGET]**
- **I4: A proof is not a session.** No artifact produced by the binding protocol may be redeemable as a credential at any homeserver. This must be structural, not conventional. **[TARGET]**
- **I5: Uniqueness.** Exactly one `ACTIVE` binding exists per routing key, enforced by a storage constraint rather than by application logic or inter-party agreement. **[TARGET]**
- **I6: Absence is signed.** "No binding exists" is a signed statement with a non-membership proof, not an unsigned default. **[TARGET]**
- **I7: Governance is not operations.** Running more resolver instances grants no additional authority. **[TARGET]**
- **I8: Key roles are disjoint.** No single key may occupy two roles in any guarantee that claims to require two. **[TARGET, and the most-violated invariant in the first round.]**

### Where the code stands against these

| | Today **[CODE]** |
|---|---|
| I1 | Violated. `POST /directory/entries` lets a member bind unilaterally. |
| I2 | Absent. There is no placement record at all; placement is a pure function of (roster, policy, context) evaluated per request and persisted nowhere. |
| I3 | Violated. identity-service is the federation's only OIDC provider and sole credential store. |
| I4 | Violated. The OTP code is a bearer token for the account: one value at a Redis key, and possession is sufficient. |
| I5 | Violated. Unconditional upsert, no uniqueness check. |
| I6 | Absent. No non-membership proofs anywhere. |
| I7 | Partly held. `MIRROR` mode exists; both live environments run `AUTHORITY` at `k=1, n=1`. |
| I8 | Violated. One authority key list is also the fallback trust root for claims. |

---

## 2. Trust assumptions

Stated in the required form. Each says what must be compromised.

**T1.** A homeserver acting alone cannot create a first binding.
→ *Break it by* compromising an accredited verifier key held by a different operator, or by actually possessing the identifier. **Caveat that must not be lost:** today Gua is the authority, the only prospective verifier, and the operator of every homeserver. At beta this reduces to "compromise Gua". The structure is worth building now because it is what lets independence arrive later, but it buys no independence today, and the memo should not pretend otherwise.

**T2.** A binding cannot be created for an identifier the claimant does not possess.
→ *Break it by* compromising the possession channel itself: SIM swap, SS7, a carrier insider, or a mailbox takeover. No federation key, homeserver key, or other account is sufficient. **This residual is irreducible for phone and email** and is the same one WhatsApp carries.

**T3.** The federation authority cannot reassign a binding to an account of its choosing.
→ **This guarantee failed review and does not currently hold.** The proposal claimed you would need a verifier key *in addition to* the authority key. But verifier accreditation is itself authority-signed, so the authority mints its own second key. At `k=1` that is one signature. *To make it true*, accreditation must be signed by a key set disjoint from the operational authority key set, with its own threshold. Until then: **break it by compromising the authority key alone.**

**T4.** An identifier proof cannot produce a login session.
→ *Break it by* compromising the target homeserver's MAS signing key or rewriting its upstream provider configuration. Federation keys and binding artifacts together are insufficient, **provided** the proof artifact carries a federation-constant audience, no scope and no localpart, and provided no client flow accepts it as an authentication input. Reviewers found the original design violated this twice by making a binding receipt the thing the client presents to log in.

**T5.** Placement cannot be committed for an identifier with no `ACTIVE` binding.
→ *Break it by* obtaining write access to the resolver's Postgres or control of the authority process, **once `POST /directory/entries` is removed rather than deprecated.** Until then, break it with any active member's roster signing key.

**T6.** The winner of a race between two first claims is auditable.
→ *Break it by* equivocating: serving two clients two different histories. That needs the authority key **and** the absence of any independent checkpoint co-signer. Witness co-signing removes it. Consensus is not required for this property.

**T7.** Replicated state contains no raw phone numbers or emails.
→ Under a blinded routing key: *break it by* compromising the OPRF key holder **and** obtaining the state. Under today's shared pepper: **the pepper alone is sufficient**, and full inversion of a national mobile numbering plan is minutes of GPU time. **[CODE]** This guarantee is also false today for an unrelated reason: `POST /directory/entries` ships raw E.164, and `POST /resolve` accepts raw E.164 unauthenticated.

---

## 3. Proposed identifier-binding protocol

Three parties, three keys, and the deliberate absence of a fourth.

```
  claimant (client)        accredited verifier         federation authority
        |                          |                            |
        |-- request challenge -----|--------------------------->|
        |<------------------------- challenge (single use) -----|
        |                          |                            |
        |-- prove possession ----->|                            |
        |   (SMS/email/SSO/passkey)|                            |
        |                          |-- ProofAttestation ------->|
        |                          |   signed over              |
        |                          |   (routingKey, accountId,  |
        |                          |    challenge, proofId)     |
        |                          |                            |-- validate,
        |                          |                            |   check uniqueness,
        |                          |                            |   append BIND leaf
        |<-------------------------------- binding is public ---|
```

The homeserver is **not** in this diagram. That is the point. It learns of the binding by reading federation state, the same as anyone else.

**Why this satisfies I1.** The binding's canonical bytes embed a signature by a verifier key. The set of accredited verifier keys must be disjoint from the set of homeserver membership keys. A homeserver holding any number of membership keys cannot produce the required signature.

**Why this satisfies I4, structurally.** The attestation's audience is a federation constant, its subject is a routing key rather than any principal on any homeserver, and it carries no scope, no localpart and no token field. A MAS token endpoint rejects it by ordinary audience checking, because no verifier key appears in any MAS upstream JWKS. **The failure mode reviewers found** is not the artifact but the *flow*: if the client presents a binding receipt to the homeserver and the homeserver treats it as evidence of authentication, the receipt has become a credential regardless of its fields. The protocol must therefore also state that a homeserver receiving a binding receipt learns only *which account claims this identifier*, and must still authenticate the user by its own means.

### First-claim squatting, traced

The attack you asked to be prevented:

1. Malicious admitted homeserver picks an unseen identifier.
2. Fabricates a generation-1 account locally. **Allowed.** Local accounts are its own business.
3. Claims the identifier. **Blocked at this step and only this step:** it cannot produce a verifier attestation, because it holds no verifier key.
4. Commits placement. **Blocked:** placement requires an `ACTIVE` binding.

Step 3 is the entire defence, which is why the disjointness of key roles (I8) is load-bearing rather than tidy.

### Contest and re-binding

Carrier recycling is not an edge case at national scale; it is routine. The protocol must handle "someone else now legitimately controls this number" without letting it become free account takeover.

- A binding to an account that holds an **account key** cannot be superseded by possession proof alone. Supersession requires the incumbent's consent, or a dispute window with notification to the incumbent's devices and an opportunity to counter-prove.
- A binding to an account with **no** account key is the weak case, and it is honest to say so: possession is all there is, and the account is takeable by whoever the carrier gives the number to next. Mitigation is product, not protocol: encourage an account key, and make the loss visible.

---

## 4. Data structures

```
MembershipEpoch                   signed by GOVERNANCE keys (k-of-n), not by the operational authority
  epoch                           monotonic; membership changes only
  previousEpochHash
  governanceKeys[]                the root; what a client pins
  members[]                       { homeserverId, genesisKeyId, admittedAt, status }
  verifierAccreditations[]        { verifierId, operatorId, keyId, publicKey,
                                    namespaces[], proofTypes[], maxAssurance,
                                    quotaPerDay, notBefore, expiresAt }

HomeserverGenesis                 self-signed by the homeserver, once, at admission
  homeserverId
  hsKeyId = H(genesisPublicKey)   self-certifying: the id IS the key hash
  recoveryKeyHash                 commitment for rotation after key loss
  signature                       by the genesis key over itself

HomeserverEndpoints               self-signed by the homeserver's current key
  homeserverId, epoch
  serverName, baseUrl, masIssuer
  notAfter                        bounds stale-entry replay
  signature                       chains to genesis via the transition chain

IdentifierBinding                 signed by an ACCREDITED VERIFIER, published by the authority
  bindingId, version, previousBindingHash
  routingKey     { rkAlg, value }  blinded; never a raw identifier
  identifierType                   PHONE_E164 | EMAIL | OIDC_SUBJECT | ACCOUNT_KEY | ...
  accountId                        opaque, stable for life, never a Matrix ID
  proofRef       { proofType, verifierKeyId, proofId, assurance, verifiedAt }
  state                            ACTIVE | DISPUTED | SUPERSEDED | REVOKED
  attestation                      verifier signature over the canonical bytes

PlacementRecord                   signed by the HOLDING homeserver
  accountId, generation, previousRecordHash
  homeserverId
  reason                           CREATE | MIGRATE | SUSPEND | RECOVER
  cosignatures[]                   destination on MIGRATE; quorum-excluding-destination on RECOVER
```

Two derivation algorithms are named **inside** the signed records (`rkAlg`, and the accountId derivation). This is not decoration: it makes changing a derivation a migration rather than the silent data-corruption event that rotating today's shared pepper would be.

---

## 5. Threat analysis

### Corrupt resolver

**[CODE] Today: total compromise.** It re-signs the roster with a different `baseUrl` and `signingKey` for any member. Placement records, if they existed, would still verify, against the swapped key. `RosterEntry` has no per-entry self-signature. `k=1, n=1` live.

**[TARGET] After genesis keys and self-signed endpoints:** reduced to withholding and staleness. It can delay, exclude, or answer "never placed". It cannot redefine a member.
→ *Break the residual by* being the sole checkpoint signer. Independent witnesses close it.

### Corrupt federation member

**[CODE] Today: total, and trivially.** One `POST /directory/entries` with its own roster signing key binds any phone to itself. Reviewers traced this end to end through admission that is entirely honest: the attacker genuinely owns its domain, genuinely passes every gate, and then simply writes the row.

A second-order harm worth noting: a client that pins the attacker's homeserver for that account will later **refuse the legitimate homeserver** when the binding is corrected, because the pin sees a key-chain break. A naive "fail closed on key change" pin makes the takeover durable.

**[TARGET] After the deletion plus verifier disjointness:** bounded to accounts it legitimately holds.

### Compromised homeserver

**[TARGET]** Blast radius is its own users, which is the intended property of keeping credentials local. It can forge placements for accounts it holds and consent to migrations away. It cannot mint a placement for an account it never held, because generation 1 must chain from a record it signed, nor create a binding, because it holds no verifier key.

### Compromised federation authority

**[TARGET]** Can suspend and delay. **Cannot** reassign a binding, *only if* accreditation is moved to a disjoint governance key set. If accreditation stays authority-signed, the authority key alone reassigns any binding, and every two-key guarantee in this memo collapses to one key.

---

## 6. Alternatives considered

**Make the homeserver's assertion authoritative, with detection after the fact.** Rejected: it is the exact thing the strengthened invariant forbids, and at national scale after-the-fact detection of identifier theft is not a remedy.

**BFT consensus over federation state.** Rejected as unjustified. Threshold signatures give "k parties agreed". Transparency gives "this was published". The gap between them is **equivocation**: neither prevents two different histories being served to two different clients. That gap is closed by independent witnesses co-signing checkpoints, which is far lighter than consensus. Consensus becomes necessary only if the federation needs a *total order over conflicting writes without a distinguished sequencer*, Gua does not, because a deterministic first-writer-wins rule plus an auditable rejection leaf is sufficient for identifier uniqueness.

**Private set intersection for routing.** Rejected on cost: the client must hold a filter over the server set, roughly 200 to 300 MB at a useful false-positive rate, incrementally updated. PSI answers a different question anyway. Routing is a single lookup by a party who already knows the number.

**Keep the shared HMAC pepper.** Rejected. A national numbering plan is on the order of 10⁹ to 10¹⁰ candidates, which is trivially invertible offline by anyone holding the state and the pepper, and the pepper cannot be rotated without re-deriving every entry from raw numbers.

**Assurance levels as a numeric ladder.** Rejected as overbuilt. Reviewers found twenty predicates of which eight were used. Named requirement predicates that a mechanism satisfies compose better and avoid arguments about what "level 2" means.

---

## 7. Unresolved questions

1. **Does the disjoint governance key set actually exist operationally?** Everything in T3 depends on accreditation being signed by keys the operational authority does not hold. Today one operator holds everything. This is an organisational question before it is a technical one.
2. **What happens to bindings issued by a verifier that is later revoked?** Cascading every affected binding to `DISPUTED` is safe and possibly catastrophic for availability if the verifier was large. Nobody has costed the alternative.
3. **Is there an honest floor for recovery?** Where a user has lost device, credentials and identifier, and the identifier has been recycled to someone else, the correct answer may be that the account is not recoverable. That is a product decision, and pretending otherwise creates the attack surface.
4. **Do clients pin per-account or per-federation?** Per-account pinning makes the durable-takeover problem above worse. Per-federation pinning weakens the guarantee. Neither is obviously right.
5. **Whole-homeserver failure** is recovery at a different scale and may need a distinct path from individual recovery. Not designed.

---

## 8. Concrete recommended decisions

**D1. Delete `POST /directory/entries`.** Not deprecate. It is the live violation of the invariant, and no amount of layered proof machinery matters while it exists. **[Highest priority in this memo.]**

**D2. Rate-limit and authenticate `POST /resolve`.** It is an unauthenticated, un-rate-limited account-existence oracle taking raw E.164 on the public production host. Independent of everything else here.

**D3. Separate governance keys from the operational authority key.** Accreditation and membership epochs signed by a key set the resolver process does not hold. Without this, every two-key guarantee in this memo is a one-key guarantee.

**D4. Self-certifying homeserver identity.** `hsKeyId = H(genesisPublicKey)`, genesis self-signed at admission, endpoints self-signed and chained. This is what stops an authority silently substituting a member's key: the identity *is* the key hash, so substitution changes the id.

**D5. Adopt an opaque `accountId`.** Sever identity from placement. Matrix `user_id` becomes derived and mutable; `accountId` is stable for life.

**D6. Blinded routing keys (VOPRF), with the tension resolved as below.** Do not ship the shared pepper into replicated state.

**D7. Assurance as named predicates, not a numeric ladder.**

**D8. A binding receipt is never an authentication input.** Write this into the protocol, and audit client flows for it, because the original designs violated it in the flow rather than in the artifact.

### On the OPRF versus offline-verifiability tension

I flagged this as possibly forcing a choice. It does not, and the resolution is worth stating because it was the strongest technical result of the round: **the two verification goals belong to different principals.**

- **Structural audit**: is the log append-only, non-equivocating, has it rolled back, works over completely opaque leaves, needs no key derivation, and is fully offline and public. This is the goal that benefits from many independent eyes, and blinding costs it nothing.
- **Answer verification**: "you said this number is on X, prove it", is only needed by a party who already knows the number, and that party is already online.

Concretely: RFC 9497 VOPRF over ristretto255, roughly 150 to 250 µs per evaluation, about 0.12 of a core at 5×10⁷ lookups per day. A client caches its own token permanently after one evaluation, so own-number routing becomes offline after a single interaction. The DLEQ proof is not optional: without it the server can key-partition clients and turn the lookup into a tracking oracle. Rotation becomes possible by indexing on `(epoch, token)`, which the pepper design cannot do at all.

---

## 9. Implementation increments

Ordered so each is independently valuable and none depends on a later one.

1. **Delete `POST /directory/entries`; rate-limit and authenticate `/resolve`.** Closes the live invariant violation and the enumeration oracle. No new concepts.
2. **Genesis keys and self-signed endpoints.** Admission retains the key; clients verify the self-signature. Closes the corrupt-authority-redefines-a-member attack.
3. **Split governance keys from the operational authority key.** Organisational plus configuration; no protocol change.
4. **Introduce `accountId` alongside the existing MXID.** Populate, do not switch. Reversible.
5. **Placement records, written by holders, discovered from each MAS's upstream links**, the only place placement truth currently exists. Read-only comparison period.
6. **Client verify-before-connect.** Until this ships, every guarantee that limits authority power is inert, because nothing checks a signature.
7. **Binding records and one accredited verifier**, still operated by Gua, with the disjoint key structure in place so a second operator can be added without a protocol change.
8. **Blinded routing keys**, with dual-read during the epoch overlap.
9. **Independent witnesses** co-signing checkpoints. This is the step that closes equivocation, and it requires a second operator to exist.

Increments 1 to 3 are worth doing even if nothing else in this memo is ever built.

---

## 10. Technical spikes required before commitment

**S1. Verifier accreditation governance (blocking D3, and therefore T3).** Can a key set be operated separately from the resolver process today, by whom, with what recovery if it is lost? If the answer is "no, one person holds everything", say so and adjust the guarantees rather than the prose.

**S2. VOPRF at national scale, one week.** Validate the throughput and caching model against a realistic address-book sync, and confirm the epoch-overlap rotation actually works end to end. The numbers above are calculated, not measured.

**S3. Client pinning semantics, three days.** Resolve unresolved question 4. Build the durable-takeover scenario and decide what a client does when the chain legitimately changes. Fail-closed makes takeovers permanent; fail-open removes the guarantee.

**S4. Carrier recycling policy, product not engineering.** What is the dispute window, who is notified, what happens to message history when a number moves to a new person. This gates the contest protocol.

**S5. Whole-homeserver failure.** Out of scope above; needs its own memo.

---

## Appendix: method and confidence

Six design tracks, each independently attacked. All six failed first review. The convergent failures were:

- **None removed `POST /directory/entries`**, so all of them layered proof requirements above a bypass.
- **Four claimed two-key guarantees where the authority mints the second key.**
- **Three made a proof artifact or receipt into a de facto credential**, violating I4 in the flow rather than the data.
- **Two were substantially overbuilt**: twenty-predicate assurance ladders and witness liveness machinery for a federation that is currently one operator.

The recommendations above are what survived, plus the corrections the reviewers demanded. They should be read as a starting position for argument, not as a settled architecture.
