> **Normative architecture decision record.** This is the frozen decision set for Gua identifier binding, account placement, resolver trust and federation governance. It is the authority when any other document in any Gua repository disagrees with it.
>
> **Frozen pending implementation evidence.** Locked decisions are not reopened by argument. They are reopened by evidence from a spike, a benchmark or an implementation that contradicts them. Open decisions and spikes proceed normally. Each closes in its own follow-up record.
>
> **How to use it.** Link to the decision by its label (`L7`, `O11`, `S1`) rather than restating its reasoning elsewhere. The plain-language explanation is the [architecture guide](../architecture/gua-identity-and-federation.md). Read that first if you are new to the design.
>
> **Reasoning record.** The three memos that produced this decision set are preserved in [rationale/](rationale/) with only punctuation normalized. They are not normative. They are kept so the reasoning can be audited.
>
> **Tags used below.** `[CODE]` verified against `main` or live configuration at the time of freezing. `[TARGET]` what the protocol should guarantee. `[LIT]` attributed to published literature.


# ADM-001: final decision set

> **Status: ARCHITECTURE FROZEN pending implementation evidence.**
> Locked decisions are not reopened by argument. They are reopened by evidence from a spike, a
> benchmark, or an implementation that contradicts them. Open decisions and spikes proceed normally.

Supersedes the decision sections of ADM-001, R1 and R2. Those remain as the reasoning record.
This is not the repository architecture document.

Tags: **[CODE]** verified against `main` or live config. **[TARGET]** what the protocol should guarantee. **[LIT]** attributed to published literature.

**Standing rule for every guarantee below:** the compromise condition is stated as *different key / different process / different operator or trust domain / governance threshold*. Two keys held by one operator are one principal. **[CODE] Today one operator holds every role, so every independence guarantee currently reduces to compromising Gua.** That is stated once here and assumed throughout rather than repeated.

---

# LOCKED ARCHITECTURAL DECISIONS

## L1. Delete two live paths

**L1a.** Delete the legacy non-interactive branch of `GET /oauth2/authorize`. **[CODE]** With `phone_number` and `otp_code` present, it verifies only the OTP, provisions an account if none exists, and issues an authorization code. The client is declared with no secret and is therefore public. No PIN, no passkey, no registration guard. *Compromise required: none. One SMS.*

**L1b.** Delete `POST /directory/entries`. **[CODE]** Any `ACTIVE` roster member can bind any phone to itself with a signature over a constant string. There is no uniqueness check. The upsert is unconditional. The signed bytes carry the raw E.164.

Both are deletions, not deprecations. Neither depends on anything else in this memo.

## L2. The three concepts stay separate

The federation validates identifier ownership. The federation coordinates placement. The target homeserver decides authentication. A federation-issued identifier-ownership artifact is never a login credential or session grant.

The test for whether a flow violates this has four questions. Was the artifact issued by a federation-scope component? Does any party treat it as evidence that *this human is present now* rather than *who owns an identifier*? Could a party holding only that artifact obtain a session? Does the homeserver still independently authenticate? A yes to the third or a no to the fourth is a violation. Ordinary homeserver-local OTP login is **not** a violation merely because an OTP is a short-lived bearer secret.

## L3. An identifier is an attribute of an account, never the account

Supersession removes an attribute. It never transfers an account, its history, its credentials or its placement. This is what makes carrier recycling survivable.

## L4. Account genesis

`AccountGenesis` is an immutable, domain-separated, canonically encoded object. `accountId = H(canonical(AccountGenesis))`.

It commits the initial account authority key, algorithm identifiers, and the **initial recovery authority and framework**. It contains **no identifier and no homeserver**. Both are separate lifecycles. Embedding either would make the accountId itself a privacy leak in replicated state.

**What genesis fixes about recovery, and what it does not.** Genesis establishes the *initial* recovery authority and the **rules under which recovery-policy transitions may later be authorized**. It does **not** freeze the exact recovery policy for the life of the account. People change devices, guardians and circumstances. An unchangeable policy would be its own failure mode. The detailed transition rules are delegated to the recovery ADM under L13.

`accountId = H(rootPublicKey)` is rejected. It makes the authority key unrotatable, leaves nowhere to commit a recovery framework, and forecloses algorithm agility.

One encoding rule is locked because it is a security property, not a format:

> **Every signed object has exactly one canonical byte representation. Decoders reject ambiguous or non-canonical encodings. Signatures and hashes cover the canonical bytes.**

Exact serialization is **O2**. This rule is what makes a signature mean one thing. The concrete framing that achieves it is an implementation choice.

**[CODE]** The existing `CanonicalRoster` is not safe to copy. It joins fields with a raw `0x1F`. That byte is asserted to be absent from the fields, and nothing enforces the assertion. It uses unescaped nested delimiters. It collapses null and empty to identical bytes. `CanonicalRoutingClaims` escapes correctly, which is the right instinct with the wrong mechanism.

## L5. Account authority is mandatory for new accounts

First-party clients generate account authority at creation. B1, where the binding commits an intended initial homeserver, is a **bootstrap path with a defined end**. It is marked in state so an auditor can distinguish rooted from bootstrap accounts.

**What account authority buys, and what it does not.** Account authority does *not* improve the generation-1 compromise condition. It buys rotation, pre-authorized recovery, migration authorization, and continuity when an identifier is recycled. Anyone building the transaction expecting a squat defence at creation will not find one.

## L6. Generation-1 is a five-step transaction, and `HostingAcceptance` is not a gate

```
0. client generates AccountGenesis, derives accountId
1. resolver supplies a TRANSACTION-STABLE ALLOCATION (mechanism is an implementation choice)
2. candidate homeserver issues short-lived HostingAcceptance(accountId, txNonce, notAfter)
3. identifier verifier(s) attest possession
4. account authority binds HA + PA[] + chosen destination + txNonce
5. sequencer accepts binding + generation-1 placement as one unit, or neither
```

**Locked at step 1, and only this:** the allocation used during registration must be **transaction-stable** for the life of the transaction, and **verifiable against signed federation policy and authenticated roster state**. A client, or any third party, must be able to check that the destination was an eligible outcome of the published policy applied to the roster at a stated point. That check must not depend on the resolver's word.

**Not locked:** the mechanism. A signed candidate set, an allocation lease, and a stable deterministic policy evaluation are all live implementation options. The choice is made on operational grounds. R2 locked a candidate set on the strength of one observation. **[CODE]** `WeightedFallbackRule` seeds on roster version. Roster version is the transparency-log size, so the seed drifts on every leaf. That observation shows that *the current evaluation is unstable*. It does not show that a set is the only remedy. Making the evaluation deterministic and stable would satisfy the requirement equally.

**Explicitly locked constraint on any mechanism chosen:** a resolver's own signature must not become an unreviewed routing authority. Whatever step 1 produces must be checkable against governance-signed policy and authenticated roster state. A resolver that can sign an allocation nobody can independently re-derive has become the placement authority by the back door. L7 exists to prevent the equivalent defect for identifier binding.

**Locked: neither `RC` nor `HA` is a security gate.**
- `RC` is the applicant's own signature. At generation 1 the claimant is the party being authorized. It is a binder and anti-replay device, which is worth keeping. It is not an authorization.
- `HA` is contributed by an **honest** homeserver performing its normal function of accepting new users. At the moment it signs, `PA` does not yet exist. The homeserver never learns the identifier, routing key, challenge or verifier. Its only available question is "will I host one more account". Refusing on a predicate that would block the attack means refusing new users. Reordering does not rescue it. If `HA` covered the attestation, the homeserver's added check would be "is this signed by an accredited verifier". That is exactly the check a compromised verifier passes. It would become a second checker of one signature, not a second authority.

`HostingAcceptance` is retained for three real jobs, none of which is a compromise term. The first is anti-orphan: placement is never committed to a homeserver that has not agreed. The second is destination pinning against the drift defect. The third is operational admission control.

## L7. The generation-1 compromise condition

> **For a previously unbound identifier, forging a binding requires the compromise of `k` distinct accredited verifier operators, where `k` is the value the configured `IdentifierProofPolicy` specifies for that identifier type.**

The condition is **derived from policy**, not fixed by the protocol. Different key: `k` verifier signing keys. Different process: as many as the operators run. Different operator or trust domain: `k` distinct ones, enforced by the evaluation rule in L8. Governance threshold: not required to forge, but required to *change* `k`, since the policy is governance-signed.

At `k = 1` this reduces to a single accredited verifier operator. That is the beta configuration. It should be understood as a policy choice with a stated cost, not as a property of the design.

This replaces R2's condition of "verifier operator **and** one homeserver operator". That condition counted an honestly obtained signature as a security gate. See L6 for why `HostingAcceptance` contributes no compromise term.

**Stated separately, because raising `k` does not touch it:** compromise of the underlying identifier channel causes **all honest verifiers to attest the attacker**. Under a SIM swap, a mailbox takeover, or a carrier insider, every one of `k` honest verifiers correctly reports that the attacker presently controls the identifier. Increasing `k` raises the cost of **forging** attestations. It does not raise the cost of **being** the current controller. This residual is irreducible for possession-based identifiers. Nothing in this architecture mitigates it.

**Consequence:** verifier accreditation and the value of `k` are together the most important control in the architecture.

## L8. `IdentifierProofPolicy`: identifier-type-specific, k-of-n over independent trust domains

Federation policy is keyed by identifier type. It lives in the already-decided `PolicyRegistry` under `GovernanceRoot` and reuses the shipped policy-bundle envelope. Per identifier type it specifies three things: `k`, the number of attestations required; the permitted proof types; and a challenge freshness bound. This is the `IdentifierProofPolicy` from which L7's compromise condition is derived. Changing `k` is a governance-signed act.

**Independence is an evaluation rule, not a new field.** The rule resolves each attestation's verifier key to the `operatorId` already carried in verifier accreditations. It then requires distinct operators. **No `trustDomainId` field is introduced.**

Two locked implementation constraints, both from live code:
- **[CODE]** `RosterVerifier.countValidSignatures` dedupes on `authorityKeyId` with the comment "one vote per authority key". Reusing that shape for attestations yields a threshold satisfiable by **one operator holding k keys**. Attestation counting must dedupe on operator, not key.
- **[CODE]** `RoutingClaimsVerifier` falls back to the authority trusted keys when its own trusted-key list is unset. It is live in that fallback state in dev. **Any independence rule must fail closed. No fallback, ever.**

**What this protects against, and what it does not.** k-of-n raises the bar for **forging** attestations from a compromised verifier. It does **nothing** about compromise of the identifier channel itself. Under a real SIM swap, *k* honest verifiers all correctly attest that the attacker presently controls the number. That residual is irreducible for phone and email. No federation machinery touches it.

## L9. Matrix has no native migration preserving identity and crypto continuity

**[CODE]** Verified across the specification, Synapse and MAS. The spec defines the domain as the allocating homeserver. Room auth rules require events to be signed by the server denoted by `sender`. Every participating server enforces this. MAS has no rename at any level. There is no `set_username`, none of its five `UPDATE users` statements touches `username`, and the column is write-once `UNIQUE`. Synapse's admin API has no rename or move endpoint. Room version 12 makes the creator's MXID permanent room structure. Portability MSCs are open and require a new room version. The migration-format MSC is abandoned.

**Locked, stated as a present-tense fact rather than an impossibility claim:** Matrix currently provides **no native migration operation** that preserves device keys, cross-signing identity, room membership continuity, history attribution or server-side key backup across a change of homeserver. **Gua account placement migration and Matrix identity migration are therefore separate problems. The second has no upstream solution today.**

This does **not** assert that those properties are permanently unachievable. Gua-specific migration tooling may be able to preserve some of them. Future room versions or MSCs may change the ceiling. Any such claim requires its own demonstration against the versions in use at the time. None is made here. A design that depends on such a claim may not assume it.

## L10. Federation genesis

A pinned `FederationGenesis` carries a **threshold set** of governance keys. It is distributed out of band: pinned in first-party client builds, published at a well-known location, and verifiable by fingerprint comparison across independent channels.

Chain: pinned genesis → governance key transitions (co-signed by old and new sets) → registry roots → member, verifier and witness identities, each self-signed with governance able only to admit or revoke → checkpoints → authenticated state → resolver proofs.

Registries are separately versioned under a common root, so a verifier rotation is not a membership epoch. The registries are `HomeserverRegistry`, `VerifierRegistry`, `PolicyRegistry` and `WitnessRegistry`.

**Locked:** `FederationGenesis` v1 is signed by the keys it enumerates. That is unavoidable. It is exactly why genesis must travel out of band. Witness identities must be rooted in genesis and verified *before* any checkpoint they co-sign is accepted. Otherwise verification is circular.

## L11. A checkpoint is an assertion, not a derivation

> A signed `(logRoot, stateRoot, size, seqTime)` proves only that the signers signed those bytes together. **Merkle roots commit to data; they do not attest to execution.**

A witness co-signature is admissible only if that witness independently did all of the following. It fetched every entry since its last verified size and checked each against its leaf hash. It verified each entry's signatures under strict canonical rules and applied the deterministic transition function. It recomputed **both** roots and found them equal. A witness signs the size it verified to. A witness that cannot verify does not sign. A witness whose replay disagrees publishes a signed dissent.

*Break integrity by:* the sequencer operator together with every full-replay witness in the client's required set.

**Two witness classes are locked, because they have different costs.** Log-only witnesses are cheap and numerous and provide equivocation resistance. Full-replay witnesses are expensive and provide integrity.

**The design constraint locked with it:** every state-affecting input must be an **explicitly authenticated and sequenced input**. That includes authoritative time and any relevant request context. They are permitted, and they are permitted *as inputs in the log*. A replaying witness then sees exactly what the sequencer saw.

What is forbidden is narrower. It is the thing that actually breaks replay: **dependence on unsynchronized local observations**. A transition may not read the replaying node's own clock, its own environment, or anything else that differs between the sequencer and a witness. Time-based rules are fine when the time is a sequenced, authenticated input. They are not fine when each node consults its own clock.

R2 stated this as "forbids wall-clock transitions and per-request-context state, forever". That was too strong. It would have foreclosed ordinary features such as expiry windows and delay periods, which this architecture already requires elsewhere.

**[CODE] Today replay is structurally impossible.** The log carries hashes, and directory mutations are unlogged. Integrity therefore currently reduces to trusting one Postgres row set.

## L12. Five properties, never conflated

A consistent, non-equivocating, highly available, perfectly ordered history can still be entirely wrong. **Integrity is a separate purchase from the other four.**

| Property | Mechanism | Break it by |
|---|---|---|
| **Integrity** | deterministic transitions + independent full replay | sequencer operator + every full-replay witness in the client's set |
| **Equivocation resistance** | witness co-signing + client pinning + consistency proofs + cross-channel comparison | sequencer + enough witnesses in one trust domain, or partitioning clients so they never compare |
| **Censorship** | detectable, not preventable, by a single sequencer | the sequencer alone |
| **Availability** | not provided by witnessing | the sequencer alone |
| **Ordering** | the distinguished sequencer | the sequencer alone |

**When BFT is justified.** Byzantine state-machine replication is justified when governance refuses any distinguished sequencer. It is also justified when the federation requires **continued operation despite malicious or failing independent ordering nodes**. That is an availability and censorship-resistance requirement. It is a legitimate trigger on its own. Threshold signatures and transparency address neither.

## L13. Recovery requirements only

Recovery is **not** decided here and gets its own ADM. Four requirements are locked:

1. Initiation must satisfy a **genesis-committed** authorization threshold.
2. Rotation and recovery races have **deterministic priority**. Freezing rotation on a pending recovery fixes the thief-rotate flood but creates a recovery-trigger denial of service; the resolution must not simply be "whoever signs fastest".
3. Cancellation or veto authority is **precommitted** and cannot equal the potentially stolen active key. Cancellation by the active key protects only the case where the owner still holds it, which is not the recovery case.
4. **Unrecoverability from loss of all committed factors is permitted.** Any design guaranteeing recovery from loss of every factor necessarily grants some party a takeover path, because recovery-from-nothing and takeover-from-nothing are the same operation seen from two sides.

## L14. VOPRF architectural shape, not construction

**Locked shape:** a stable **logical** PRF key with **proactive threshold-share refresh** appears capable of preserving routing outputs during routine operator rotation. That would mean the cross-epoch uniqueness problem need not arise in normal operation.

**Not locked, and explicitly downgraded from R2:** the exact construction. **[LIT]** RFC 9497 specifies OPRF, VOPRF and POPRF for a single server holding the key. It specifies **neither threshold operation nor rotation**, so do not cite it for either. Recent threshold-OPRF literature has identified shortcomings in earlier models and constructions. The CRYPTO 2025 fully-adaptive threshold pOPRF work explicitly addresses proactive refresh and verifiability. That is itself evidence that the earlier composition was not settled. **No composition is claimed validated. See S1.**

Emergency replacement of the logical key is a **separate** problem, treated under O4.

## L15. Routing-key privacy is required in replicated state

Raw phone numbers and email addresses do not appear in replicated federation state. **[CODE]** Today both services HMAC with a shared 64-hex pepper from one Kubernetes secret, with differing constructions. The pepper cannot be rotated without re-deriving every entry from raw numbers. A national numbering plan is 10⁹ to 10¹⁰ candidates. Anyone holding the state and the pepper can trivially invert it offline.

## L16. `/resolve` must not be a cheap unrestricted enumeration oracle

The requirement is stated this way rather than as "authenticate `/resolve`". That framing is circular, because `/resolve` is needed before any account session exists. Controls are layered, and none may assume an account session. **[CODE]** Today it is unauthenticated and un-rate-limited. It takes a raw E.164 and returns `exists`, on the public production host.

---

# OPEN DESIGN DECISIONS

**O1. Authenticated dictionary choice.** An authenticated dictionary supporting efficient membership *and* non-membership proofs is required. Sparse Merkle, indexed Merkle with sorted-neighbour, and existing verifiable-map approaches are **not** yet decided. R2's lock on indexed Merkle is withdrawn pending benchmark. Criteria: proof size, update cost, implementation risk in a Java service, phone-side verification cost.

**O2. Wire-level protocol specification.** Integer widths, framing, Base32 prefixing, entropy length, hash-suite identifiers and signature encodings move to a protocol-specification task. The *architecture* locks only L4's two encoding rules.

**O3. `k` per identifier type.** What `k` should be for phone, email, SSO and account-key, and whether any type warrants `k = 1` at beta.

**O4. Emergency replacement of the logical VOPRF key.** **[LIT]** RFC 9497's `Finalize` places the raw input inside the final hash. Its output is therefore not key-homomorphic. A party that does not hold the input cannot re-key it. Updatable constructions in the Pythia line support bulk rotation because their output form differs. **The fork between plain RFC 9497 and an updatable construction is preserved and not chosen here.** It must be decided before implementation, because it is not a later swap.

**O5. Recovery mechanism.** Deferred to its own ADM under L13's four requirements.

**O6. Cancellation authority** for recovery, given it cannot be the active key.

**O7. Whether witnessing is worth building before a second operator exists**, beyond the format and verification path. If the answer is that it is theatre until then, build the format now so it is not a rewrite later. Do not claim the guarantee.

**O8. Client behaviour on genesis version skew**, without creating a downgrade path.

**O9. `ADOPT_ROOT`**, the path by which a bootstrap account gains authority. As sketched, it carries proof-of-possession by the new key and confirmation by the current holder, with no artifact from the human. That is a homeserver-initiated seizure. It needs a fresh possession proof and a delay with notification, or it must be removed.

**O10. Client pinning semantics**, including what a client does when a legitimate key chain change is indistinguishable from a takeover.

**O11. Passkey discovery and relying-party architecture.** Open, and larger than it appears. Must cover: a relying party per homeserver, versus a shared federation relying party, versus related origins; platform-synced hints as a discovery aid; identifier-first fallback when no hint exists; and the native platform constraints on iOS and Android including association files, entitlements and Credential Manager. **[CODE]** Neither client has any native WebAuthn today. The flow is entirely web-based against a single global host.

The binding constraint is ordering. A discoverable credential is indexed by relying-party id, and no platform offers cross-relying-party enumeration. **Routing must therefore precede the ceremony**. The locked requirement on any answer is that **routing and discovery must not become global authentication**. Whatever the global plane does to help a client find its homeserver, the homeserver must still mint the challenge, hold the key, verify the assertion and decide the session. A discovery mechanism that ends up holding or verifying credentials has violated L2.

**O12. Resolver replica and bootstrap protocol.** Open. Must cover: how a replica acquires the pinned federation genesis; how it discovers checkpoints; how it verifies a snapshot rather than trusting one; how it replays mutations to current state; how it behaves on encountering a fork; and the distinction between read-only query replicas and any node with authority.

The locked invariant on any answer: **running another resolver grants no governance authority.** Replica count is an availability and latency decision and never a voting or signing decision. **[CODE]** Today both environments run a single node in `AUTHORITY` mode at `k = 1, n = 1`. `MIRROR` mode exists but is unexercised. This invariant is therefore currently a design intention rather than an enforced property.

**O13. Catastrophic governance-key loss and root transition.** Explicitly deferred, not solved here. If a governance threshold set is lost or compromised beyond its own transition rules, this architecture has no mechanism to recover. The pinned `FederationGenesis` is by construction the thing that cannot be replaced from inside the system. This needs its own governance decision covering out-of-band re-rooting, client re-pinning, and what happens to accounts and placements across a root transition. It is a governance question before it is a protocol question. Answering it inside ADM-001 would have produced a mechanism nobody had agreed to operate.

---

# IMPLEMENTATION AND CRYPTOGRAPHIC SPIKES

**S1. Threshold OPRF with proactive refresh. CRYPTO REVIEW REQUIRED.** Blocks L14 and O4.
For a cryptographer, exactly: is a threshold OPRF composed with dynamic proactive share refresh sound as a single system? Does verifiability survive the composition? Does any reviewed construction preserve the logical key, and therefore stable routing outputs, across share refresh *and* support bulk update on logical-key compromise? What is the correct binding of the VOPRF public key and generation into the checkpoint chain to prevent generation rollback? **Do not implement on our own authority.**

**S2. Authenticated dictionary benchmark.** Closes O1. Proof size, update throughput, phone-side verification cost, Java implementation risk.

**S3. Full-replay witness feasibility.** State size, initial sync time, incremental replay cost at target write rates, and behaviour of a witness that falls behind. Determines whether L11's integrity guarantee is operationally real or aspirational.

**S4. Enumeration controls for `/resolve`.** Closes L16. Which layered controls actually work without an account session, and what residual enumeration capability remains, quantified.

**S5. Verifier accreditation governance.** Can a governance key set be operated in a genuinely different trust domain from the resolver process, by whom, with what recovery if lost? This is organisational before it is technical. L7 makes it the highest-value control in the architecture.

**S6. Migration of existing accounts** from `directory_entries.homeserver_id` and the current subject behaviour, given L9. **[CODE]** MAS keys links on `(provider ULID, subject)`, and no code path rewrites a subject. The route is therefore a new provider row plus a link association pass, never an in-place update. The silent trap is `routeExistingUser`. It derives `preferredUsername` from `localpartOf(userId)` and ignores the directory's username column. Re-keying to an identifier containing a colon, with `on_conflict: add` live, silently merges every user onto one account.

---

## Appendix: the pattern that recurred, and what to do about it

The same defect appeared at every layer: **the first object in every chain has no predecessor, and each design gave that first object weaker protection than the ones that follow.** The account genesis had no delay, notification or log leaf. `FederationGenesis` v1 is signed by the keys it enumerates. The VOPRF generation label was learned from the party it constrains. The generation-1 placement had no predecessor to chain from.

This is not a bug to fix once. It is the structural cost of bootstrapping trust. The response has two parts. Make each first object expensive to produce, distributed out of band, and verifiable by comparison across independent channels. Stop adding layers that inherit the hole while appearing to close it.

The second recurring error was counting signatures instead of principals. `RC` was counted as an authorization when it is a binder. `HA` was counted as a gate when it is honest participation. k-of-n was counted per key when keys are held per operator. **A signature is only a compromise term if obtaining it requires a compromise.**
