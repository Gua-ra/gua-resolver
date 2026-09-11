# ADM-001-R2: foundational resolutions

Status: **resolutions for review.** Not the repository architecture document.
Scope: the four foundational issues only. Four tracks, each corrected adversarially. **The VOPRF track held. The other three did not**, and two of the corrections change the *framing*, not just the mechanism.

Tags: **[CODE]** verified against `main`. **[TARGET]** what the protocol should guarantee. **[LIT]** attributed to published literature.

---

## 1. Corrected account genesis model

**`accountId = H(rootPublicKey)` is confirmed defective. Adopt the genesis object.** The defect is not one thing but five: rotation destroys the stability the identifier exists to provide; the key becomes permanently unrotatable and therefore a permanent high-value secret in a consumer keystore; there is nowhere to commit a recovery policy, so policy falls back to mutable server state, which *is* the unilateral-override hole; no algorithm agility; no multi-key genesis.

```
GENC(AccountGenesis) =
    str("gua.account-genesis.v1")
 || u16   structVersion = 1
 || key(suiteId, initialAccountAuthorityKey)
 || u8    recoveryCommitmentAlg      // 0x00 = NO RECOVERY EVER (commitment must be zero-length)
 || bytes recoveryPolicyCommitment   // 32 bytes, or empty iff alg == 0x00
 || u64   genesisTimeSeconds
 || bytes entropy                    // exactly 16 bytes CSPRNG, MANDATORY
 || seq(str) extensions              // empty in v1

accountIdBytes = u8 0x01 || u8 0x01 || SHA-256(GENC(AccountGenesis))
accountId      = "ga1" || base32-lowercase-nopad(accountIdBytes)
```

Deliberately **not** in the genesis object: any identifier, and any homeserver. Both are separate lifecycles, and embedding either would make the accountId itself a privacy leak in replicated state.

### The canonical encoding is load-bearing, and the existing one is not safe to copy

**[CODE]** `CanonicalRoster.bytes` joins thirteen fields with a raw `0x1F` and a comment asserting it "can't appear in the fields". Nothing enforces that: `AdmissionService` never rejects control characters in `id`, `serverName`, `baseUrl`, `masIssuer` or `region`. Nested collections use their own unescaped `|`, `;` and `,`. `nz()` collapses null and empty to identical bytes. `CanonicalRoutingPolicy` repeats it. `CanonicalRoutingClaims` gets it right by escaping, which is the correct instinct with the wrong mechanism, because escaping is a discipline every future field author must remember.

GENC therefore has **no delimiters to inject into**: fixed-width integers, length-prefixed everything, `opt()` distinguishing absent from empty, raw key bytes rather than X.509 SPKI so one key cannot produce two account ids. Two rules make it real:

- **The wire form is the canonical form.** JSON views are debugging only; no signature covers one.
- **A verifier hashes only bytes it received.** Never accept a parsed object, re-encode, and hash the re-encoding. That habit is the entire injection class.

`entropy` is mandatory so a degraded RNG producing the same keypair twice cannot silently merge two accounts into one identity. Hash is not truncated: 128 bits gives a 2⁶⁴ birthday bound on constructing a colliding genesis holding the attacker's key, which is buyable.

---

## 2. Exact generation-1 sequence, and the correction that matters most

```
0. client generates AccountGenesis, derives accountId
1. resolver returns an ALLOCATION-SIGNED CANDIDATE SET (not a single drifting pick)
2. client asks a candidate for HOSTING ACCEPTANCE
   HA = sign_hs( accountId, txNonce, notAfter )        short-lived
3. identifier verifier attests possession
   PA = sign_verifier( accountId, routingKey, challenge, proofId )
4. client binds the transaction
   RC = sign_accountAuthority( accountId, HA, PA, chosenHomeserver, txNonce )
5. sequencer accepts BINDING + PLACEMENT gen-1 as ONE unit, or neither
```

Immunity to the drift defect is why step 1 returns a **set**: `WeightedFallbackRule` seeds on roster version, which is the transparency-log size and increments on every leaf **[CODE]** (`AuthorityRosterStore.java:67`, `WeightedFallbackRule.java:71`), so any single-destination commitment made before acceptance is stale by construction. A signed candidate set is stable; the claimant picks within it; the placement is valid only for a member of that set.

### The correction that changes the framing

**The four-party transaction does not add a second gate at generation 1, and the memo must stop claiming it does.**

- `RC` is the *applicant's own* signature. At generation 1 the claimant is the party being authorized, not an authorizer. You cannot count the applicant among the independent authorizations that constrain the applicant. `RC`'s real function is binding and anti-replay: it ties `HA + PA + destination` into one non-reusable unit. That is genuine and worth keeping. It is **not a gate**.
- `accountId` is self-certifying, so the "account authority" is whoever registered. **Nothing links the holder of `accountPub` to the human who possesses the identifier except `PA`.**
- Therefore at generation 1, ROOTED and BOOTSTRAP have the **same compromise condition**: an accredited verifier operator **and** one homeserver operator.

**This does not overturn your instruction to make account authority mandatory. It relocates the justification.** Account authority buys almost nothing against squatting *at creation*; it buys everything *afterwards*: rotation, pre-authorized recovery, migration authorization, and continuity when an identifier is recycled. The memo should say that, because the current framing would have someone build the transaction expecting a squat defence it does not deliver.

**Residual: `ADOPT_ROOT` is a takeover path.** The path by which a bootstrap account later gains authority carries two signatures, proof-of-possession by the *new* key and confirmation by the *current holder*, and no artifact contributed by the human. It must additionally require a fresh `PA` and a delay with notification, or it is a homeserver-initiated account seizure with a nice name.

---

## 3. Account authority rotation and recovery

```
AccountKeyTransition { accountId, prevTransitionHash, seq, newActiveKey,
                       policyChange?, effectiveAfter, sig_current, sig_new }
```
Rotation is co-signed by old and new. Chain verifies from genesis. Clients pin the genesis, not the active key.

### I10 corrected: the honest boundary

Replace *"loss of the root key must never mean loss of the account"* with:

> Recovery is available exactly to a set satisfying the recovery policy committed at genesis. An account whose genesis committed `alg = 0x00`, or whose committed recovery factors are all lost, is **not recoverable**, and this is a deliberate property. Any design guaranteeing recovery from the loss of every factor necessarily grants some party a path to take an account without the holder, because recovery-from-nothing and takeover-from-nothing are the same operation viewed from two sides.

### The defect that must be fixed before this ships: the thief-rotate flood

A `ROTATE` that does not change the recovery commitment is effective immediately; a `RECOVER` always waits Δ. So a thief holding the active key rotates at sequence *n*, instantly. The owner's `RECOVER` is now stale against a new tip and must be rebuilt at *n+1*. The thief rotates again. **Cost to the thief: one signature per attempt, forever.** No cancellation is ever used, so escalation rules keyed on cancellations do nothing.

"Only a satisfying set of the recovery policy *can* recover" stays true. "A satisfying set of the recovery policy *can* recover" becomes false precisely when an adversary holds the active key, which is the primary scenario recovery exists for.

**Required fix:** a pending `RECOVER` **freezes** rotation. Once a valid `RECOVER` is sequenced, `ROTATE` is refused until the window closes. The rotation-versus-recovery race must not be winnable by whoever can sign fastest.

**Second defect: `RecoveryCancel` is misassigned.** Cancellation by the *current active key* protects only the case where the owner still holds that key, which is not the recovery case. In a genuine recovery the owner does not hold it, so the cancellation window as designed protects the thief rather than the owner. Cancellation authority must come from a genesis-committed factor, not from the active key.

---

## 4. Federation genesis and trust chain

```
pinned FederationGenesis (threshold governance key set, distributed out of band)
  -> governance key transitions (co-signed old set and new set, threshold at both ends)
  -> registry roots: HomeserverRegistry | VerifierRegistry | PolicyRegistry | WitnessRegistry
  -> member / verifier / witness identities (each self-signed, governance only admits or revokes)
  -> checkpoints (logRoot, stateRoot, seqTime) + witness co-signatures
  -> authenticated state
  -> resolver proofs
```

**The bootstrap honesty problem, stated rather than hidden.** `FederationGenesis` v1 is signed by the keys it enumerates. That is unavoidable, and it is exactly why it must travel out of band: pinned in first-party client builds, published at a well-known location, and verifiable by fingerprint comparison across independent channels. A third-party client or a new member obtains it the same way, out of band, or it obtains nothing trustworthy.

**Corrections carried from review:**

- **Witness circularity.** The witness key set cannot live inside the object witnesses attest, or verification is circular at the step that matters. Witness identities belong in a registry rooted in genesis, verified *before* any checkpoint they co-sign is accepted.
- **`RECOVER` for a homeserver is a takeover path** if governance quorum plus a new key suffices and mandatorily installs a fresh key. Bound it: quorum excluding the destination, published delay, and no silent identity continuity.
- **Divergent genesis chains.** A governance quorum can produce two valid `FederationGenesis` successor chains and show different clients different ones. Threshold signatures do not prevent equivocation. Only independent witnessing or out-of-band fingerprint comparison detects it.
- **Witness independence is theatre while one operator exists.** Say so. Build the *format* and the verification path now so it is not a rewrite, and do not claim the guarantee until a second operator holds witness keys.

---

## 5. Revised VOPRF lifecycle: A is solved

**This is the good news, and it demotes what R1 called its most important open question.**

**Attribution, precisely.** RFC 9497 specifies OPRF, VOPRF and POPRF in prime-order groups, ciphersuites and test vectors, assuming a **single** server holding `skS`. It specifies **neither threshold operation nor key rotation**; its only rotation mentions are advisory Security Considerations text. **[LIT]** Do not cite it for either.

**A. Routine operator and share rotation, with a stable logical key: solved.**
- **[LIT]** TOPPSS (Jarecki, Kiayias, Krawczyk, Xu, ACNS 2017), construction `2HashTDH`: each server returns `a^(λ_i · k_i)` for Lagrange coefficients relative to the chosen evaluation set, and `Σ λ_i·k_i = k` for **any** qualified subset. The output depends only on `(x, k)` and not on which shares participated. Realises the UC T-OPRF functionality under T-OMDH in ROM.
- **[LIT]** Proactive refresh: Herzberg, Jarecki, Krawczyk, Yung (CRYPTO 1995) refresh shares by adding shares of a random polynomial with `g(0) = 0`, so the secret is unchanged. Dynamic committees, so operators can join and leave: Baron, El Defrawy, Lampkins, Ostrovsky (ACNS 2015) and CHURP (CCS 2019), which also changes the threshold while preserving the secret.
- **[LIT]** Proactive + verifiable + threshold specifically: Baecker et al., "A Fully-Adaptive Threshold Partially-Oblivious PRF" (CRYPTO 2025), repairing key-refresh and non-verifiability gaps in earlier models.

**Therefore: routine rotation does not change the routing key.** The cross-epoch uniqueness problem does not arise in normal operation, and the uniqueness invariant is stated per identifier per **logical** key. R1's A2 is demoted from a blocking open question to an emergency-only concern.

**B. Replacement of the logical key after compromise: a genuine emergency migration, and harder than it looks.**

RFC 9497's `Finalize` computes `Hash(len(x) || x || len(unblinded) || unblinded || "Finalize")`. **The raw input `x` is inside the final hash.** So the RFC's output is **not key-homomorphic and cannot be re-keyed by any party that does not hold `x`.** With the RFC construction, case B requires re-derivation by a party holding raw identifiers.

**[LIT]** Pythia (Everspaugh, Chatterjee, Scott, Juels, Ristenpart, USENIX Security 2015) supports bulk rotation of previously obtained outputs via a compact constant-size token, because its output form differs. **[LIT]** Jarecki, Krawczyk, Resch (CCS 2019) add non-interactive update after key rotation.

**This is a real design fork:** if Gua wants case-B bulk re-keying without touching raw identifiers, it must adopt a Pythia-style updatable construction rather than plain RFC 9497. Decide before implementing, because it is not a later swap.

**Correction carried from review:** the case-B safety argument leans on a `voprfKeyGeneration` label the client learns from the party the label constrains. A client with no pinned checkpoint, or one whose pinned state predates the change, can be rolled back to the compromised generation. The generation must be anchored in the checkpoint chain and clients must refuse to go backwards. And "atomic at a checkpoint" is not honest for an operation the same design costs at hours; state the overlap window and what holds during it.

### Authenticated current state, concretely

Append-only mutation log **plus** an authenticated map; checkpoint carries `(logRoot, stateRoot, seqTime)` with witness co-signatures. Recommendation: an **indexed Merkle tree with sorted-neighbour non-membership**, over a sparse Merkle tree, for proof size and cheap phone-side verification.

`/resolve` returns, in one response: binding membership proof, or non-membership proof; current placement proof; and the co-signed checkpoint for freshness. A client verifies the checkpoint signatures against the governance chain from pinned genesis, then verifies both proofs against `stateRoot`, then confirms `stateRoot` is tied to `logRoot` at that checkpoint so the map provably reflects the log.

---

## 6. Remaining attacks and open questions

**Attacks that still work**

1. **A1, the live OTP-to-session bypass.** Unchanged from R1 §0. **Compromise required: none. One SMS.** Still the highest-priority item in any of these memos.
2. **Thief-rotate flood**, until pending-recovery freezes rotation.
3. **`ADOPT_ROOT` seizure**, until it requires a fresh possession proof plus delay.
4. **Governance-quorum genesis divergence**, until independent witnesses exist.
5. **Generation-1 squat** remains at *verifier operator + one homeserver operator*, for rooted and bootstrap accounts alike. Account authority does not change this.

**Open questions**

1. **Pythia-style updatable construction, or plain RFC 9497?** Decide before implementation. This is the fork with the longest tail.
2. **Cancellation authority** for recovery, given it cannot be the active key.
3. **Whether witnessing is worth building before a second operator exists**, beyond the format.
4. **What a client does when its pinned genesis is `k` versions behind**, without creating a downgrade path.

**For a cryptographer, exact questions**

- Is `2HashTDH` composed with CHURP-style dynamic proactive refresh sound as a single system, and does verifiability survive the composition?
- Does a Pythia-style updatable pOPRF meet Gua's requirement that a routing key be stable across share refresh *and* bulk-updatable on logical-key compromise, and what is the concrete construction?
- What is the correct binding of the VOPRF public key and generation into the checkpoint chain to prevent generation rollback?

---

## 7. Precise replacements to ADM-001-R1

**R1 §4, decision 7**: replace `accountId = H(rootAlg || rootPublicKey)` with `accountId = "ga1" || base32(0x01 || 0x01 || SHA-256(GENC(AccountGenesis)))`, and add GENC as a named requirement with the "no delimiters, hash only received bytes" rules.

**R1 §1, I10**: replace with the boundary wording in §3 above. Delete "loss of the root key must never mean loss of the account".

**R1 §4, decision 8**: B1 is demoted to a bootstrap path with a defined end, marked in state so an auditor can tell rooted from bootstrap accounts. **Add the correction**: account authority does not improve the generation-1 compromise condition; its value is rotation, recovery, migration authorization and recycling continuity.

**R1 §2.1**: replace the B1 floor/ceiling framing with the four-message sequence in §2 above, including the allocation-signed candidate **set** rather than a single destination, and the explicit statement that `RC` is a binder rather than a gate.

**R1 §3, A4**: replace "name exactly one out-of-band root" with the `FederationGenesis` threshold object and the chain in §4 above.

**R1 §3, A2**: demote from the headline open question to case B only, with the attribution in §5 and the note that RFC 9497 covers neither threshold nor rotation.

**R1 §5, open question 1**: replace with the Pythia-versus-RFC-9497 fork.

**R1 §5**: add: cancellation authority for recovery; genesis version skew.

---

## Appendix: the pattern, one more time

Three of four tracks failed review, and the failure was again the generation-1 species: **the first object in every chain has no predecessor, and every design gave that first object weaker protection than the ones that follow.** The account genesis has no delay, no notification, no log leaf. `FederationGenesis` v1 is signed by the keys it enumerates. The VOPRF generation label is learned from the party it constrains.

That is not a bug to fix once. It is the structural cost of bootstrapping trust, and the only honest response is to make each first object expensive to produce, distributed out of band, and verifiable by comparison across channels, rather than to keep adding a layer that inherits the same hole.
