# Gua Federation Routing — Resolver / Roster / Placement design

> Status: design approved (prototype build starting). This is the canonical design for how Gua clients
> discover *which homeserver* they belong to, how the federation's membership is tracked and trusted,
> and how new accounts are placed. It is implemented by the **gua-resolver** service.

## 0. The core framing — "routing" is three different jobs

Most confusion dissolves once these are kept separate. They have different trust, scaling, and
consistency properties:

| Job | What it does | Read/write | Trust | Scale |
|---|---|---|---|---|
| **Resolution** (front door) | phone/username → which homeserver | read-mostly, cacheable | public-ish | huge, trivial to replicate |
| **Roster** (membership) | the set of homeservers that exist + endpoints | read-mostly, rare writes | **authority-gated** | tiny, signed, freely mirrorable |
| **Placement** (write policy) | which homeserver a *new* account is created on | write, at provisioning | home operator's policy | low volume |

The **gua-resolver** service owns Resolution + Roster (+ the Placement *engine*); the **identity-service**
IdP performs the Placement *decision at provisioning time* and remains the credential authority.

## 1. Why a separate service (not inside identity-service)

identity-service is the credential-holding IdP (OTP/PIN/MAS upstream/Twilio). The Resolver is the global
front door every client and every federated operator must reach. Keep them apart because:

- **Trust surface** — don't bolt the global front door onto the secret-holding component; and other
  operators must be able to run a Resolver *mirror* without running your IdP.
- **Scaling profile** — Resolution is read-only, cacheable, anycast-able, ~zero compute; the IdP is
  stateful and crypto-heavy. Scale independently.
- **Replication/sovereignty** — a roster + resolver can be safely mirrored by anyone; the IdP cannot.

Placement *policy* stays adjacent to provisioning (identity-service calls the resolver's placement
engine, then atomically creates the account + writes the directory entry).

## 2. Universal client routing — end to end (iOS + web)

The missing piece is a **pre-auth resolve step**. Today clients pick a homeserver from build config
(`GuaDefaultAccountProvider`) and run OIDC against it. The change:

1. Client captures phone → `POST /resolve` → `{exists, homeserver:{base_url, mas_issuer, region}}` or
   `{exists:false, register_at:{…}}`.
2. Client runs **standard Matrix OIDC** against *that* homeserver's MAS, `login_hint=phone`.
3. New phone → resolver returns the placement homeserver → OIDC-register there.

- **iOS (gua-ios):** the plumbing already accepts a dynamic homeserver
  (`AuthenticationClientFactory.makeClient(homeserverAddress:)`, `AuthenticationService.configure(for:)`,
  `urlForOIDCLogin(loginHint:)`). Insert the resolve call; feed it the resolved address instead of
  `GuaDefaultAccountProvider`. The only hardcoded value becomes the **resolver entry point** (anycast +
  small bootstrap fallback list — like DNS root hints), not a homeserver.
- **web (gua-web / Element Web fork):** same pre-auth resolve step in the Gua login screen before OIDC.
- **Android (later):** same contract, new repo at feature-parity time.

Phase 1 works with a single homeserver (resolver returns the one homeserver) — wiring the client
indirection now makes the clients universal-ready and is the prerequisite for everything else.

## 3. How the roster learns about a new homeserver

A new institution/carrier stands up a Gua homeserver — the network must learn it **safely** (no box may
inject itself and hijack phone→homeserver mappings). This is a membership + trust problem, solved with a
**signed roster + admission control**, distributed by pull (precedent: Tor directory consensus, a DNS
zone, a CA trust store):

1. **Enrollment/admission** — operator applies; the federation **authority** vets (domain-ownership
   proof + policy/endorsement), issues a `homeserver_id` + membership credential, records the entry
   `{server_name, base_url, mas_issuer, region, weight, accepts_new, signing_key, claim_predicates}`.
2. **Signed roster** — the entry joins a versioned roster, **threshold-signed** by the authority set
   (see §5), built on top of each homeserver's existing Matrix signing key.
3. **Distribution (pull)** — every resolver/IdP periodically fetches the roster (HTTP+ETag or pub/sub),
   **verifies signatures + transparency-log inclusion**, and serves it. New HS propagates within a
   refresh interval; compromise → authority publishes a revocation.
4. **Existing accounts on the new HS** — the homeserver is the **authoritative writer** for its own
   accounts: it writes their `phone_hash → homeserver_id` rows to the shared directory, authenticated by
   its membership credential (can only write for accounts it hosts → no hijacking).
5. **New accounts routed there** — placement is a **policy over roster metadata** (§6). The entry's
   `claim_predicates` + `region`/`weight`/`accepts_new` make it a candidate automatically — adding a
   carrier = adding a signed roster entry, no redeploy.

## 4. Federated resolver instances (institutions running their own)

Desirable for availability/latency/sovereignty — **but split read from authority**:

- **Roster (public)** — freely mirrorable. An institution's resolver pulls the signed roster, verifies it
  against the authority's published keys + the transparency log, and serves it. More mirrors = more
  availability.
- **Authority (admission + roster signing)** — **not** freely replicable; the trust root. Held by a small
  threshold set of directory authorities (§5). An institution runs a **cache**, not an authority.
- **Phone→homeserver directory (sensitive!)** — do **not** bulk-replicate the phone graph to every
  institution (PII + enumeration risk). Keep it centrally/regionally authoritative with replicated
  **read caches** that institutions *query* (rate-limited, peppered-HMAC, no bulk export). Each HS still
  writes only its own accounts' entries.

So a mirror syncs by: pull+verify the **signed roster** (public, full copy) and **query** the directory
(no bulk copy).

## 5. Trust & authority — verifiability without a PoW blockchain

**The question:** how do we admit homeservers/authorities openly (universities, nonprofits, enthusiasts)
without it becoming a security hole? Is blockchain the answer?

**Honest answer: take blockchain's *verifiability*, drop its *permissionless PoW consensus*.** Bitcoin
solves consensus among anonymous, mutually-distrusting validators with no admission control, paying for
it with PoW (energy, latency, throughput limits, token economics). Gua has the opposite situation:
**identifiable institutions that can be vetted.** Full PoW/token blockchain is the wrong tool — overkill,
operationally heavy, and a new attack surface that could "backfire" exactly as feared.

But the underlying instincts are right and map to lighter, battle-tested primitives:

| Your intuition (from Bitcoin) | The right primitive for Gua |
|---|---|
| Hash-linked history nobody can rewrite | **Merkle transparency log** (Certificate Transparency / Sigstore Rekor / Go checksum DB / git). Every admit/revoke/update is an append-only, hash-chained entry; anyone can audit it and gossip log heads to detect split-views. |
| No single node can forge truth | **Threshold / multi-signature authority** — roster validity requires *k-of-n* signatures from the directory-authority set (cf. Tor's ~9 dir auths, DNSSEC root KSK ceremony, multisig). One corrupt authority can't admit a malicious HS. |
| Corrupt nodes get rejected by the network | **Verify-on-read + revocation** — clients/resolvers verify threshold sigs + log inclusion before trusting a roster entry; bad actors are identifiable and revocable (logged). |
| Open participation | **Accountable on-ramp, not anonymity** — admission = domain-ownership proof + endorsement/policy, *publicly logged*. Openness comes from a clear, auditable on-ramp, not permissionless joining. Sybil-resistance via endorsements/web-of-trust, not PoW. |

**How new *authorities* are trusted over time:** authority-set changes are themselves threshold-signed by
the current set and appended to the transparency log. Start with **n=1 (Gua)**, grow toward a handful of
independent, reputable institutions holding keys. This is how CA programs, DNSSEC, and Tor evolve their
trust roots — gradual, accountable, auditable.

> A permissioned ledger *could* carry this log, but it isn't necessary: a Merkle transparency log +
> threshold signatures gives the same tamper-evidence and distributed trust with far less complexity and
> no token/PoW. **Recommendation: build that; do not adopt PoW/token consensus.**

### Authority model (initial → evolving)
- **Now:** Gua is the sole authority (n=1). Roster signed by one Ed25519 authority key; all changes in
  the transparency log from day 0 (so the audit trail exists before it's needed).
- **Next:** k-of-n threshold across a few independent institutions; published authority-key set;
  client/resolver gossip of log heads.
- **Later:** community endorsement / staking for admission; formal governance of the authority set.

## 6. Pluggable placement — a flexible rule engine

Placement must be **universal and flexible**: a carrier hosts a homeserver and claims its own numbers; a
university claims its affiliates; a region claims by area code; otherwise spread by weight. Design:

**Placement = an ordered pipeline of rules** over a `PlacementContext` (E.164 phone + derived country /
MCCMNC / carrier, affiliation assertions, region hint, gov-id claims, custom attributes). Each rule
returns a homeserver candidate or **abstains**; the first match (by priority) wins; deterministic.

Two kinds of rules:

- **Claim rules (operator-declared, authoritative, data-driven):** each homeserver's *roster entry*
  carries declarative `claim_predicates` — e.g. `{carrier: "Vivo"}`, `{country:"BR", phone_prefix:"+5511"}`,
  `{affiliation_domain:"usp.br"}`. Because they live in the **signed roster**, an operator can only claim
  what the authority admitted, and the authority **validates non-overlap** at admission (two carriers
  can't both claim the same range). Adding a carrier = adding a signed roster entry — **no code, no
  redeploy.**
- **Policy rules (federation defaults):** region match, weighted load-spreading, residency, fallback to
  default. Applied when no operator claim matches.

**Extensibility (SPI):** `PlacementRule { Optional<HomeserverId> evaluate(PlacementContext); int priority(); }`.
Built-ins: `CarrierClaimRule`, `PhonePrefixClaimRule`, `AffiliationClaimRule`, `RegionRule`,
`WeightedFallbackRule`. For logic beyond declarative matching (institution-specific membership checks),
a `RemoteClaimRule` calls the operator's own `/claims` webhook ("is this user yours?") — so an operator
can implement arbitrary placement logic **without shipping code into the resolver.**

**Carrier-agreement example (Brazil):** each participating carrier's roster entry declares
`claim_predicates: [{mccmnc: "72411"}]` (or carrier name / number range). A new BR signup whose verified
phone resolves to that carrier is placed on that carrier's homeserver automatically. A university entry
adds `{affiliation_domain: "usp.br"}` + a `RemoteClaimRule` webhook. Both coexist by priority; the
authority guarantees their predicates don't conflict.

**Determinism & consistency:** placement is a pure function of (context, current roster). The same
input yields the same homeserver, so re-resolution at login is stable. MXIDs are immutable, so placement
is decided once, at account creation.

## 7. Phasing
- **Phase 1 (now, dev):** stand up gua-resolver with `/resolve` + `/roster` returning the single dev
  homeserver; wire the iOS + web pre-auth resolve step; transparency log + single-authority signing in
  place from day 0 (even with one entry).
- **Phase 2 (2nd operator):** dynamic signed roster + admission flow; declarative claim predicates +
  placement engine; second homeserver proves cross-operator routing/federation.
- **Phase 3 (scale/sovereignty):** resolver/roster mirrors run by institutions; threshold (k-of-n)
  authority; community admission/endorsement; directory read-cache replication with abuse controls.
