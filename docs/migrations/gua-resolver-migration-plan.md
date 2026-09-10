# Migration to ADM-001

> **Status: TARGET ARCHITECTURE, governed by [ADM-001](../decisions/ADM-001-identifier-binding-placement-trust.md).**
> This is the path from the implementation on `main` to the frozen target. It replaces the July 2026 plan, which is preserved as [history/gua-resolver-migration-plan-2026-07.md](history/gua-resolver-migration-plan-2026-07.md). That plan introduced signed routing policy and mirrors and its phases 0 to 3 are done; its phases 4 and 5 are superseded by what follows.

Each phase is independently valuable, has a rollback, and does not depend on a later phase. Phases are ordered by risk reduction, not by how much architecture they deliver. The first two remove live defects and would be worth doing even if nothing else here were ever built.

Tags: **[CODE]** what exists on `main`. **[TARGET]** what the phase delivers.

---

## Where we are starting from

**[CODE]** identity-service is the single OIDC provider and the sole credential store for every homeserver. Each homeserver's MAS delegates upstream to it with the same client id and provider id, differing only by redirect URI. The OIDC subject is the full Matrix ID, so identity and placement are the same string. The resolver computes routing per request from roster and policy and persists no placement. The shared directory is empty; the accounts that exist are recorded only in identity-service, with `homeserver_id` set to `default` for every one, including an account that a federation test proved lives on a second homeserver. Both environments run a single resolver in `AUTHORITY` mode at `k = 1, n = 1`, and one operator holds every key.

Two paths are live that ADM-001 identifies as defects:
- `GET /oauth2/authorize` with `phone_number` and `otp_code` issues an authorization code on OTP alone, with no PIN, passkey or registration check, on a public client.
- `POST /directory/entries` lets any active member bind any phone number to itself with no uniqueness check.

---

## Phase 0: remove the two live paths

**Delivers:** ADM-001 L1a and L1b.

- Delete the legacy non-interactive branch of `GET /oauth2/authorize` in identity-service.
- Delete `POST /directory/entries` and its client in identity-service's `ResolverDirectoryClient`.

**Validation:** the endpoints return 404; the interactive login flow is unaffected; no client on `main` calls either path.

**Rollback:** revert the two commits. Nothing else depends on them.

**Why first:** neither needs any new concept, and each is exploitable today with no compromise of any key.

---

## Phase 1: homeserver self-signed roster entries

**Delivers:** ADM-001 L10's chain from member identity to endpoint metadata. Closes the attack where a compromised authority rewrites a member's address and keys with every placement signature still verifying.

- Admission retains the member's genesis key, not only a possession proof over `serverName`.
- Each roster entry carries a self-signature by the member over its own endpoint and key metadata.
- Clients verify the self-signature after the authority signature, and refuse an entry without one.

**[CODE] today:** `AdmissionService` verifies key possession over `serverName` only and does not retain the key; `RosterEntry` has no self-signature field; `CanonicalRoster` signs `baseUrl`, `masIssuer` and `signingKey` under the authority alone.

**Validation:** the existing federation testbed re-admits both homeservers with retained genesis keys; a roster rebuilt with a substituted `baseUrl` fails client verification.

**Rollback:** clients tolerate the missing self-signature behind a flag during the transition, then the flag is removed.

**Dependency note:** the exact canonical encoding of the self-signed entry is ADM-001 O2. Do not copy `CanonicalRoster`'s delimiter form; see L4.

---

## Phase 2: separate governance keys from the operational authority key

**Delivers:** the precondition for every "two trust domains" guarantee in ADM-001, in particular L7 and L8.

- Membership epochs and verifier accreditations are signed by a key set the resolver process does not hold.
- The resolver's own key signs checkpoints and serves records; it can no longer accredit a verifier or admit a member.
- `RoutingClaimsVerifier` must fail closed when its trusted-key list is unset, instead of falling back to the authority keys. **[CODE]** It falls back today, and dev runs in that state.

This phase is organisational before it is technical: it needs a second key holder, a custody procedure, and a recovery plan for the governance keys. ADM-001 S5 covers the questions. Until it exists, every independence guarantee in the target reduces to compromising one operator, and the documentation must say so.

**Rollback:** the operational key retains governance powers until the cutover commit; revert restores them.

---

## Phase 3: introduce `AccountGenesis` and `accountId` alongside the Matrix ID

**Delivers:** ADM-001 L4 and L5, without changing anything that routes or authenticates yet.

- New accounts created by first-party clients generate an `AccountGenesis` on device and register its `accountId`.
- Existing accounts receive an `accountId` through a bootstrap path marked as such in state, so an auditor can distinguish rooted from bootstrap accounts. The path by which a bootstrap account later gains real authority is ADM-001 O9 and is not built in this phase.
- **Nothing reads `accountId` for routing or login in this phase.** It is populated and verified, and that is all.

**Hazard, from ADM-001 S6:** the account id must not be substituted into any field that MAS derives a localpart from. **[CODE]** `routeExistingUser` derives `preferredUsername` from `localpartOf(userId)` and ignores the directory's username column; re-keying `user_id` to a value containing a colon, with `on_conflict: add` live, silently merges every returning user onto one account. Sever that derivation before this phase, and audit every path that derives a localpart from a user id.

**Rollback:** drop the column. No consumer exists yet.

---

## Phase 4: placement records for existing accounts

**Delivers:** ADM-001 L6's committed placement, for accounts that already exist.

- For each existing account, discover its true placement from the one place it is recorded today: **[CODE]** each MAS's `upstream_oauth_links` table. The directory's `homeserver_id` column is not a source; it reads `default` for every account.
- Each holding homeserver signs a generation-1 placement record for the accounts it holds.
- Run the resolver in **comparison mode**: answer from policy as today, but also compute what the placement record would answer, and log every disagreement. Do not serve from records yet.

**Validation:** zero disagreements on the accounts that were placed by policy; exactly the known disagreements for accounts the testbed placed elsewhere.

**Rollback:** records are additive; comparison mode is a flag.

---

## Phase 5: binding records and the first accredited verifier

**Delivers:** ADM-001 L7 and L8, at `k = 1`.

- identity-service's phone verification becomes the first accredited verifier. Its accreditation is governance-signed under Phase 2's separated keys, with `operatorId` recorded.
- Binding records are written for existing identifiers, attested by that verifier, and the `IdentifierProofPolicy` is published with `k = 1` for phone.
- The attestation-counting rule dedupes on `operatorId`, not on key id. **[CODE]** `RosterVerifier` dedupes on key id today and must not be reused as is.

**Validation:** a binding whose attestation is not signed by an accredited operator is rejected with a logged rejection leaf.

**Rollback:** bindings are additive; the resolver continues to answer from Phase 4 records.

---

## Phase 6: clients verify before they connect

**Delivers:** the point at which ADM-001's guarantees stop being inert. Until this phase, nothing checks a signature and every guarantee that limits the resolver's power is a design intention.

- The client verifies the roster chain from pinned federation genesis, the member self-signature, the binding and placement records, and the checkpoint, before handing a homeserver address to the SDK.
- **[CODE] today:** both clients take `baseUrl` from the resolver response verbatim.
- A client with no pinned state trusts the first checkpoint it sees for that account and pins it; behaviour on a later chain change is ADM-001 O10 and must be decided before this phase ships, because a naive fail-closed rule makes an attacker's early pin permanent.

**Rollback:** verification runs in log-only mode first, reporting failures without blocking.

---

## Phase 7: authentication moves to the homeserver bundle

**Delivers:** ADM-001 L2 as an operational fact rather than a target. This is the largest phase and gets its own decision record before it starts.

- Each homeserver's MAS gains local authentication for the mechanisms it supports, starting with passkeys verified by the homeserver rather than centrally. ADM-001 O11 governs how a client finds the right homeserver before the ceremony.
- identity-service's remaining role is decided in that record. The candidates are: a federation verifier only, holding no login credentials; or retirement.

**Dependency:** the OIDC subject question from ADM-001 S6. **[CODE]** MAS keys upstream links on `(provider ULID, subject)` with a unique index and cannot rewrite a subject, so any change to what the subject means is a new provider row plus a link association pass, never an in-place update.

---

## Phase 8: blinded routing keys

**Delivers:** ADM-001 L15.

**Gated on ADM-001 S1**, cryptographic review of the threshold construction, and on the O4 decision between a plain RFC 9497 instantiation and an updatable construction. Do not start this phase before both are settled; the choice is not a later swap.

---

## Phase 9: independent witnesses

**Delivers:** the equivocation-resistance and integrity properties of ADM-001 L11 and L12.

**Gated on a second operator existing.** Build the checkpoint format and the witness verification path earlier so this is not a rewrite; do not claim the guarantee until a second party holds witness keys.

---

## What is deliberately not in this plan

- **Account recovery.** ADM-001 L13 sets four requirements and defers the mechanism to its own record.
- **Matrix identity migration between homeservers.** ADM-001 L9: Matrix has no native operation preserving device keys, cross-signing, room membership or history across a homeserver change. Gua placement migration is a separate problem and any tooling that claims to preserve those properties needs its own demonstration.
- **Catastrophic governance-key loss.** ADM-001 O13.
