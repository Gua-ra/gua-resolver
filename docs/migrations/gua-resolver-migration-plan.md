# Migration to ADM-001

> **Status: target architecture, governed by [ADM-001](../decisions/ADM-001-identifier-binding-placement-trust.md).**
> The path from `main` to the frozen target, superseding the [July 2026 plan](history/gua-resolver-migration-plan-2026-07.md) (phases 0 to 3 done).

"Today:" marks current `main` behaviour.

## Starting point

identity-service is the only OIDC provider and credential store for every homeserver. The OIDC subject is the full Matrix ID, fusing identity and placement. The resolver routes from roster and policy, storing no placement; the shared directory is empty. Each environment runs one resolver in `AUTHORITY` mode at `k = 1, n = 1`, and one operator holds every key.

## Phase 0: remove the two live paths

**Goal**

Close two paths exploitable without any key compromise.

**Changes**

- Delete identity-service's legacy non-interactive `GET /oauth2/authorize` branch. Today: an OTP alone yields an authorization code, with no PIN, passkey or registration check.
- Delete `POST /directory/entries` and its caller in `ResolverDirectoryClient`. Today: any active member can bind any phone number to itself, with no uniqueness check.

**Validation**

- Both endpoints 404; interactive login still works.

**Rollback**

Revert the two commits.

## Phase 1: self-signed roster entries

**Goal**

The authority alone can no longer rewrite roster entries.

**Changes**

- Today: `AdmissionService` checks possession then drops the key; entries carry no self-signature; only the authority signs.
- Admission retains the member's genesis key.
- Each entry carries a member self-signature over endpoint and key metadata (not `CanonicalRoster`'s delimiter form); clients verify both and refuse entries without one.

**Validation**

- Both testbed homeservers re-admit with retained genesis keys; a substituted `baseUrl` fails client verification.

**Rollback**

A transition flag tolerates missing self-signatures; remove it afterwards.

**Blocked by**

O2 (canonical self-signed entry encoding), L4.

## Phase 2: separate governance keys

**Goal**

Governance signing leaves the resolver process.

**Changes**

- Today: `RoutingClaimsVerifier` falls back to the authority keys when its trusted-key list is unset, and dev runs that way.
- A governance key set outside the resolver signs membership epochs and accreditations. Until a second key holder, custody and recovery procedures exist, every independence guarantee reduces to one operator; documentation must say so.
- The resolver's key signs checkpoints and serves records; it can no longer admit or accredit.
- `RoutingClaimsVerifier` fails closed on an unset trusted-key list.

**Validation**

- Governance signatures from the operational key alone are rejected.

**Rollback**

Revert the cutover commit; the operational key regains governance powers.

**Blocked by**

S5.

## Phase 3: `AccountGenesis` and `accountId`

**Goal**

New accounts get an on-device `AccountGenesis`; every account gets an `accountId`. Routing and login do not change.

**Changes**

- Today: `routeExistingUser` derives `preferredUsername` from `localpartOf(userId)`. Re-keying `user_id` to a value containing a colon, with `on_conflict: add` live, merges every returning user onto one account.
- New first-party accounts generate an `AccountGenesis` on device and register its `accountId`, never in a field MAS derives a localpart from.
- Existing accounts get a bootstrap `accountId`, marked so auditors can tell them apart; adoption comes later.

**Validation**

- `accountId` is populated; nothing reads it yet.

**Rollback**

Drop the column.

**Blocked by**

Severing that derivation in `routeExistingUser` (the S6 trap) and auditing every other localpart derivation.

## Phase 4: placement records for existing accounts

**Goal**

Record where each existing account really lives.

**Changes**

- Today: the directory's `homeserver_id` reads `default` for every account, including one a federation test proved lives elsewhere.
- Only each MAS's `upstream_oauth_links` table records true placement.
- Each holding homeserver signs a generation-1 placement record for its accounts.
- Comparison mode: answer from policy as today, log where the record disagrees, serve nothing from records yet.

**Validation**

- Zero disagreements except the known testbed placements.

**Rollback**

Records are additive; comparison mode is a flag.

## Phase 5: binding records and first verifier

**Goal**

Identifier ownership becomes a signed, attested record; identity-service's phone verification is the first accredited verifier.

**Changes**

- Today: `RosterVerifier` dedupes on key id.
- The verifier's accreditation is governance-signed under Phase 2's keys and records `operatorId`.
- Existing identifiers get binding records attested by that verifier; `IdentifierProofPolicy` publishes `k = 1` for phone.
- Attestation counting dedupes on `operatorId`; do not reuse `RosterVerifier` as is.

**Validation**

- Unaccredited bindings are rejected and logged as rejection leaves.

**Rollback**

Bindings are additive; Phase 4 records still answer.

**Blocked by**

Phase 2.

## Phase 6: clients verify before connecting

**Goal**

Clients check signatures before connecting.

**Changes**

- Today: both clients take `baseUrl` from the resolver response verbatim.
- Before handing the SDK an address, the client verifies the chain: pinned genesis, roster, self-signature, binding and placement records, checkpoint.
- An unpinned client pins the first checkpoint it sees for that account. Decide chain-change behaviour before shipping: a naive fail-closed rule makes an attacker's early pin permanent.

**Validation**

- Log-only mode reports unverifiable responses; enforcement refuses them.

**Rollback**

Verification ships in log-only mode first.

**Blocked by**

O10 (pinning on a chain change).

## Phase 7: authentication moves to homeservers

**Goal**

Each homeserver authenticates its own users; its own decision record comes first.

**Changes**

- Today: MAS keys upstream links on `(provider ULID, subject)` with a unique index and never rewrites a subject.
- Each MAS gains local authentication, passkeys first. A new subject meaning is a new provider row plus a link association pass, never an in-place update.
- Customer passkeys can ship through identity-service earlier; this phase moves the ceremony to homeservers.
- Pre-ceremony homeserver discovery stays an open decision, outside this phase. The Phase 7 decision record settles identity-service's remaining role: federation verifier without login credentials, or retirement.

**Validation**

- Set in that record.

**Rollback**

Set in that record.

**Blocked by**

That record. O11 (passkey discovery and relying party). S6 (OIDC subject migration).

## Phase 8: blinded routing keys

**Goal**

Keep raw phone numbers and email addresses out of replicated federation state.

**Changes**

- The construction cannot be swapped later, so both gates must settle first.

**Validation**

- Defined with the construction.

**Rollback**

Defined with the validation.

**Blocked by**

S1 (cryptographic review of the threshold construction). O4 (RFC 9497 versus an updatable construction).

## Phase 9: independent witnesses

**Goal**

A second party confirms the log neither equivocates nor miscomputes state.

**Changes**

- Build the checkpoint format and witness verification path earlier; claim nothing until a second party holds witness keys.

**Validation**

- A second operator's witness co-signs checkpoints.

**Rollback**

Nothing to roll back.

**Blocked by**

A second witness operator.

## Deliberately out of scope

- Account recovery: four requirements in the decision record; the mechanism gets its own record.
- Matrix identity migration between homeservers: nothing native preserves device keys, cross-signing, membership or history across a move; placement migration is separate.
- Catastrophic governance-key loss; deferred to its own decision.
