# Migration to ADM-001

> **Status: target architecture, governed by [ADM-001](../decisions/ADM-001-identifier-binding-placement-trust.md).**
> The path from `main` to the frozen target, superseding the [July 2026 plan](history/gua-resolver-migration-plan-2026-07.md) (phases 0 to 3 done).

"Today:" marks current `main` behaviour.

## Starting point

identity-service is the only OIDC provider and credential store for every homeserver. The OIDC subject is the full Matrix ID, fusing identity and placement. The resolver routes from roster and policy, storing no placement; the shared directory still holds the rows written before its write endpoint was removed. Each environment runs one resolver in `AUTHORITY` mode at `k = 1, n = 1`, and one operator holds every key.

## Phase 0: remove the two live paths

Status: complete, 2026-09-11. Both paths are gone from `main`; see the implementation status in [../decisions/README.md](../decisions/README.md).

**Goal**

Close two unsafe legacy paths.

**Changes**

- Delete the legacy non-interactive `phone_number` + `otp_code` branch of identity-service's `GET /oauth2/authorize`. The endpoint stays for the interactive flow. Done 2026-09-11: the non-interactive branch is gone and an authorization code is issued only by the interactive `/login/**` flow.
- Delete `POST /directory/entries` and its caller in `ResolverDirectoryClient`. Done 2026-09-11: the endpoint and the identity-service client that called it are both gone.

**Validation**

- A `phone_number` + `otp_code` request to `/oauth2/authorize` no longer produces an authorization code.
- The normal interactive OAuth flow still completes.
- `POST /directory/entries` is gone.

**Rollback**

Revert the two commits.

## Phase 1: self-signed roster entries

**Goal**

The authority alone can no longer rewrite roster entries.

**Changes**

- Today: an entry can carry the member's own signature over its endpoint, key and search fields (`gua-member-entry.v1`, encoded with `gua-lp.v1`, never `CanonicalRoster`'s delimiter form); the key an operator is admitted with is retained as the anchor of that chain; a member adopts, moves or re-keys its entry through `POST /authority/roster/{id}/member`, and each accepted attestation is committed to the log as a `MEMBER_ATTEST` leaf.
- Today: entries with no member signature are still served and counted. The transition flag `gua.resolver.roster.require-member-signature` is off in both environments until every ACTIVE member has been attested (`docs/runbooks/member-attestation.md`).
- Clients verify the member signature and refuse entries without one. Not started: client enforcement is Phase 6.

**Validation**

- Both testbed homeservers re-admit with retained genesis keys; a substituted `baseUrl` fails client verification.

**Rollback**

A transition flag tolerates missing self-signatures; remove it afterwards.

**Blocked by**

O2 (canonical self-signed entry encoding), L4. Decided for roster, member and governance objects in [ADM-007](../decisions/ADM-007-canonical-encoding-and-member-entries.md), which unblocked this phase.

## Phase 2: separate governance keys

**Goal**

Governance signing leaves the resolver process and is anchored in a pinned federation genesis.

**Changes**

- Today: the resolver loads a pinned `FederationGenesis` with its threshold set of governance keys, verifies it against the id it is pinned to, applies any governance key transitions, and publishes it at `GET /.well-known/gua-federation`. The four registry roots (`HomeserverRegistry`, `VerifierRegistry`, `PolicyRegistry`, `WitnessRegistry`) are named in it; only `HomeserverRegistry` has a code path.
- Today: that governance key set, held outside the resolver, signs membership epochs. A signed `HomeserverRegistry` epoch is submitted through `POST /authority/registry/homeservers/epoch`, verified back to the genesis with the threshold counted by `operatorId`, committed to the log as a `MEMBERSHIP_EPOCH` leaf, and served at `GET /registry/homeservers/epoch/current|{n}`.
- Today: with `gua.resolver.governance.required` on, the resolver's key can no longer admit or change a member's status. An admission lands `PENDING` and stays out of the signed roster entirely until an epoch admits it, and a suspend or revoke records intent only, on the log as a `STATUS_INTENT` leaf; an epoch is what makes either take effect. The flag is off in both environments until the key ceremony has run (`docs/runbooks/governance-keys.md`).
- Today: `gua.resolver.genesis.expected-chain-head` pins how far the governance key transition chain has run, so a truncated or removed transitions file is a startup failure rather than a silent downgrade to a key set that was rotated out.
- Today: policy signing has left the process. `POST /authority/policy/sign` is replaced by `POST /authority/policy/validate`, which validates against the live roster and reports whether the bundle verifies under the governance keys; bundles are signed offline with the governance tool.
- Today: both trust-root changes are gated on `gua.resolver.governance.required`. With it on, `RoutingClaimsVerifier` fails closed on an unset trusted-key list and `RoutingPolicyVerifier` verifies under the governance key set with no fallback to the authority keys. With it off, both keep their pre-cutover behaviour exactly, because an environment's deployed policy bundle is signed with the operational key and narrowing the root under it stops the service starting. `RoutingPolicySigner` has no authority fallback either way: it cannot affect startup or serving, and nothing in the process calls it once signing moved offline.
- Accreditations are Phase 5, witnesses Phase 9, and a PolicyRegistry epoch object is deferred until `IdentifierProofPolicy` needs it.
- Clients pin the genesis per environment. Not started: client enforcement is Phase 6, so the chain is data to them, not a gate.

**Validation**

- Governance signatures from the operational key alone are rejected once the flag is on, and the application is booted in both shapes to prove it: the deployed shape (operational-key bundle, no genesis, flag off) starts and serves, the governed shape starts, and the operational-key bundle under the flag fails startup with the signature error rather than being accepted (`src/test/java/global/gua/resolver/startup`).
- Membership and policy verify back to the pinned genesis; a genesis file that does not match the pinned id fails startup.
- With the flag on, a direct admission cannot become ACTIVE without an epoch, and is not served in any form before one.
- A transitions file shorter than the pinned chain head fails startup.

**Rollback**

`gua.resolver.governance.required=false` restores the direct admission path AND both verifier fallbacks, without a code rollout: the membership path and the two trust roots are gated on that one flag. Only in-process policy signing is gone for good, and it needs no rollback because it is neither on the startup path nor on any request path. A genesis already pinned in client builds stays; clients do not enforce it before Phase 6.

**Blocked by**

Was blocked by S5. Unblocked by the minimal custody rule in [ADM-007](../decisions/ADM-007-canonical-encoding-and-member-entries.md) "Phase 2 objects" (key held off-cluster, encrypted at rest, offline backup, never a Kubernetes Secret in a resolver namespace, manual signing, `k = 1` at one operator stated plainly). S5 itself stays open: nothing here makes the governance key set a genuinely separate trust domain.

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
- The verifier's accreditation is governance-signed under Phase 2's keys and records `operatorId` as a lookup key.
- Existing identifiers get binding records attested by that verifier; `IdentifierProofPolicy` publishes `k = 1` for phone.
- The threshold counts independently governed verifier trust domains, resolved through accreditation. `operatorId` is a lookup key, not the security boundary. Do not reuse `RosterVerifier`, which counts keys.

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
- Verification ships in shadow (log-only) mode first. Enforcement waits for the pinning semantics decision.

**Validation**

- Shadow mode reports unverifiable responses without blocking any connection.

**Rollback**

Turn enforcement off; shadow mode keeps reporting.

**Blocked by**

O10 (pinning semantics), for enforcement only. Phase 2 (pinned genesis).

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
