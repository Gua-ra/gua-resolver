# Resolver migration plan

> The path from `main` to the design in [federation work that is not built yet](../architecture/planned-federation-work.md). It supersedes the [July 2026 plan](history/gua-resolver-migration-plan-2026-07.md), whose phases 0 to 3 are done.

"Today:" marks current `main` behaviour.

## Starting point

identity-service is the only OIDC provider and credential store for every homeserver. The OIDC subject is the full Matrix ID, fusing identity and placement. The resolver routes from roster and policy, storing no placement; the shared directory still holds the rows written before its write endpoint was removed. Each environment runs one resolver in `AUTHORITY` mode at `k = 1, n = 1`, and one operator holds every key.

## Phase 0: remove the two live paths

Status: complete. Both paths are gone from `main`.

**Goal**

Close two unsafe legacy paths.

**Changes**

- The non-interactive `phone_number` + `otp_code` branch of identity-service's `GET /oauth2/authorize` is deleted. An authorization code is issued only by the interactive `/login/**` flow.
- `POST /directory/entries` and the identity-service client that called it are deleted.

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

- Today: an entry can carry the homeserver's own signature over its endpoint, key and search fields. The format is `gua-member-entry.v1` in the `gua-lp.v1` encoding.
- Today: the key an operator is admitted with stays as the first key of its entry chain. A homeserver adopts, moves or re-keys its entry through `POST /authority/roster/{id}/member`. Each accepted entry is logged as a `MEMBER_ATTEST` leaf.
- Today: entries with no member signature are still served and counted. `gua.resolver.roster.require-member-signature` is off in both environments until every active homeserver has signed its entry. See the [member attestation runbook](../runbooks/member-attestation.md).
- Not started: clients verifying the member signature and refusing entries without one. That is Phase 6.

**Validation**

- Both testbed homeservers re-admit with retained genesis keys; a substituted `baseUrl` fails client verification.

**Rollback**

A transition flag tolerates missing self-signatures; remove it afterwards.

**Blocked by**

Was blocked on the encoding of a self-signed entry. That is now specified in [signed federation objects](../specs/federation-signed-objects.md).

## Phase 2: separate governance keys

**Goal**

Governance signing leaves the resolver process and is anchored in a pinned federation genesis.

**Changes**

- Today: the resolver loads a pinned `FederationGenesis` with its governance keys and threshold, checks it against the pinned id, applies any governance key transitions and publishes the result at `GET /.well-known/gua-federation`. The genesis names four registries. Only `HomeserverRegistry` has a code path.
- Today: the governance keys are held outside the resolver and sign membership epochs. An epoch is submitted through `POST /authority/registry/homeservers/epoch` and verified back to the genesis, with the threshold counted by `operatorId`. It is logged as a `MEMBERSHIP_EPOCH` leaf and served at `GET /registry/homeservers/epoch/current` and `/epoch/{n}`.
- Today: with `gua.resolver.governance.required` on, the resolver's own key can no longer admit a homeserver or change its status. An admission lands `PENDING` and stays out of the signed roster until an epoch admits it. A suspend or revoke records a `STATUS_INTENT` leaf and takes effect only through an epoch. The flag is off in both environments until the key ceremony has run. See the [governance keys runbook](../runbooks/governance-keys.md).
- Today: `gua.resolver.genesis.expected-chain-head` pins how far the governance key chain has run. A truncated or missing transitions file fails startup, so a key set that was rotated out cannot come back.
- Today: policy signing has left the process. `POST /authority/policy/validate` replaces `POST /authority/policy/sign`. It checks a bundle against the live roster and reports whether it verifies under the governance keys. Bundles are signed offline with the governance tool.
- Today: the same flag gates both trust roots. With it on, `RoutingClaimsVerifier` rejects every envelope when its trusted-key list is unset, and `RoutingPolicyVerifier` verifies under the governance keys with no fallback to the authority keys. With it off, both behave as before. Each environment's deployed policy bundle is signed with the operational key, and narrowing the root under it would stop the service starting. `RoutingPolicySigner` has no authority fallback either way, and nothing in the process calls it.
- Later: accreditations are Phase 5 and witnesses Phase 9. A `PolicyRegistry` epoch object is deferred, and it must land before `IdentifierProofPolicy` shares that registry. See [federation genesis](../specs/federation-signed-objects.md#federation-genesis).
- Not started: clients pinning the genesis per environment. Client enforcement is Phase 6, so the chain is data to them, not a gate.

**Validation**

- Governance signatures from the operational key alone are rejected once the flag is on. The startup tests boot three shapes (`src/test/java/global/gua/resolver/startup`). The deployed shape, with an operational-key bundle, no genesis and the flag off, starts and serves. The governed shape starts. An operational-key bundle under the flag fails startup with the signature error.
- Membership and policy verify back to the pinned genesis; a genesis file that does not match the pinned id fails startup.
- With the flag on, a direct admission cannot become ACTIVE without an epoch, and is not served in any form before one.
- A transitions file shorter than the pinned chain head fails startup.

**Rollback**

`gua.resolver.governance.required=false` restores the direct admission path and both verifier fallbacks without a code rollout. In-process policy signing is gone for good and needs no rollback, because it is on neither the startup path nor a request path. A genesis already pinned in client builds stays. Clients do not enforce it before Phase 6.

**Blocked by**

Was blocked on governance key custody. Unblocked by the minimum custody rule in the [governance keys runbook](../runbooks/governance-keys.md#custody) (key held off-cluster, encrypted at rest, offline backup, never a Kubernetes Secret in a resolver namespace, manual signing, `k = 1` at one operator stated plainly). Whether a governance key set can be run by a genuinely separate party stays open.

## Phase 3: `AccountGenesis` and `accountId`

**Goal**

New accounts get an on-device `AccountGenesis`; every account gets an `accountId`. Routing and login do not change.

**Changes**

- Today: every account has an `accountId`. identity-service mints a bootstrap identifier at signup and backfills one for each existing account (`identity.genesis.enabled` and `identity.genesis.bootstrap-backfill.enabled`, both on by default). Passkeys use it as their WebAuthn user handle. Nothing else reads it, and `AccountIdNotReadGuardTest` fails the build if it reaches routing, login or a claim.
- Today: identity-service accepts an on-device `AccountGenesis` at `POST /account/genesis`, parses the `gua:` login hint and verifies the attach proof. Both apps carry the key store and the genesis builder behind a flag that is off.
- Today: the attach step cannot run in the deployed flow. The signup profile step runs in a web view with no channel to the key the app holds, so every native account is a bootstrap account. With the server flag on, an app that presented a handle would fail its signup, so the app flags stay off.
- Today: a returning user's `preferred_username` comes from the stored username. When none is stored, the only fallback is the localpart of a well-formed Matrix ID, and anything else is refused (`AccountLocalpartResolver` in identity-service, guarded by `LocalpartDerivationGuardTest`).
- Not started: giving an existing account a committed key. That is the account authority work, in development on open pull requests.

Formats: [account identifiers and placement records](../specs/account-identifiers-and-placement-records.md).

**Validation**

- `accountId` is populated; only passkeys read it.

**Rollback**

Turn the flags off. The `account_genesis` table stays, because an identifier is permanent.

**Blocked by**

Nothing for bootstrap identifiers. Accounts with a committed key wait on account authority. Issuing recovery framework `0x01` in production stays refused (`identity.genesis.production-issuance`).

## Phase 4: placement records for existing accounts

**Goal**

Record where each existing account really lives.

**Changes**

- Today: the directory's `homeserver_id` reads `default` for every account, including one a federation test proved lives elsewhere.
- Only each MAS's `upstream_oauth_links` table records true placement.
- Today: the resolver verifies, stores and serves generation-1 placement records and commits them to the log as `PLACEMENT_CHECKPOINT` leaves (`gua.resolver.placement.*`). identity-service signs and publishes a record for each account with exactly one MAS link, and compares records against those links daily (`identity.placement.*`). Every one of these flags is off by default.
- Comparison mode: answer from policy as today, log where the record disagrees, serve nothing from records. No flag makes routing read a record.

**Before routing may read a placement record**

All of these must hold. Proposing it is a later phase, not this one.

- Every account has an `account_genesis` row, and `gua_identity_accounts_without_genesis` has been zero, with its alert silent, for 14 days.
- The daily comparison ran for 14 consecutive days in dev and 14 in prod. On `gua_identity_placement_shadow_total`, the results `record_disagrees`, `mas_multiple` and `mas_username_mismatch` stayed at zero, `directory_stale` appeared only for allowlisted testbed accounts, and every `mas_none` account is listed and explained.
- On the resolver, `gua_resolver_placement_conflicts_total` and `gua_resolver_placement_orphaned_by_roster` stayed at zero over that window, and a full re-verification against the current roster passes.
- Every MAS runs with `on_conflict: fail` (`gua_identity_mas_localpart_on_conflict`), and `mas_none` is zero.
- New accounts hold a committed key: the apps ship it and the server requires it for native signups, and web signups do the same or stop creating accounts. This waits on account authority.

Comparing inside `/resolve` on each request is not part of this list. It needs Phase 5's binding records. Publishing records in production also waits on a review of what a public mapping from `accountId` to homeserver reveals.

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

The [pinning rules](../architecture/planned-federation-work.md#apps-verifying-before-they-connect), for enforcement only. Phase 2 (pinned genesis).

## Phase 7: authentication moves to homeservers

**Goal**

Each homeserver authenticates its own users; its own design comes first.

**Changes**

- Today: MAS keys upstream links on `(provider ULID, subject)` with a unique index and never rewrites a subject.
- Each MAS gains local authentication, passkeys first. A new subject meaning is a new provider row plus a link association pass, never an in-place update.
- Customer passkeys can ship through identity-service earlier; this phase moves the ceremony to homeservers.
- Pre-ceremony homeserver discovery stays an open decision, outside this phase. That design settles identity-service's remaining role: federation verifier without login credentials, or retirement.

**Validation**

- Set in that design.

**Rollback**

Set in that design.

**Blocked by**

That design, including the [passkey relying party and the sign-in subject migration](../architecture/planned-federation-work.md#sign-in-decided-by-each-homeserver-and-passkeys).

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

Cryptographic review of the threshold construction. The updatable alternative to RFC 9497 is rejected, and the review must confirm that. See [phone numbers that cannot be recovered from stored state](../architecture/planned-federation-work.md#phone-numbers-that-cannot-be-recovered-from-stored-state).

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

- Account recovery. Recovery of sign-in factors is built in identity-service. Recovery of account authority belongs to the account authority work.
- Matrix identity migration between homeservers: nothing native preserves device keys, cross-signing, membership or history across a move; placement migration is separate.
- Catastrophic governance-key loss, which is undecided.
