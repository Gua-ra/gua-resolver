Architecture decision records for Gua. The entry point is [ADM-001](ADM-001-identifier-binding-placement-trust.md), the frozen decision set for identifier binding, account placement, resolver trust and federation governance. It is normative. Its locked decisions are reopened by concrete evidence, such as a counterexample, a changed requirement or implementation results, not by preference.
The memos that produced it are preserved under [rationale/](rationale/) with only punctuation normalized. They are the reasoning record. They are not normative.

## Accepted follow-up records

- [ADM-007](ADM-007-canonical-encoding-and-member-entries.md): the `gua-lp.v1` canonical encoding and self-signed member roster entries, extended with the Phase 2 governance objects (`gua-federation-genesis.v1`, `gua-governance-transition.v1`, `gua-registry-epoch.v1`, `gua-homeserver-registry-content.v1`) and the minimal governance key custody rule that unblocked Phase 2. Closes the part of O2 that Phases 1 and 2 need; nothing locked in ADM-001 is reopened.


## Proposed records

These are proposals. They are not normative until a decision freezes them, and they do not override ADM-001.

- [ADM-002](ADM-002-account-recovery.md): Recovering an account authority key and resetting login factors, with what stays unrecoverable. Status: Proposed.
- [ADM-003](ADM-003-private-identifier-lookup.md): A routing key that does not put identifiers in replicated state, and the construction choices it needs reviewed. Status: Proposed.
- [ADM-004](ADM-004-passkey-discovery-and-relying-party.md): How a returning device finds the right homeserver before offering a passkey. Status: Proposed.
- [ADM-005](ADM-005-federation-state-replication-witnesses-ordering.md): Replication, witnesses, checkpoints and what a second operator changes. Status: Proposed.
- [ADM-006](ADM-006-matrix-portability.md): What moving an account can and cannot mean, given what Matrix supports today. Status: Proposed.
- [ADM-008](ADM-008-account-genesis-and-placement-records.md): Account genesis, bootstrap identity and placement record formats. Status: Accepted for implementation.
## Implementation status

Which ADM-001 decisions the code on `main` has reached. Everything not listed is still target.

- L1b: implemented (`POST /directory/entries` removed), 2026-09-11. Existing directory rows stay until placement records replace them.
- L1a: implemented in identity-service (the non-interactive `phone_number` + `otp_code` branch of `GET /oauth2/authorize` removed; an authorization code is only issued by the interactive login flow), 2026-09-11.
- Phase 1 (member self-signed entries): code on main, flag off; activation pending operator attestation.
- Phase 2 (governance keys, federation genesis, registry roots): code on main, `gua.resolver.governance.required` off. The resolver loads and serves a pinned `FederationGenesis` at `/.well-known/gua-federation`, accepts governance-signed `HomeserverRegistry` epochs, serves them at `/registry/homeservers/epoch/*`, and commits each to the log as a `MEMBERSHIP_EPOCH` leaf. Governance signing is outside the process: the in-resolver `POST /authority/policy/sign` is replaced by `POST /authority/policy/validate`, and signing moves to the offline tool (`docs/runbooks/governance-keys.md`). An admission under governance stays out of the signed roster until an epoch admits it, a status request is logged as a `STATUS_INTENT` leaf, and `genesis.expected-chain-head` pins the key chain so a truncated transitions file cannot walk the key set back. Activation per environment is pending the key ceremony.
- L10: partial. The genesis, the governance key transitions format and the HomeserverRegistry epoch chain exist and the resolver verifies them back to the pinned genesis. `VerifierRegistry` and `WitnessRegistry` are shapes with no code path (Phase 5 and Phase 9), `PolicyRegistry` content is the existing bundle envelope verified under the governance keys rather than a separate epoch object, and clients do not verify the chain yet (Phase 6).
- L8: fail-closed implemented, 2026-09-11. `RoutingClaimsVerifier` no longer falls back to policy or authority keys, `RoutingPolicyVerifier` no longer falls back to authority keys and prefers the governance key set, and `RoutingPolicySigner` no longer falls back to the authority signing key. Governance thresholds count distinct `operatorId`s through `GovernanceVerifier`; the roster and policy verifiers keep their per-key counting for the operational snapshot and must not be reused for a threshold that has to mean independence.
- L16: interim controls, 2026-09-11. `POST /resolve` is rate-limited per client and globally inside the service (README, "Interim abuse controls") and per source at the ingress (gua-deploy `k8s/services/login-ingress.sh`). It still answers `exists` for any raw E.164 with no account session; the L16 [CODE] sentence predates these controls and is left as written.
