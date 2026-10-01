Architecture decision records for Gua. [ADM-001](ADM-001-identifier-binding-placement-trust.md) is the entry point and is normative. Its locked decisions are reopened by concrete evidence, not by preference.
The memos that produced it are preserved under [rationale/](rationale/) with only punctuation normalized. They are the reasoning record and are not normative. Short labels such as `L8` or `phase 2` are defined in the [identifier index](IDENTIFIERS.md).

## Records

| Record | ID | Status |
| --- | --- | --- |
| Identifier binding, account placement, resolver trust and federation governance | [ADM-001](ADM-001-identifier-binding-placement-trust.md) | Frozen, normative |
| Account recovery and login-factor reset | [ADM-002](ADM-002-account-recovery.md) | Proposed |
| Private identifier lookup: a routing key that keeps identifiers out of replicated state | [ADM-003](ADM-003-private-identifier-lookup.md) | Proposed |
| Passkey discovery and the per-operator relying party | [ADM-004](ADM-004-passkey-discovery-and-relying-party.md) | Proposed |
| Federation state replication, witnesses and ordering | [ADM-005](ADM-005-federation-state-replication-witnesses-ordering.md) | Proposed |
| Matrix identity portability: what moving an account can and cannot mean | [ADM-006](ADM-006-matrix-portability.md) | Proposed |
| Canonical encoding, self-signed member roster entries and the governance objects | [ADM-007](ADM-007-canonical-encoding-and-member-entries.md) | Accepted |
| Account genesis, bootstrap identity and placement record formats | [ADM-008](ADM-008-account-genesis-and-placement-records.md) | Accepted for implementation |

A proposed record is not normative until a decision freezes it, and it does not override ADM-001.

## Implementation status

Which ADM-001 decisions the code on `main` has reached. Everything not listed is still target.

- Account genesis, bootstrap ids and attach proof (phase 3): native accounts are bootstrap-only, and genesis is present but disabled. Every flag defaults off, on the server and in both clients. identity-service on `main` carries the genesis registration, the `gua:` login-hint grammar and the attach-proof verifier. Both clients carry the authority key store and the genesis builder on `develop`, behind their own off-by-default flag, and neither is on `main` yet. No native account holds an account authority key. Decision 6's attach step is not implementable in the deployed flow, an OTP-authorized replacement was reviewed and rejected, and a secure `ADOPT_ROOT` is deferred; see ADM-008, "Implementation status and direction". Framework 0x01 production issuance stays refused until ADM-002 fixes the 0x01 delay bounds and answers its independence question.
- No localpart derived from the user id (S6): implemented in identity-service, with a guard test.
- Member directory write removed (L1b): `POST /directory/entries` is gone, 2026-09-11. Existing directory rows stay until placement records replace them.
- Non-interactive login branch removed (L1a): implemented in identity-service (the non-interactive `phone_number` + `otp_code` branch of `GET /oauth2/authorize` removed; an authorization code is only issued by the interactive login flow), 2026-09-11.
- Member self-signed roster entries (phase 1): code on main, flag off; activation pending operator attestation.
- Governance keys, federation genesis and registry roots (phase 2): code on main, `gua.resolver.governance.required` off. The resolver loads and serves a pinned `FederationGenesis` at `/.well-known/gua-federation`, accepts governance-signed `HomeserverRegistry` epochs, serves them at `/registry/homeservers/epoch/*`, and commits each to the log as a `MEMBERSHIP_EPOCH` leaf. Governance signing is outside the process: the in-resolver `POST /authority/policy/sign` is replaced by `POST /authority/policy/validate`, and signing moves to the offline tool (`docs/runbooks/governance-keys.md`). The fail-closed policy and claims trust roots are gated on the same flag, so deploying this code changes no trust root on its own. An admission under governance stays out of the signed roster until an epoch admits it, a status request is logged as a `STATUS_INTENT` leaf, and `genesis.expected-chain-head` pins the key chain so a truncated transitions file cannot walk the key set back. Activation per environment is pending the key ceremony.
- Governance root and registries (L10): partial. The genesis, the governance key transitions format and the HomeserverRegistry epoch chain exist and the resolver verifies them back to the pinned genesis. `VerifierRegistry` and `WitnessRegistry` are shapes with no code path (Phase 5 and Phase 9), `PolicyRegistry` content is the existing bundle envelope verified under the governance keys rather than a separate epoch object, and clients do not verify the chain yet (Phase 6).
- Trust roots that fail closed (L8): implemented behind `gua.resolver.governance.required`, 2026-09-11. With the flag on, `RoutingClaimsVerifier` no longer falls back to policy or authority keys and `RoutingPolicyVerifier` verifies under the governance key set alone; with it off, both keep the pre-cutover fallbacks, because an environment's deployed policy bundle is signed with the operational key and narrowing the root under a running environment stopped it starting once already. The client-side `ResolverVerifier` has no fallback in either case. `RoutingPolicySigner` no longer falls back to the authority signing key, unconditionally, since it is on no startup or request path. Governance thresholds count distinct `operatorId`s through `GovernanceVerifier`; the roster and policy verifiers keep their per-key counting for the operational snapshot and must not be reused for a threshold that has to mean independence.
- `/resolve` enumeration (L16): interim controls, 2026-09-11. `POST /resolve` is rate-limited per client and globally inside the service (`gua.resolver.abuse.*`) and per source at the ingress (gua-deploy `k8s/services/login-ingress.sh`). It still answers `exists` for any raw E.164 with no account session; the L16 [CODE] sentence predates these controls and is left as written.
