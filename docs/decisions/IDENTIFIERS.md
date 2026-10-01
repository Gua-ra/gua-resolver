# Decision record identifiers

Every short label used in this repository's comments, docs and runbooks, with where it is defined. Labels are stable: they are never renumbered, and a label is cited after the rule it names ("thresholds count operators, never keys (ADM-001 L8)"). This page defines; the records decide.

## Records

- [ADM-001](ADM-001-identifier-binding-placement-trust.md): the frozen decision set: identifier binding, account placement, resolver trust, federation governance. Normative.
- [ADM-002](ADM-002-account-recovery.md): account recovery and login-factor reset. Proposed.
- [ADM-003](ADM-003-private-identifier-lookup.md): a private routing key that keeps identifiers out of replicated state. Proposed.
- [ADM-004](ADM-004-passkey-discovery-and-relying-party.md): passkey discovery and the relying-party architecture. Proposed.
- [ADM-005](ADM-005-federation-state-replication-witnesses-ordering.md): replication, witnesses, checkpoints and ordering. Proposed.
- [ADM-006](ADM-006-matrix-portability.md): what moving a Matrix account can and cannot mean. Proposed.
- [ADM-007](ADM-007-canonical-encoding-and-member-entries.md): the `gua-lp.v1` encoding, self-signed member entries and the phase 2 governance objects. Accepted.
- [ADM-008](ADM-008-account-genesis-and-placement-records.md): account genesis, bootstrap identity and placement record formats. Accepted for implementation.
- R1 and R2: the two review rounds that produced ADM-001, preserved as [rationale/ADM-001-R1-corrections.md](rationale/ADM-001-R1-corrections.md) and [rationale/ADM-001-R2-foundations.md](rationale/ADM-001-R2-foundations.md), after the [base memo](rationale/ADM-001-base.md). Reasoning record only, not normative. The D1 to D8 numbering inside the base memo is the memo's own and is not the D list of any record below.

## ADM-001 labels

Tags: `[CODE]` verified against `main` or live configuration when frozen, `[TARGET]` what the protocol should guarantee, `[LIT]` attributed to published literature. The **standing rule** (the paragraph before the locked decisions) is that two keys held by one operator are one principal, so every independence guarantee today reduces to compromising Gua.

### L: locked decisions

- L1a, L1b: the two live paths deleted ([L1. Delete two live paths](ADM-001-identifier-binding-placement-trust.md#l1-delete-two-live-paths)). L1a is the non-interactive `phone_number` + `otp_code` branch of `GET /oauth2/authorize` in identity-service; L1b is `POST /directory/entries` in the resolver.
- L2: [The three concepts stay separate](ADM-001-identifier-binding-placement-trust.md#l2-the-three-concepts-stay-separate)
- L3: [An identifier is an attribute of an account, never the account](ADM-001-identifier-binding-placement-trust.md#l3-an-identifier-is-an-attribute-of-an-account-never-the-account)
- L4: [Account genesis](ADM-001-identifier-binding-placement-trust.md#l4-account-genesis)
- L5: [Account authority is mandatory for new accounts](ADM-001-identifier-binding-placement-trust.md#l5-account-authority-is-mandatory-for-new-accounts)
- L6: [Generation-1 is a five-step transaction, and HostingAcceptance is not a gate](ADM-001-identifier-binding-placement-trust.md#l6-generation-1-is-a-five-step-transaction-and-hostingacceptance-is-not-a-gate)
- L7: [The generation-1 compromise condition](ADM-001-identifier-binding-placement-trust.md#l7-the-generation-1-compromise-condition)
- L8: [IdentifierProofPolicy: identifier-type-specific, k-of-n over independent trust domains](ADM-001-identifier-binding-placement-trust.md#l8-identifierproofpolicy-identifier-type-specific-k-of-n-over-independent-trust-domains)
- L9: [Matrix has no native migration preserving identity and crypto continuity](ADM-001-identifier-binding-placement-trust.md#l9-matrix-has-no-native-migration-preserving-identity-and-crypto-continuity)
- L10: [Federation genesis](ADM-001-identifier-binding-placement-trust.md#l10-federation-genesis)
- L11: [A checkpoint is an assertion, not a derivation](ADM-001-identifier-binding-placement-trust.md#l11-a-checkpoint-is-an-assertion-not-a-derivation)
- L12: [Five properties, never conflated](ADM-001-identifier-binding-placement-trust.md#l12-five-properties-never-conflated)
- L13: [Recovery requirements only](ADM-001-identifier-binding-placement-trust.md#l13-recovery-requirements-only)
- L14: [VOPRF architectural shape, not construction](ADM-001-identifier-binding-placement-trust.md#l14-voprf-architectural-shape-not-construction)
- L15: [Routing-key privacy is required in replicated state](ADM-001-identifier-binding-placement-trust.md#l15-routing-key-privacy-is-required-in-replicated-state)
- L16: [/resolve must not be a cheap unrestricted enumeration oracle](ADM-001-identifier-binding-placement-trust.md#l16-resolve-must-not-be-a-cheap-unrestricted-enumeration-oracle)
- B1: the bootstrap path inside L5, where the binding commits an intended initial homeserver and the account is marked as not yet rooted.

### O: open design decisions ([section](ADM-001-identifier-binding-placement-trust.md#open-design-decisions))

- O1: authenticated dictionary choice
- O2: wire-level protocol specification (partly closed by ADM-007)
- O3: `k` per identifier type
- O4: emergency replacement of the logical VOPRF key
- O5: recovery mechanism (ADM-002)
- O6: cancellation authority for recovery
- O7: whether witnessing is worth building before a second operator exists
- O8: client behaviour on genesis version skew, without a downgrade path
- O9: `ADOPT_ROOT`, the path by which a bootstrap account gains authority
- O10: client pinning semantics
- O11: passkey discovery and relying-party architecture (ADM-004)
- O12: resolver replica and bootstrap protocol; running a resolver grants no authority
- O13: catastrophic governance-key loss and root transition

### S: spikes ([section](ADM-001-identifier-binding-placement-trust.md#implementation-and-cryptographic-spikes))

- S1: threshold OPRF with proactive refresh; crypto review required
- S2: authenticated dictionary benchmark (closes O1)
- S3: full-replay witness feasibility
- S4: enumeration controls for `/resolve` (closes L16)
- S5: verifier accreditation governance; S5-min is the minimal custody rule ADM-007 item 11 adopted
- S6: migration of existing accounts from `directory_entries.homeserver_id`, and the `routeExistingUser` trap

## Labels inside the other records

Each record numbers its own decisions and questions. A bare `D1` or `Q1` is only meaningful with its record name in front of it.

- ADM-002: D1 to D5 are the narrowed choices under "Decision or narrowed choice" (D1 recovery framework `0x02`, D2 transition rules, D3 what stays unrecoverable, D4 the login-factor ladder, D5 the SMS PIN reset as P3). Q1 to Q7 are the production blockers. SR1 is the security review the transition rules wait for.
- ADM-003: decisions 1 to 7 under "Decision or narrowed choice"; Q1 to Q9 are the production blockers.
- ADM-004: requirements 1 to 10; D1 to D6 are the decisions (D1 relying-party id scope, D2 origin allow-lists, D3 no native ceremony from a self-signed entry alone, D4 new-device discovery order, D5 credentials migrate as data, D6 random user handles); Q1 to Q8 are the production blockers.
- ADM-005: two lists share the letter D. Under "Options considered", D1 and D2 are the two tree options (sparse Merkle, sorted-neighbour indexed Merkle); decisions 1 to 13 follow, and decision 13 narrows O1 to tree option D1. Under "Blockers for production", D1 to D8 are open questions, unrelated to the tree options.
- ADM-006: H0 is decided (option A, no per-account move); H1 is narrowed and not built (option B). Q1 to Q7 are the production blockers.
- ADM-007: items 1 to 6 are the encoding and member-entry decisions; items 7 to 13 are the phase 2 governance objects (7 the four `gua-lp.v1` objects, 8 thresholds count operators, 9 governance admits and does not redefine, 10 registry scope, 11 key custody, 12 the `gua.resolver.governance.required` flag, 13 the chain-head pin).
- ADM-008: decisions 1 to 10 (1 canonical bytes, 2 accountId, 3 entropy and proof, 4 recovery framework, 5 authority key, 6 attach handle, 7 placement records, 8 accounts without evidence, 9 shadow mode, 10 order and subject), then the shadow-mode exit criteria 1 to 6. "Decision N" in code without a record name means ADM-008 decision N.

## Migration plan phases

- Phase 0: [remove the two live paths](../migrations/gua-resolver-migration-plan.md#phase-0-remove-the-two-live-paths)
- Phase 1: [self-signed roster entries](../migrations/gua-resolver-migration-plan.md#phase-1-self-signed-roster-entries)
- Phase 2: [separate governance keys](../migrations/gua-resolver-migration-plan.md#phase-2-separate-governance-keys)
- Phase 3: [AccountGenesis and accountId](../migrations/gua-resolver-migration-plan.md#phase-3-accountgenesis-and-accountid)
- Phase 4: [placement records for existing accounts](../migrations/gua-resolver-migration-plan.md#phase-4-placement-records-for-existing-accounts)
- Phase 5: [binding records and first verifier](../migrations/gua-resolver-migration-plan.md#phase-5-binding-records-and-first-verifier)
- Phase 6: [clients verify before connecting](../migrations/gua-resolver-migration-plan.md#phase-6-clients-verify-before-connecting)
- Phase 7: [authentication moves to homeservers](../migrations/gua-resolver-migration-plan.md#phase-7-authentication-moves-to-homeservers)
- Phase 8: [blinded routing keys](../migrations/gua-resolver-migration-plan.md#phase-8-blinded-routing-keys)
- Phase 9: [independent witnesses](../migrations/gua-resolver-migration-plan.md#phase-9-independent-witnesses)

"Phase N" in code and runbooks means these phases. The [July 2026 plan](../migrations/history/gua-resolver-migration-plan-2026-07.md) used a different numbering and is superseded.

## Labels local to the code

- Admission gates 1 to 3 (`admission/AdmissionService.java`): key possession, domain ownership, uniqueness and claim non-overlap.
- `MEMBER_ATTEST`, `MEMBERSHIP_EPOCH`, `STATUS_INTENT`, `PLACEMENT_CHECKPOINT`: transparency-log leaf types, defined in `roster/TransparencyLog.java` and fixed on the wire.
- Framework `0x01`, `0x02`: recovery framework ids (ADM-008 decision 4, ADM-002 D1). Suite `0x00`, `0x01`: genesis suites (ADM-008 decision 1).

