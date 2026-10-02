# Former decision records

This directory used to hold numbered decision records. They were replaced by documents named for what they describe:

- [Gua identity and federation](../architecture/gua-identity-and-federation.md): how the system works today.
- [Signed federation objects](../specs/federation-signed-objects.md): encoding, homeserver-signed roster entries, governance objects and their verification rules.
- [Account identifiers and placement records](../specs/account-identifiers-and-placement-records.md): byte formats and acceptance rules.
- [Federation work that is not built yet](../architecture/planned-federation-work.md): the gaps and the constraints on closing them.

New decisions go into the document they change. Do not add numbered records here.

The tables below exist because golden-vector files, applied database migrations, log messages and other repositories still cite the old identifiers. The `decision` field in both vector files in `docs/specs/` names the former ADM-007 path. That path is historical, and its content is now in [signed federation objects](../specs/federation-signed-objects.md).

## Records

| Former identifier | Subject | Now |
| --- | --- | --- |
| ADM-001 | Identifier binding, account placement, resolver trust, governance | Rules in force: [signed federation objects](../specs/federation-signed-objects.md). Unbuilt design and its constraints: [planned federation work](../architecture/planned-federation-work.md). Overview: [architecture guide](../architecture/gua-identity-and-federation.md). |
| ADM-001 rationale memos (base, R1, R2) | The review rounds behind ADM-001 | Removed. In git history. |
| ADM-002 | Account recovery proposal | Sign-in factor recovery as built: [delayed account recovery](../architecture/gua-identity-and-federation.md#delayed-account-recovery). Recovery of account authority, with the proposed order for competing key changes: [account authority and device lifecycle](../architecture/planned-federation-work.md#account-authority-and-device-lifecycle). |
| ADM-003 | Private identifier lookup proposal | [Phone numbers that cannot be recovered from stored state](../architecture/planned-federation-work.md#phone-numbers-that-cannot-be-recovered-from-stored-state) |
| ADM-004 | Passkey discovery and relying party proposal | [Sign-in decided by each homeserver, and passkeys](../architecture/planned-federation-work.md#sign-in-decided-by-each-homeserver-and-passkeys). Passkeys as built: [account security](../architecture/gua-identity-and-federation.md#account-security). |
| ADM-005 | Replication, witnesses and ordering proposal | [Checkpoints, witnesses and replicas](../architecture/planned-federation-work.md#checkpoints-witnesses-and-replicas) |
| ADM-006 | Matrix identity portability | [Moving an account to another homeserver](../architecture/planned-federation-work.md#moving-an-account-to-another-homeserver) |
| ADM-007 | `gua-lp.v1` encoding, homeserver-signed entries, governance objects | [Signed federation objects](../specs/federation-signed-objects.md) |
| ADM-008 | Account genesis, `accountId`, placement records | [Account identifiers and placement records](../specs/account-identifiers-and-placement-records.md) |

## Labels still cited elsewhere

| Label | Rule in one line | Now |
| --- | --- | --- |
| ADM-001 standing rule | Two keys held by one operator are one party | [Planned federation work](../architecture/planned-federation-work.md), opening paragraph, and [identifier ownership](../architecture/planned-federation-work.md#identifier-ownership-attested-by-independent-verifiers) |
| ADM-001 L1a | A sign-in code is issued only by the interactive flow | [How sign-in works](../architecture/gua-identity-and-federation.md#how-sign-in-works) |
| ADM-001 L1b | Homeservers cannot write the phone directory | [How a phone number is resolved](../architecture/gua-identity-and-federation.md#how-a-phone-number-is-resolved) |
| ADM-001 L2 | Ownership, placement and sign-in stay separate, with the test for a flow | [Sign-in decided by each homeserver](../architecture/planned-federation-work.md#sign-in-decided-by-each-homeserver-and-passkeys) |
| ADM-001 L3 | An identifier is an attribute of an account | [Identifier ownership](../architecture/planned-federation-work.md#identifier-ownership-attested-by-independent-verifiers) |
| ADM-001 L4, O2 | One canonical byte representation per signed object. Account objects hold no identifier | [Rules for every signed object](../specs/federation-signed-objects.md#rules-for-every-signed-object), [account object rules](../specs/account-identifiers-and-placement-records.md#rules) |
| ADM-001 L5, B1, O9 | Accounts with and without a committed key, and how one gains a key | [Status](../specs/account-identifiers-and-placement-records.md#status), [account authority](../architecture/gua-identity-and-federation.md#in-development-account-authority) |
| ADM-001 L6 | New accounts registered as one transaction with a committed placement | [New accounts](../architecture/planned-federation-work.md#new-accounts-registered-as-one-checkable-transaction), [placement record](../specs/account-identifiers-and-placement-records.md#placement-record-66--n-bytes) |
| ADM-001 L7, L8, O3, S5 | Verifier attestation. Thresholds count operators. Trust roots fail closed | [Identifier ownership](../architecture/planned-federation-work.md#identifier-ownership-attested-by-independent-verifiers), [governance rules](../specs/federation-signed-objects.md#rules-governance-verification-depends-on) |
| ADM-001 L9 | Matrix has no migration that keeps identity | [Moving an account](../architecture/planned-federation-work.md#moving-an-account-to-another-homeserver) |
| ADM-001 L10, O8, O13 | Federation genesis, key chain, loss of governance keys | [Governance objects](../specs/federation-signed-objects.md#governance-objects), [losing the governance keys](../architecture/planned-federation-work.md#losing-the-governance-keys) |
| ADM-001 L11, L12, O1, O7, O10, O12, S2, S3 | Checkpoints, witnesses, pinning, replicas | [Checkpoints, witnesses and replicas](../architecture/planned-federation-work.md#checkpoints-witnesses-and-replicas), [apps verifying](../architecture/planned-federation-work.md#apps-verifying-before-they-connect) |
| ADM-001 L13, O5, O6 | Recovery requirements | [Account authority and device lifecycle](../architecture/planned-federation-work.md#account-authority-and-device-lifecycle). Sign-in factor recovery as built: [changing device or losing access](../architecture/gua-identity-and-federation.md#changing-device-or-losing-access) |
| ADM-001 L14, L15, L16, O4, S1, S4 | Lookup keys, no raw identifiers in shared state, `/resolve` enumeration | [Phone numbers](../architecture/planned-federation-work.md#phone-numbers-that-cannot-be-recovered-from-stored-state) |
| ADM-001 O11, S6 | Passkey relying party. Sign-in subject migration | [Sign-in decided by each homeserver](../architecture/planned-federation-work.md#sign-in-decided-by-each-homeserver-and-passkeys) |
| ADM-002 D1, Q6 | Recovery framework `0x01` is not issued in production | [Account genesis, key-rooted](../specs/account-identifiers-and-placement-records.md#account-genesis-key-rooted-87-bytes) |
| ADM-002 D2, D3 | Order for competing key changes. Operators never reassign an account | [Account authority and device lifecycle](../architecture/planned-federation-work.md#account-authority-and-device-lifecycle) |
| ADM-004 D6 | A random 64-byte passkey user handle | Superseded. The passkey user handle is the `accountId`: [status](../specs/account-identifiers-and-placement-records.md#status) |
| ADM-007 items 1 to 6 | Encoding and homeserver-signed entries | [Signed federation objects](../specs/federation-signed-objects.md#the-gua-lpv1-encoding) |
| ADM-007 items 7 to 13, "Phase 2 objects" | Governance objects, thresholds, custody, the governance switch, the chain head pin | [Governance objects](../specs/federation-signed-objects.md#governance-objects). Custody: [governance keys runbook](../runbooks/governance-keys.md#custody) |
| ADM-008 decisions 1 to 5 | Byte layouts, `accountId`, registration proof, recovery framework, authority key | [Account identifiers](../specs/account-identifiers-and-placement-records.md#rules) |
| ADM-008 decision 6 | Attach handle and attach proof | [Attaching it to a new account](../specs/account-identifiers-and-placement-records.md#attaching-it-to-a-new-account) |
| ADM-008 decisions 7 to 9 | Placement records and comparison mode | [Placement record](../specs/account-identifiers-and-placement-records.md#placement-record-66--n-bytes), [migration plan](../migrations/gua-resolver-migration-plan.md#phase-4-placement-records-for-existing-accounts) |
| ADM-008 decision 10 | An `accountId` never appears in a sign-in claim | [Rules](../specs/account-identifiers-and-placement-records.md#rules) |
