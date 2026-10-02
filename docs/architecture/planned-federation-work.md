# Federation work that is not built yet

The gaps between the system described in [Gua identity and federation](gua-identity-and-federation.md) and a federation that several independent operators can trust. Each section says what is missing today, the constraints any implementation must keep, and what blocks it. Nothing here is built unless a section says so. The order of work is in the [migration plan](../migrations/gua-resolver-migration-plan.md).

## Constraints on all of it

- **Three questions stay separate.** Which account an identifier refers to, which homeserver holds that account, and whether this person may sign in right now. The federation may answer the first two. Only the homeserver answers the third. Nothing the federation issues is a login credential or a session.
- **An identifier is an attribute of an account.** If a carrier reassigns a number and it is later tied to a new account, the old account, its history, credentials and homeserver do not move.
- **Independence means independently governed parties.** Two keys held by one operator count once. A check that needs a key set never falls back to a different one when that set is missing.
- **A signature adds security only if obtaining it requires compromising someone.** A homeserver agreeing to host a new account, or an applicant signing their own request, binds a transaction together. Neither is a check on who owns the phone number.
- **Running a resolver grants no authority.** The number of resolvers is an availability decision, never a voting or signing one.
- **No guarantee is claimed before it is true.** One operator runs everything today, so no independence property holds yet, and no document or UI may say otherwise.

## Identifier ownership attested by independent verifiers

Today the identity service's own directory is the only record of which account a phone number belongs to.

The design makes that a signed record. A verifier checks that a person controls an identifier and signs a statement. Governance accredits verifiers. A governance-signed policy per identifier type says how many independently governed verifiers must agree, which proofs are allowed and how fresh a challenge must be. Forging a record for an unused identifier then requires compromising that many verifier operators, or enough governance keys to change the policy.

One limit survives any number of verifiers: whoever controls the phone number right now, including after a SIM swap, is truthfully attested by every honest verifier.

Open: how many verifiers each identifier type needs. Blocked by governance being enabled and by a second operator to make the count mean something.

## New accounts registered as one checkable transaction

Today the resolver picks a homeserver for a new number by evaluating policy on each request, and nothing is recorded. The weighted fallback seeds on the roster version, which is the transparency log size, so its answer can change whenever any leaf is appended.

The design: the app creates the account's identity, the resolver proposes a homeserver, that homeserver signs a short-lived agreement to host, verifiers attest the identifier, and the identifier record and the first placement record are committed together or not at all.

Constraints: the proposed homeserver stays fixed for the life of the transaction, and anyone can re-derive it from the signed policy and roster without trusting the resolver's word. The homeserver's agreement prevents an account being placed where nobody agreed to host it. It is not a security check.

[Placement records](../specs/account-identifiers-and-placement-records.md#placement-record-66--n-bytes) exist and, with their flags on, are compared daily against where accounts really live. Routing may read them only once the conditions listed in the [migration plan](../migrations/gua-resolver-migration-plan.md#phase-4-placement-records-for-existing-accounts) hold.

## Apps verifying before they connect

Today the apps hand the resolver's `baseUrl` to the Matrix SDK as received. The [verification protocol](../verification/gua-resolver-verification-protocol.md) describes what a client can check now, and a Java reference verifier exists, but no app runs it.

The design: before connecting, the app checks the pinned federation root, the roster, the homeserver's own signature on its entry, and the placement record. It ships in report-only mode first.

Open: what an app does when a homeserver's key changes in a way it cannot tell from a takeover, and how it handles a federation root newer than the one it was built with without opening a downgrade path.

## Checkpoints, witnesses and replicas

Today the transparency log proves that a history of hashes was only appended to. It does not prove what the current state is. Directory changes are not logged, the resolver stamps entries with its own clock, the answer "no account for this number" is unsigned, and two clients could be shown two different histories without noticing. Mirror mode exists and is not exercised.

Constraints:

- A signed checkpoint proves only that its signers signed those bytes. It says nothing about whether the state was computed correctly.
- A witness signature counts toward correctness only if that witness fetched every entry, verified it, replayed it and recomputed the state itself. A witness that only checks the log is growing consistently helps detect split histories and nothing more. Clients must be able to tell the two kinds apart.
- Every input that affects state, including time, is an entry in the log, so a replay sees what the resolver saw. Nothing reads a local clock during replay.
- A witness run by the resolver's operator counts for nothing.
- The sets of witnesses a client accepts must overlap in at least one honest party.

The leading design is one ordering resolver, cheap log-only witnesses, expensive replaying witnesses, and a sparse Merkle tree so that both "this account exists" and "no such account" come with proofs. Agreement among several ordering nodes is only worth its cost if the federation refuses a single ordering party or must keep running through a malicious one.

Blocked by a second operator. The formats can be built earlier. The guarantee cannot be claimed earlier.

## Phone numbers that cannot be recovered from stored state

Today the resolver and the identity service both store an HMAC-SHA256 of the phone number under a shared secret pepper. A national numbering plan has between one and ten billion candidates, so anyone holding the stored values and the pepper recovers every number. The pepper cannot be rotated without the raw numbers. `POST /resolve` needs no session, reveals whether a number has an account, and is protected only by rate limits per client, globally and at the ingress.

Requirements: no raw or cheaply reversible identifier appears in state that leaves the operator, and turning a number into its lookup key requires an online evaluation that the evaluator can meter without learning the number.

The leading design is a verifiable oblivious pseudorandom function (RFC 9497) evaluated by several parties holding shares of one key, with shares refreshed on rotation so stored lookup keys do not change. That combination has not been validated. It needs review by a cryptographer before any of it is implemented, and the choice cannot be swapped later because every stored key depends on it.

## Sign-in decided by each homeserver, and passkeys

Today the identity service authenticates users for every homeserver and verifies every passkey. The passkey relying party is the Gua sign-in domain.

Constraints for moving authentication to each homeserver:

- Finding the homeserver happens before the passkey ceremony, because a passkey is tied to one relying party and no platform lists passkeys across relying parties.
- Whatever helps an app find its homeserver never stores a credential key and never receives an assertion.
- A passkey's relying party is fixed when it is created. Homeservers run by Gua keep the Gua relying party so existing passkeys keep working. A homeserver run by someone else uses a relying party it controls.
- A homeserver's self-signed roster entry never makes it eligible for a native passkey ceremony under the Gua relying party. A browser enforces origin for web ceremonies. A native ceremony uses the app's compiled association and does not.
- The auth service keys upstream links on provider and subject and never rewrites a subject. Changing what the subject means is a new provider plus a link pass, never an edit in place.

Blocked by its own design, which also decides what remains of the identity service afterwards.

## Moving an account to another homeserver

Gua offers no per-account move, and nothing currently needs one. Moving a whole homeserver keeps every Matrix ID and every key and is the tool for capacity.

A Matrix ID contains its server name, every event is signed by the server named in its sender, the auth service never renames a user, and no adopted Matrix feature carries device keys, verification, room membership or message attribution across servers. A move would therefore mean a new Matrix ID with conversations re-established from the user's devices: new device keys, contacts verify the person again, and earlier messages keep the old sender.

Constraints if this is ever built: only the account's own authority can authorize it, the destination authenticates the person from scratch, the old Matrix ID is never given to anyone else, and no record, tool or screen claims the identity is the same or the move is seamless.

Revisit when a second operator exists or a regional or legal requirement demands it.

## Losing the governance keys

If the governance keys are lost or compromised beyond what their own rotation rule can repair, there is no recovery inside the system. The answer today is a new federation root and new app builds that pin it. What happens to accounts and placements across such a change is undecided, and it is a governance question before it is a protocol one.

## Account authority and device lifecycle

In development on open pull requests and switched off. See the [short description](gua-identity-and-federation.md#in-development-account-authority) in the architecture guide.
