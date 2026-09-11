# ADM-004: Passkey discovery and per-operator relying-party architecture

> **Status: Proposed, not frozen.** It freezes when independent reviewers answer Q1 to Q8 and spikes PK1 to PK5 pass.

## Context

L2 makes the target homeserver the authentication authority, and no federation artifact is a login credential. O11 locks one requirement: routing precedes the ceremony, and discovery never becomes global authentication.

ADM-001 left O11 open: RP layout, hints, fallback, native constraints. Phase 7 of the [migration plan](../migrations/gua-resolver-migration-plan.md) defers discovery here. S6 governs subject migration.

Facts, [CODE] unless marked:

- F1. identity-service verifies every passkey for every homeserver. The RP id is the brand domain; origins equal the sign-in host.
- F2. Both apps send `login_hint=passkey` (on develop, 2026-09-11; iOS `e93dc1592`, Android `970b5c243d`, neither on `main`).
- F3. The user handle is the UTF-8 Matrix user ID, so it names the homeserver.
- F4. The Rust SDK's OAuth client accepts a code only on a redirect whose `state` matches a request it started (unverified: the SDK ships as a checksum-pinned binary xcframework at 26.06.03). Issuer binding is Q4.
- F5. Signature counters are not validated, and untrusted attestation is accepted.

## Scope

In: new-device discovery, RP id layout, phishing resistance, credential migration, the first shippable step.

Out: PRF key material, recovery (L13, O5), S6 mechanics, enrollment UX.

## Requirements

1. The homeserver mints the challenge, holds the key, verifies and decides (O11, L2). Routing completes first.
2. No discovery component stores a credential key or receives an assertion (L2).
3. Credentials enrolled under F1 survive Phase 7 without re-enrollment (shipped passkeys).
4. Passkey sign-in reaches only an existing account (L6; L1a and Phase 0 removed the path that provisioned one).
5. Discovery ends before the SDK starts OIDC at one homeserver (F4).
6. Discovery adds no enumeration capacity and no identifier to replicated state (L15, L16).
7. A hint is used only after the client verifies its homeserver against the pinned chain (L10, Phase 6).
8. An assertion made for one operator never yields a session at another, including by relay of a native assertion (L2, standing rule).
9. Admitting a third-party operator needs no app release, because admission is a governance act under L10.
10. Every step rolls back without invalidating a credential (migration plan, per-phase rollback; requirement 3).

Requirements 1 and 2 are targets, not present-tense claims: identity-service today holds and verifies for every homeserver (F1), and sits on the phone-entry routing path through `/resolve`. Requirement 1 is met at cutover (order step 4), requirement 2 when those endpoints retire.

## Options considered

**A. Shared brand RP id.** All operators use the brand domain, with third-party origins related to it. Meets 3. Fails 8 as a platform property: any origin valid for the RP id can prompt every Gua credential. WebAuthn Level 3 section 5.11 requires clients supporting Related Origin Requests to support at least five registrable origin labels. No client is known to support more [passkeys.dev], so it fails 9.

**B. RP id per homeserver, with a hint cache.** Meets 1, 2 and 8. Fails 3, because an RP id is fixed at creation [WebAuthn Level 2, 2021]. Each RP domain needs a compiled associated domain, and no platform enumerates across RP ids (O11).

**C. WebAuthn conditional UI.** Conditional mediation lists credentials for one RP id. The challenge must be minted first, so before routing that party is central, failing 1 and 2.

**D. Discovery record keyed by a blinded identifier.** Keyed by a blinded phone number, it is identifier-first `/resolve` under L15, L16, S1 and O4. Keyed by PRF output, it needs PRF-capable credentials, which we lack. The resolver would see a stable per-credential key at every sign-in, failing 6.

## Decision or narrowed choice

- D1. RP id scope follows operator trust domain. Gua homeservers keep the brand RP id, so enrolled credentials survive (3). A third-party operator uses an RP id it controls (8), never one related to a Gua RP id.
- D2. Each homeserver's allow-list names only its own web origins plus the shared first-party app origins. Its self-signed roster entry publishes its RP id and web origins (L10).
- D3. A self-signed entry never makes a member eligible for a native ceremony. Under L10 governance can only admit or revoke, so an admitted member can self-assert the brand RP id. Browsers block that for web ceremonies. A native `get()` does not, because it uses the app's compiled association and ignores the member's origin. Native eligibility comes from a compiled Gua homeserver list or a governance-attested operator trust domain. Third-party members run web ceremonies on their own origin (9).
- D4. A new device tries a verified synced hint, then identifier-first through `/resolve`, both ending at the verified homeserver (4, 5, 7).
- D5. Credentials migrate as data: identity-service copies each record to the homeserver in the placement record, RP id unchanged, so nobody re-enrolls. One authoritative verifier across that copy is Q6.
- D6. New accounts get a 64-byte random user handle. Existing handles stay valid and are treated as opaque. They remain nonconformant until re-enrollment (Q8), and never drive discovery.

Not adopted: A for third parties, C before routing, D, and a local probe ceremony. Open: that probe if hints underperform (Q8), the verifier library, counter policy (Q5). No option changes L6.

**First shippable step.** Both apps write a synced hint `{homeserverId, rosterVersion, writtenAt}` after sign-in. On a fresh install the passkey button starts OIDC at the hinted homeserver if the roster lists it `ACTIVE`, otherwise phone entry. Neither app verifies that roster: iOS `fetchRoster` decodes `GET /roster` with no signature check, and Android reads `status` alone. So the hint ships behind a dev flag until Phase 6 verification is enforced (ADM-005 decision 8). Requirement 7 is not met before that, and PK1 and Q3 are open.

## Blockers for production

Expert questions:

- Q1. WebAuthn security: Gua homeservers share one RP id and one native iOS origin, with exact allow-lists. Can any relay yield a session beyond the one-operator assumption? Specifically, can an admitted member self-assert the brand RP id, then relay a native assertion over a challenge taken from a Gua homeserver?
- Q2. Platform, for iOS 26 and Android 16 and each app's minimum target: are the native origins `https://<rpId>` (iOS) and `android:apk-key-hash:<base64url SHA-256>` (Android) correct? Can a verifier tell a native iOS ceremony from a web page?
- Q3. Security: whoever controls the platform account writes the hint. Is denial of service the worst case, or can it steer an OTP or PIN to a malicious member?
- Q4. OAuth: does every MAS return `iss`, and does the SDK reject a mismatched issuer [RFC 9207, RFC 9700; Fett, Küsters, Schmitz, CCS 2016]?
- Q5. WebAuthn: confirm or refute this policy for synced passkeys. Ignore signature counters, record BE and BS at registration and each assertion, and reject `BE = 0` on the synced path. Does copying records between verifiers open a clone-detection gap?
- Q6. Distributed systems: confirm or refute this cutover protocol. The verifier named by placement generation G is the sole verifier, identity-service refuses assertions once G advances, and any restore bumps G again. Does any interleaving leave two live verifiers?
- Q7. Platform: does a non-brand web origin in `ASWebAuthenticationSession` or a Custom Tab offer synced passkeys without association?
- Q8. L2 interpretation: is a local probe ceremony a discovery aid or a credential use? Do Matrix IDs in existing handles force re-enrollment?

Spikes:

- PK1. Hint sync. Pass: a hint from device A is readable at first launch on device B, same platform account.
- PK2. Third-party ceremony. Pass: a passkey enrolls and asserts at a dev2 origin under its own RP id, no app change.
- PK3. Relay. Pass: the dev verifier rejects assertions from a dev2 origin, another Gua homeserver's origin, and a self-asserted Gua RP id.
- PK4. Migration. Pass: a copied dev credential asserts at the homeserver origin, RP id unchanged. identity-service then refuses it; restoring it needs a generation bump.
- PK5. Association. Pass: AASA and `assetlinks.json` at each Gua RP id list both apps, and native registration succeeds.

## Implementation implications

Services: both apps; identity-service (random handles, `rp_id` column); MAS fork (verifier, credential table, allow-list); gua-resolver (entry origins, O2); gua-deploy (association files).

Data: a portable record of credential id, COSE key, counter, BE and BS flags, transports, handle, RP id and account.

Order:

1. Random handles now, with the hint behind a dev flag until Phase 6 verification is enforced (ADM-005 decision 8).
2. RP id and web origins in self-signed entries, with Phase 1.
3. MAS verifier in shadow over copied records, after Phase 4.
4. Per-account cutover via a new provider row and link association (Phase 7, S6).
5. identity-service passkey endpoints retired after the rollback window.

Tests: hinted homeservers not `ACTIVE` or unverified are ignored. The passkey path never creates accounts. The harness gains a second origin and a self-asserted RP id.

Rollback: the hint is an app flag with fallback. Handle changes touch only new credentials. identity-service rows persist until the window closes, refused once G names the homeserver.

## Relationship to ADM-001

Labels touched: L2, L6, L10, L15, L16, O2, O4, O11, S1 and S6, plus the trust-domain standing rule. O11 is narrowed, not closed.

Nothing locked is reopened. After per-account cutover (order step 4), the homeserver mints, holds, verifies and decides, as L2 requires of the target. Until then identity-service holds that role, as Phase 7 records. Routing still precedes the ceremony.
