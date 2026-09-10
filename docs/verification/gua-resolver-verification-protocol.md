> **Status: CURRENT IMPLEMENTATION.** This protocol verifies what the resolver serves **today**: the signed roster, the routing policy bundle, the transparency log, and a `/resolve` decision reproduced from those artifacts. It is accurate for the code on `main` and remains the reference for platform verifiers until the target verification chain ships.
>
> It does **not** yet cover the guarantees added by [ADM-001](../decisions/ADM-001-identifier-binding-placement-trust.md), which is the normative target. Specifically, none of the following is implemented or verifiable today:
>
> - homeserver **self-signed roster entries** (L10), so a client cannot yet detect an authority that has rewritten a member's address or key;
> - **binding records** attested by accredited identifier verifiers (L7, L8), so a client cannot yet verify that an identifier legitimately refers to an account;
> - **placement records** signed by the holding homeserver (L6), so a `/resolve` answer is still a per-request policy evaluation rather than a committed fact;
> - a pinned **federation genesis** and governance-key chain (L10); the trust roots below are still a configured authority key set;
> - checkpoints carrying an authenticated **state root** with witness co-signatures (L11, L12); the log checkpoint below proves history, not current state;
> - **non-membership proofs**, so "no account for this identifier" is an unsigned answer.
>
> Do not read this document as describing the target. When the target verification chain is specified, this file will be moved to `history/` and replaced.

# Gua Resolver Client Verification Protocol

Date: 2026-07-08

This is the canonical algorithm a Gua client (or any third party) uses to verify a resolver's answer without
trusting the resolver. The Java reference implementation is
`global.gua.resolver.verify.ResolverVerifier`; platform verifiers (web / iOS / Android) port this spec.

## Trust roots

A verifier is configured out of band with:

- the published **authority public keys** (n) and the **authority threshold** `k`;
- optionally distinct **policy-signing keys** + threshold. The Java reference implementation falls back to
  the authority keys when these are unset; that fallback is the key-role sharing ADM-001 L8 requires to fail
  closed, so do not copy it into a port.

These are the only inputs the verifier trusts. Everything else is fetched and verified against them.

## Artifacts the client fetches

- `GET /roster` -> `SignedRoster` (version, entries, `logCheckpoint`, `authoritySignatures`).
- `GET /policy/routing` -> `RoutingPolicyBundle` (or none if policy is disabled).
- `GET /roster/log` and `GET /roster/log/consistency?first=&second=` -> transparency-log events + proofs.
  Served by the authority node only; a mirror does not relay them, so a client pointed at a mirror cannot
  run the log steps below today.
- `GET /policy/log` -> the `POLICY_PUBLISH` history + checkpoint.
- `POST /resolve` with `trace: true` -> the decision plus the artifact coordinates it used
  (`rosterVersion`, `policyId`, `policyVersion`).

## 1. Verify the roster

1. Recompute the canonical bytes (`CanonicalRoster`): `version`, `issuedAt` (epoch millis), sorted entries,
   sorted claim predicates, and the `logCheckpoint` (merkle root + size). Each entry includes the
   homeserver's user-search discoverability policy: `searchVisibility` (`GLOBAL` default, `SERVER`, or
   `GROUP`) followed by its sorted `searchGroups` joined by `|` (empty when none), placed between
   `signingKey` and `admittedAt`. Verifiers reading rosters that predate these fields treat them as
   `GLOBAL` with no groups.
2. Count valid `authoritySignatures`: each must be Ed25519-valid over the canonical bytes under a trusted
   authority key, one vote per key. Require at least `k`.
3. Verify transparency-log consistency: the `logCheckpoint` must be an append-only extension of the last one
   the client saw (`verifyConsistency`). This detects a history rewritten since this client's own last
   checkpoint; it does not by itself rule out a split view between clients (ADM-001 L11, L12).

## 2. Verify the policy (if present)

1. **Authority attestation.** Recompute the canonical bytes (`CanonicalRoutingPolicy`, which excludes the
   signatures and INCLUDES each zone's `delegateKeyId` + `delegatePublicKey`). Require at least `k` valid
   authority signatures. This attests each delegation zone's grant: its scope, allowed homeservers, validity
   window, and delegate public key.
2. **Delegate attestation (per zone).** For every zone, recompute `CanonicalDelegatedRules` over
   (`policyId`, `version`, `zoneId`, the rules whose `delegatedZoneId == zoneId`, in canonical order) and
   require a `delegateSignatures` entry for that zone that is Ed25519-valid under the zone's
   `delegatePublicKey`. A rule is trusted only if its zone is BOTH authority-attested and delegate-signed, so
   a delegate controls its own rules within an authority-granted scope. This constrains delegates, not the
   authority: the authority attests the delegate key and this protocol pins none (ADM-001 L6).
3. **Validity + scope.** A zone applies only while `notBefore <= now < expiresAt`. A rule must target a
   homeserver in its zone's `allowedHomeserverIds` and match within the zone scope (phone prefix / subdomain /
   OIDC issuer). Reject the bundle otherwise. **Not performed by the Java reference verifier today:**
   `ResolverVerifier` does not run `RoutingPolicyValidator`; scope and allowed-homeserver checks run only when
   a bundle is loaded from file and at `/authority/policy/sign`.
4. **Transparency.** The policy version's content hash (SHA-256 of the canonical bytes) must appear as a
   `POLICY_PUBLISH` leaf in the transparency log, so the served policy is the publicly logged one.

## 3. Reproduce the decision

Placement is a deterministic function of (verified roster, verified policy, context). Note that the weighted
fallback seeds on the roster version, which is the transparency-log size, so its result moves whenever a
policy or directory-checkpoint leaf is appended even when membership did not change (ADM-001 L6 records
this). To verify a `/resolve` answer:

- **New account (`exists=false`, `registerAt`).** Run the placement pipeline over the verified artifacts and
  confirm it yields the same homeserver id the resolver returned:
  1. **Signed policy rules** (priority order) whose zone is delegate-verified and currently valid, and whose
     match holds. Institution-domain / OIDC rules require the context's claims to be verified (see below).
  2. **Legacy signed-roster claim predicates** (carrier/geo may be self-asserted; affiliation/attribute
     require verified claims).
  3. **Stable weighted fallback** across active homeservers accepting new accounts (deterministic hash of the
     context + roster version + candidate ids/weights).
- **Existing account (`exists=true`, `homeserver`).** The client cannot reproduce a directory lookup (the
  phone graph is private), and no per-lookup inclusion proof is served today, so this branch is not
  verifiable in the current implementation. What a client can check is that the returned homeserver id is
  currently ACTIVE in the verified roster. The signed **directory checkpoint** (`GET /directory/checkpoint`)
  commits the authority node to a directory state as a whole and carries no proof for an individual mapping
  (ADM-001 L11, O1).

### Verified vs self-asserted claims

Institution/OIDC placement is granted only for affiliations/attributes that arrived inside a
signature-verified, subject-bound routing-claims envelope. A public caller's self-asserted
affiliations/attributes are never trusted for privileged routing. The verifier reproduces this: it applies
institution/OIDC rules only when the context is marked claims-verified.

## Canonical encodings (must match byte for byte)

- `CanonicalRoster`, `CanonicalRoutingPolicy`, `CanonicalDelegatedRules`, `CanonicalRoutingClaims` are the
  authoritative serializations. Routing-claims use backslash-escaped delimiters so the encoding is injective.
  All timestamps are epoch milliseconds; all maps/lists are sorted; all bytes are UTF-8.
- Only the routing-claims encoding escapes. `CanonicalRoster` joins fields with a raw `0x1F` that is asserted,
  not enforced, to be absent from values, and collapses null and empty. Port it byte for byte to verify what
  is served today; do not reuse it as the encoding for any new signed object (ADM-001 L4).

## Failure handling

Any failed signature, threshold shortfall, broken consistency proof, expired artifact, out-of-scope rule, or
reproduced-decision mismatch means the resolver's answer is not trustworthy: the client must fall back to a
different mirror or refuse to proceed, never silently accept the unverified answer.
