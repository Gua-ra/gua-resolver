# Gua Resolver Client Verification Protocol

Date: 2026-07-08

This is the canonical algorithm a Gua client (or any third party) uses to verify a resolver's answer without
trusting the resolver. The Java reference implementation is
`global.gua.resolver.verify.ResolverVerifier`; platform verifiers (web / iOS / Android) port this spec.

## Trust roots

A verifier is configured out of band with:

- the published **authority public keys** (n) and the **authority threshold** `k`;
- optionally distinct **policy-signing keys** + threshold (defaults to the authority keys).

These are the only inputs the verifier trusts. Everything else is fetched and verified against them.

## Artifacts the client fetches

- `GET /roster` -> `SignedRoster` (version, entries, `logCheckpoint`, `authoritySignatures`).
- `GET /policy/routing` -> `RoutingPolicyBundle` (or none if policy is disabled).
- `GET /roster/log` and `GET /roster/log/consistency?first=&second=` -> transparency-log events + proofs.
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
   the client saw (`verifyConsistency`), so the authority cannot present a forked history / split view.

## 2. Verify the policy (if present)

1. **Authority attestation.** Recompute the canonical bytes (`CanonicalRoutingPolicy`, which excludes the
   signatures and INCLUDES each zone's `delegateKeyId` + `delegatePublicKey`). Require at least `k` valid
   authority signatures. This attests each delegation zone's grant: its scope, allowed homeservers, validity
   window, and delegate public key.
2. **Delegate attestation (per zone).** For every zone, recompute `CanonicalDelegatedRules` over
   (`policyId`, `version`, `zoneId`, the rules whose `delegatedZoneId == zoneId`, in canonical order) and
   require a `delegateSignatures` entry for that zone that is Ed25519-valid under the zone's
   `delegatePublicKey`. A rule is trusted only if its zone is BOTH authority-attested and delegate-signed, so
   a delegate controls its own rules within an authority-granted scope and no one can forge them.
3. **Validity + scope.** A zone applies only while `notBefore <= now < expiresAt`. A rule must target a
   homeserver in its zone's `allowedHomeserverIds` and match within the zone scope (phone prefix / subdomain /
   OIDC issuer). Reject the bundle otherwise.
4. **Transparency.** The policy version's content hash (SHA-256 of the canonical bytes) must appear as a
   `POLICY_PUBLISH` leaf in the transparency log, so the served policy is the publicly logged one.

## 3. Reproduce the decision

Placement is a deterministic pure function of (verified roster, verified policy, context). To verify a
`/resolve` answer:

- **New account (`exists=false`, `registerAt`).** Run the placement pipeline over the verified artifacts and
  confirm it yields the same homeserver id the resolver returned:
  1. **Signed policy rules** (priority order) whose zone is delegate-verified and currently valid, and whose
     match holds. Institution-domain / OIDC rules require the context's claims to be verified (see below).
  2. **Legacy signed-roster claim predicates** (carrier/geo may be self-asserted; affiliation/attribute
     require verified claims).
  3. **Stable weighted fallback** across active homeservers accepting new accounts (deterministic hash of the
     context + roster version + candidate ids/weights).
- **Existing account (`exists=true`, `homeserver`).** The client cannot reproduce a directory lookup (the
  phone graph is private). Instead verify the signed **directory checkpoint** + inclusion proof for the
  peppered phone hash against the roster-anchored checkpoint (see the directory-HA design), and confirm the
  returned homeserver id is currently ACTIVE in the verified roster.

### Verified vs self-asserted claims

Institution/OIDC placement is granted only for affiliations/attributes that arrived inside a
signature-verified, subject-bound routing-claims envelope. A public caller's self-asserted
affiliations/attributes are never trusted for privileged routing. The verifier reproduces this: it applies
institution/OIDC rules only when the context is marked claims-verified.

## Canonical encodings (must match byte for byte)

- `CanonicalRoster`, `CanonicalRoutingPolicy`, `CanonicalDelegatedRules`, `CanonicalRoutingClaims` are the
  authoritative serializations. Routing-claims use backslash-escaped delimiters so the encoding is injective.
  All timestamps are epoch milliseconds; all maps/lists are sorted; all bytes are UTF-8.

## Failure handling

Any failed signature, threshold shortfall, broken consistency proof, expired artifact, out-of-scope rule, or
reproduced-decision mismatch means the resolver's answer is not trustworthy: the client must fall back to a
different mirror or refuse to proceed, never silently accept the unverified answer.
