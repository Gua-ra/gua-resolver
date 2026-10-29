> **Status: current implementation.** This protocol verifies what the resolver serves today: the signed roster, the routing policy bundle, the transparency log, and a `/resolve` decision reproduced from those artifacts. It is the reference for platform verifiers.
>
> Built, off by default, and not verified by any client:
>
> - **Homeserver-signed roster entries.** The resolver verifies and logs them and refuses a substituted entry (section 1a). Requiring one on every active entry is off by default. A client that does not check the member block itself cannot detect a resolver operator that rewrote a homeserver's address or key.
> - **Placement records** signed by the holding homeserver. The resolver verifies, stores and serves them when `gua.resolver.placement.*` is on. No routing answer reads one, so a `/resolve` answer is still a policy evaluation on each request.
> - **A pinned federation genesis and governance key chain.** The resolver loads and publishes them when configured, and they become its trust root for membership and policy once `gua.resolver.governance.required` is on. Until then the trust roots below are the configured authority and policy keys.
>
> Not built. See [federation work that is not built yet](../architecture/planned-federation-work.md):
>
> - **Binding records** attested by accredited verifiers, so a client cannot verify that an identifier belongs to an account.
> - Checkpoints carrying a **state root** with witness co-signatures. The log checkpoint below proves history, not current state.
> - **Proofs of absence**, so "no account for this identifier" is an unsigned answer.

# Gua Resolver Client Verification Protocol

Date: 2026-07-08

This is the canonical algorithm a Gua client (or any third party) uses to verify a resolver's answer without
trusting the resolver. `global.gua.resolver.verify.ResolverVerifier` is the Java reference for the roster and
policy signatures, the policy validity window, locating an answer in the roster, and placement. The member
block and transparency-log checks are specified here and run in the web, iOS and Android apps.

## Trust roots

A verifier is configured out of band with:

- the published **authority public keys** (n) and the **authority threshold** `k`;
- the **policy-signing keys** + threshold. These are the federation's governance keys once a genesis is
  pinned. A verifier has no fallback to the authority keys: an unset list verifies nothing rather than
  silently accepting a bundle signed by the operational roster key. This is unconditional in
  the reference verifier and in every port. Do not copy the server here: the resolver keeps that fallback
  until `gua.resolver.governance.required` is turned on, because it has a deployed bundle signed with the
  operational key to keep serving, and a client has no such thing to preserve.
- optionally the pinned **federation genesis**, published at `GET /.well-known/gua-federation` on the
  resolver origin as `{genesisId, fingerprint, chainHead, genesis, transitions[]}`, where `chainHead` says
  how far the governance key chain has run: the genesis id with no transition applied, the hash of the last
  applied transition after that. It is signed by the keys it enumerates, so
  fetching it proves nothing on its own: it is a trust root only once its fingerprint has been compared
  against an independent channel and pinned. **No client fetches or pins it yet.**

These are the only inputs the verifier trusts. Everything else is fetched and verified against them.

## Artifacts the client fetches

- `GET /roster` -> `SignedRoster` (version, entries, `logCheckpoint`, `authoritySignatures`).
- `GET /policy/routing` -> `RoutingPolicyBundle`, or `404` when no bundle is in effect.
- `GET /roster/log` and `GET /roster/log/consistency?first=&second=` -> transparency-log events + proofs.
  Served by the authority node only; a mirror does not relay them, so a client pointed at a mirror cannot
  run the log steps below today.
- `GET /policy/log` -> the `POLICY_PUBLISH` history + checkpoint.
- `POST /resolve` -> the answer, with `rosterVersion`: the roster version the answer was made against, left out
  when the roster changed while the answer was being made. With
  `trace: true` it also returns the decision trace (rule, policy id and version, zone), but only where
  `gua.resolver.abuse.trace-enabled` is on. That is off by default, because the trace shows policy internals
  to anonymous callers. `/resolve` is rate limited per client (20 per minute by default, `429` with
  `Retry-After`).

## 1. Verify the roster

1. Recompute the canonical bytes (`CanonicalRoster`): `version`, `issuedAt` (epoch millis), sorted entries,
   sorted claim predicates, and the `logCheckpoint` (merkle root + size). Each entry includes the
   homeserver's user-search discoverability policy: `searchVisibility` (`GLOBAL` default, `SERVER`, or
   `GROUP`) followed by its sorted `searchGroups` joined by `|` (empty when none), placed between
   `signingKey` and `admittedAt`. A resolver image from before 2026-08-14 serves entries without either field, and
   its signature covers bytes without them (`RosterForm.LEGACY`). When no entry carries
   `searchVisibility`, encode that older form; when every entry carries it, encode the two fields; refuse a
   roster that mixes the two. Production served the older form on 2026-10-27.
2. Count valid `authoritySignatures`: each must be Ed25519-valid over the canonical bytes under a trusted
   authority key, one vote per key. Require at least `k`.
3. Verify transparency-log consistency: the `logCheckpoint` must be an append-only extension of the last one
   the client saw (`verifyConsistency`). This detects a history rewritten since this client's own last
   checkpoint; it does not by itself rule out a split view between clients.

## 1a. Verify a member self-signature

An entry may carry a `member` block: the homeserver's own signature over the fields it controls
([signed federation objects](../specs/federation-signed-objects.md)). It is additive JSON, absent on
entries that have not been attested, and outside `CanonicalRoster`, so step 1 above is unchanged either way.

1. Parse the `member` block strictly. Unknown fields and trailing content are refused rather than ignored, so
   a signature cannot cover fewer fields than you go on to read. The resolver also refuses duplicate keys,
   which it detects while parsing the whole roster, so a duplicate refuses the roster. Require
   `schema` = `gua-member-entry.v1` and `alg` = `Ed25519`.
2. Recompute the canonical bytes with the `gua-lp.v1` rules (length-prefixed, no delimiters): the schema tag,
   then `homeserver.id`, `serverName`, `baseUrl`, `masIssuer`, `member.alg`, `homeserver.signingKey`,
   `member.keyId`, `member.sequence`, `notBefore` and `notAfter` as epoch milliseconds, `region` as an
   optional (absent and empty are different bytes), `searchVisibility` by name, and `searchGroups` as a set
   sorted by unsigned UTF-8 byte order with duplicates refused. `weight`, `acceptsNew`, `claims`,
   `admittedAt` and `status` are authority attributes and are not covered.
3. Require a `signatures[]` element whose `keyId` equals `member.keyId` and that verifies under
   `homeserver.signingKey`. A substituted `baseUrl`, `masIssuer`, `signingKey` or search policy fails here.
4. Require the verifier's current time to lie in `[notBefore, notAfter]`, and the window to be no longer than
   the published maximum entry lifetime (400 days).
5. If you already hold an accepted entry for that homeserver id: the sequence must not go backwards, one
   sequence must name one entry, and a changed `signingKey` must also be signed by the previous `keyId` under
   the previous key, with a new key id. With no prior state, step 3 plus the authority signature and log
   inclusion are what you have; what a client does about a changed identity is not decided.
6. A failure refuses that entry. It is dropped from the verified view and counted, never partially accepted.

The log commits to each accepted entry: a `MEMBER_ATTEST` leaf whose payload hash is the SHA-256 of the same
canonical bytes, at the index the entry was accepted. Golden vectors for the encoding, the entry bytes, the
hashes and the signatures are published in `docs/specs/gua-lp-v1-vectors.json`, so a port can be checked byte
for byte before it is trusted.

**Tolerated today.** The resolver serves entries that carry no member block, and its own transition flag
`gua.resolver.roster.require-member-signature` decides whether an unattested ACTIVE entry is served at all.
A verifier that refuses such entries on its own is ahead of the deployment and will see an empty roster in
environments that have not finished attesting.

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
   authority: the authority attests the delegate key and this protocol pins none.
3. **Validity + scope.** The bundle applies only while `notBefore <= now < expiresAt`, and so does each zone;
   a missing bound is open, and so is a bound at `1970-01-01T00:00:00Z`, which the canonical bytes cannot tell
   from a missing one. A rule must target a homeserver in its zone's `allowedHomeserverIds` and match
   within the zone scope (phone prefix / subdomain / OIDC issuer). Reject the bundle otherwise.
   `ResolverVerifier` and the apps check both windows. Only `RoutingPolicyValidator` checks scope and allowed
   homeservers, when a bundle is loaded from file and at `/authority/policy/validate`.
4. **Transparency.** The policy version's content hash (SHA-256 of the canonical bytes) must appear as a
   `POLICY_PUBLISH` leaf in the transparency log, so the served policy is the publicly logged one.

## 3. Reproduce the decision

Placement is a deterministic function of (verified roster, verified policy, context). Note that the weighted
fallback seeds on the roster version, which is the transparency-log size, so its result moves whenever a
policy or directory-checkpoint leaf is appended even when membership did not change. To verify a `/resolve` answer:

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
  verifiable in the current implementation. What a client can check is that the returned homeserver is an
  ACTIVE entry of the verified roster. The signed **directory checkpoint** (`GET /directory/checkpoint`)
  commits the authority node to a directory state as a whole and carries no proof for an individual mapping.

### Verified vs self-asserted claims

Institution/OIDC placement is granted only for affiliations/attributes that arrived inside a
signature-verified, subject-bound routing-claims envelope. A public caller's self-asserted
affiliations/attributes are never trusted for privileged routing. The verifier reproduces this: it applies
institution/OIDC rules only when the context is marked claims-verified.

The resolver accepts an envelope only when all of these hold (`RoutingClaimsVerifier`, pinned by
`RoutingClaimsVerifierTest`):

- it is signed by a trusted key and names this resolver as its audience;
- its subject is the phone number in the request (`claims.require-subject-binding`, on by default);
- it has not expired and its lifetime is at most `claims.max-lifetime` (5 minutes);
- its nonce has not been seen before. `JdbcRoutingClaimsReplayStore` records each issuer and nonce until the
  envelope can no longer be accepted (`claims.replay-protection-enabled`, on by default).

A public client can carry such an envelope but cannot create one.

## Canonical encodings (must match byte for byte)

- `CanonicalRoster`, `CanonicalRoutingPolicy`, `CanonicalDelegatedRules`, `CanonicalRoutingClaims` are the
  authoritative serializations. Routing-claims use backslash-escaped delimiters so the encoding is injective.
  All timestamps are epoch milliseconds; all maps/lists are sorted; all bytes are UTF-8.
- `gua-member-entry.v1` uses `gua-lp.v1`, a length-prefixed encoding with no delimiters at all: `u32`
  big-endian lengths, `int64` big-endian integers, a presence byte for optionals, sets sorted by unsigned
  UTF-8 byte order. It is the encoding for every newer signed object, specified in
  [signed federation objects](../specs/federation-signed-objects.md), and the vectors in
  `docs/specs/gua-lp-v1-vectors.json` pin it.
- Only the routing-claims encoding escapes. `CanonicalRoster` joins fields with a raw `0x1F` that is asserted,
  not enforced, to be absent from values, and collapses null and empty, except that a null `id`, `serverName`,
  `baseUrl` or `masIssuer` is the text `null`. `CanonicalRoutingPolicy` writes a missing instant and the epoch
  both as 0. Whoever serves a roster can therefore
  turn a null claim field into an empty string, or split a list element on `|`, without breaking the
  signature, and that changes which claims match. Port it byte for byte to verify what is served today; do
  not reuse it as the encoding for any new signed object.

Golden vectors for the roster bytes in both forms, authority signatures and thresholds, the transparency-log
leaves, roots and consistency proofs, routing-policy bundles with their delegate signatures and validity
windows, the policy's log step, reproduced placements and the check of a `/resolve` answer against the roster
are in `docs/specs/gua-client-verification-v1-vectors.json`. `./gradlew clientVerificationVectors` writes the
file from the production code, and `ClientVerificationVectorsTest` fails when the committed file differs. A port
runs the same file before its results are trusted.

## Failure handling

Any failed signature, threshold shortfall, broken consistency proof, expired artifact, out-of-scope rule, or
reproduced-decision mismatch means the resolver's answer is not trustworthy: the client must fall back to a
different mirror or refuse to proceed, never silently accept the unverified answer.

## Report-only verification in the apps

The web, iOS and Android apps run the six checks below after each `/resolve` answer. The result never changes
what the app connects to and never delays sign-in. Each run logs one line, so enforcement can be turned on per
check once real traffic shows no failures.

**Inputs and limits.** Each build carries its environment's authority keys and threshold, and its policy keys
and threshold. A run has 10 seconds on a monotonic clock. A fetch that fails or answers anything but a 2xx is
`unverifiable(roster_unavailable)`, `unverifiable(log_unavailable)` or `unverifiable(policy_unavailable)`, except
a `404` from `/policy/routing` (check 5). A response over 2 MiB, nested more than 64 levels, or not of the
expected shape makes the checks that need it `unverifiable(parse_error)`. The expected shape includes:
timestamps in the resolver's form (ISO-8601 UTC with an uppercase `T` and `Z`), sizes and indexes that fit in 31
bits, and consistency proof hashes of 64 lowercase hex characters. A signature entry without a key id or a value
counts as a signature that does not verify. The apps do not look for duplicate keys: every signature is checked
over the values the app parsed, so a duplicate cannot get unsigned data accepted. On the web, checks 1, 4 and 5 start when the phone step opens, and the report is logged just
before the browser leaves for sign-in, with any check still running as `unverifiable(timeout)`.

**Outcomes.** Each check reports one outcome. `invalid`, `unverifiable` and `indeterminate` carry one reason,
written `outcome(reason)`.

1. **rosterSignature.** The form comes from the served JSON (section 1, step 1), and a mixed roster is
   `unverifiable(mixed_roster_form)`. Too few valid signatures is `invalid(unknown_key_id)` when no signature
   names a trusted key, `invalid(bad_signature)` when some do and none verifies, and
   `invalid(threshold_not_met)` otherwise. Unless this check is `valid`, whatever its reason, the other five are
   `unverifiable(roster_unverified)` and nothing more is fetched.
2. **homeserverMatch** locates the answer's `serverName`, `baseUrl` and `masIssuer` in the roster with
   `ResolverVerifier.locate`: `ACTIVE_MATCH`, `INACTIVE`, `FIELD_MISMATCH` or `NOT_IN_ROSTER`. Only
   `ACTIVE_MATCH` passes.
3. **memberEntry** checks the member block (section 1a) of the entry that check 2 located, when it is
   `ACTIVE_MATCH` or `INACTIVE`. An entry without a block is `unattested`, which passes while the deployment
   does not require one. `FIELD_MISMATCH` and `NOT_IN_ROSTER` give `unverifiable(no_matching_entry)`. A block
   that fails is `invalid` with one of `parse_error` (an unknown field, or a field of the wrong type, null
   included, or a bound that does not parse), `unsupported_schema`, `unsupported_alg`, `bad_key_id`,
   `bad_sequence`, `bad_window` (a missing bound, sub-millisecond precision, `notAfter` not after `notBefore`,
   or more than 400 days), `outside_window`, `malformed_signature`, `no_canonical_encoding`,
   `bad_signing_key`, `missing_signature` or `bad_signature`.
4. **logConsistency** compares the roster's checkpoint with the last one the app accepted from this resolver
   base URL. With no pin yet it is `firstSeen` and pins the checkpoint. The same size needs the same root. A
   larger size needs a proof from `/roster/log/consistency` that verifies, as RFC 9162 section 2.1.4.2 checks it,
   and then moves the pin. Those are `consistent`, or `inconsistent` when they fail. A smaller size is `rollback`. A pin store that cannot be
   read or written is `unverifiable(storage_unavailable)`. Runs against one resolver never overlap, so the pin
   only moves forward.
5. **policy.** The first `checkpoint.size` leaves of `/roster/log` must hash to the signed root, whether a
   policy is served or not (`invalid(log_mismatch)`). A `404` from `/policy/routing` is then `notPresent`, which
   passes, when none of those leaves is a `POLICY_PUBLISH`, and `unverifiable(policy_not_served)` when one is.
   A served bundle must:
   - verify under the policy keys, with the same three reasons as check 1, or be
     `unverifiable(no_policy_keys)` when none is configured;
   - be in effect now, else `invalid(outside_window)`;
   - have its `POLICY_PUBLISH` leaf among those leaves. No matching leaf is `invalid(policy_not_logged)`. A
     leaf only past the checkpoint, as right after an honest publish, is
     `unverifiable(policy_newer_than_checkpoint)`;
   - be the newest version of its `policyId` within the checkpoint, read from the leaf subjects
     `<policyId>:v<version>`, else `unverifiable(policy_superseded)`.

   A checkpoint of more than 4,096 leaves is `unverifiable(log_too_large)`, and the log is not fetched.
6. **placement**, in this order:
   - an answer whose `exists` is true or missing is `indeterminate(existing_account)`, since a directory lookup
     cannot be reproduced;
   - a check 5 that is neither `valid` nor `notPresent` makes it `unverifiable(policy_unverified)`;
   - otherwise section 3 runs for the phone number alone. When a rule that matches the phone and ranks above
     the rule that decided sits in a zone without a valid delegate signature, the result is
     `indeterminate(unsigned_rule)`. Delegate signatures are covered by neither the bundle signatures nor its
     log leaf, so a missing one cannot be told from a removed one. Policy rules rank by priority, then id, and
     all of them rank above roster claims and the fallback;
   - a reproduced entry with the answer's `serverName`, `baseUrl` and `masIssuer` is `match`. Any other result
     is `mismatch` when the answer's `rosterVersion` equals the verified roster's, and
     `indeterminate(unattributed)` when it differs or is missing.

A check still working when the 10 seconds run out is `unverifiable(timeout)`, and an unexpected error is
`unverifiable(internal_error)`. With no usable authority key every check is `unverifiable(no_trust_roots)`,
and on a platform without Ed25519 every check is `unverifiable(crypto_unsupported)`. Nothing is fetched in
those two cases, and the report is still logged.

**Overall and the report line.** `overall` is `failed(<check>)` for the first check that is `invalid`,
`INACTIVE`, `FIELD_MISMATCH`, `NOT_IN_ROSTER`, `rollback`, `inconsistent` or `mismatch`. Otherwise it is
`unverifiable(<check>)` for the first check that is `unverifiable` or `indeterminate`, and otherwise
`verified`. Every app logs the same line at info level, with no phone number, URL, server name or answer:

```
Resolver verification environment=dev rosterVersion=4 rosterForm=v1 rosterSignature=valid homeserverMatch=ACTIVE_MATCH memberEntry=unattested logConsistency=consistent policy=valid placement=indeterminate(existing_account) overall=unverifiable(placement) durationMs=640
```

`rosterVersion` is `none` unless the roster signature is valid. `rosterForm` is `v1`, `legacy` or `mixed` as
detected from the served JSON, and `none` when no roster was read.

**Compatibility while report-only.**

- Production serves the legacy roster form, no routing policy and no `rosterVersion` in its answers, so a
  placement that differs there is `indeterminate(unattributed)`.
- Each environment lists its policy keys explicitly. Dev lists its authority key, because that key signs its
  policy. Production lists none until governance keys exist, so a policy served there would be
  `unverifiable(no_policy_keys)`.
- A mirror serves no transparency log. Check 4 still passes or fails while the checkpoint has not grown, and is
  `unverifiable(log_unavailable)` once it has. Check 5 is always `unverifiable(log_unavailable)`.
- The pin survives sign-out and is cleared only with the app's data. After a log is recreated, as in a dev
  reset, every run reports `rollback` until then.
- A rotation of an authority key needs an app release that lists both keys. Until the apps verify the
  governance chain, there is no in-band way to learn a new key, and none is attempted.

Enforcement is turned on per check, starting with check 2, after report-only traffic for that check has shown
no `invalid` outcome from legitimate deployments for a period the operator sets.
