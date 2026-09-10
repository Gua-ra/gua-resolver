> **Status: HISTORICAL VALIDATION/DESIGN.** A migration plan from July 2026, preserved for provenance. **Not normative.**
>
> This was the phased rollout plan for signed routing policy and resolver mirrors. Phases 0 to 3 are done as far as this plan's code work goes: policy is enabled from a mounted file and signed, the routing-claims verifier and fail-closed directory lookup ship, and mirror mode with its cache exists and is covered by tests. Both deployed environments still run a single node, so the second node of phase 3 is a test fixture rather than a deployment.
>
> Phases 4 and 5 are superseded by [ADM-001](../../decisions/ADM-001-identifier-binding-placement-trust.md) and should not be executed as written:
>
> - **Phase 4, production governance.** It raises the resolver's own signing threshold and configures MAS or identity-service as routing-claims issuers. ADM-001 roots governance in a pinned federation genesis held outside the resolver process (L10, S5) and keeps identity-service out of federation-scope artifacts (L2).
> - **Phase 5, directory availability.** Every option it lists keeps the member-written directory. ADM-001 replaces that directory with verifier-attested binding records and signed placement records (L1b, L6, L7), and separates replica count from authority (O12).
> - **The backward-compatibility notes** treat the `exists` flag in `/resolve` and the directory-write signature string as contracts to preserve. ADM-001 marks the first as an enumeration defect to remove (L16) and the second as a path to delete (L1b).
>
> The current plan is [gua-resolver-migration-plan.md](../gua-resolver-migration-plan.md).

# Gua Resolver Migration Plan

Date: 2026-07-03

## Migration Goals

- Keep public and mobile clients working.
- Introduce signed routing policy gradually.
- Avoid routing split-brain.
- Preserve MAS/OIDC compatibility.
- Make rollback possible.

## Phase 0: Current Compatible Release

Ship code with:

- `gua.resolver.policy.enabled=false`,
- deterministic fallback,
- trace support,
- security default deny,
- signed routing-claims verifier available,
- mirror directory lookup fail-closed by default,
- policy endpoints returning empty status/no policy.

Expected behavior:

- existing `/resolve` clients continue to work,
- no routing-policy file required,
- roster claims keep working.

Validation:

```sh
./gradlew test --no-daemon
curl -s -X POST http://localhost:8095/resolve \
  -H 'content-type: application/json' \
  -d '{"phone":"+5511987654321"}'
curl -s -X POST http://localhost:8095/resolve \
  -H 'content-type: application/json' \
  -d '{"phone":"+5511987654321","trace":true}'
```

## Phase 1: Dev Policy Shadow Mode

Create an unsigned or test-signed policy file based on
`src/main/resources/policies/delegated-routing.example.json`.

Run with signatures optional only in local/dev:

```sh
GUA_RESOLVER_POLICY_ENABLED=true \
GUA_RESOLVER_POLICY_FILE=/path/to/delegated-routing.dev.json \
GUA_RESOLVER_POLICY_REQUIRE_SIGNATURES=false \
./gradlew bootRun
```

Use `/policy/routing/status` and trace mode to confirm rules match as expected.

## Phase 2: Signed Dev Policy

Generate a policy signing key or reuse dev authority key.

Configure:

```text
GUA_RESOLVER_POLICY_ENABLED=true
GUA_RESOLVER_POLICY_FILE=/etc/gua/policy/routing.json
GUA_RESOLVER_POLICY_REQUIRE_SIGNATURES=true
GUA_RESOLVER_POLICY_SIGNATURE_THRESHOLD=1
GUA_RESOLVER_POLICY_KEY_ID=<dev-policy-key>
GUA_RESOLVER_POLICY_PRIVATE_KEY=<private-key-for-signing-node-only>
```

Policy-serving mirrors should have trusted public keys but no private signing key.

## Phase 3: Mirror Rollout

Run at least two resolver nodes:

- national/public resolver,
- institutional or regional mirror.

Each mirror must:

- verify roster,
- verify routing policy,
- expose status,
- configure `GUA_RESOLVER_MIRROR_CACHE_FILE` before production,
- keep `GUA_RESOLVER_DIRECTORY_FAIL_OPEN_ON_LOOKUP_ERROR=false` unless there is a documented legacy need.

## Phase 4: Production Governance

Move from 1-of-1 to k-of-n signing:

- roster threshold >= 2 where practical,
- policy threshold >= 2 where practical,
- separate keys for roster and routing policy if governance roles differ,
- documented emergency revocation process.

Replace placeholder domain proof verifier with DNS or well-known challenge before admitting real third-party
homeservers.

Configure trusted routing-claims keys:

```text
GUA_RESOLVER_CLAIMS_AUDIENCE=gua-resolver
GUA_RESOLVER_CLAIMS_MAX_LIFETIME=PT5M
GUA_RESOLVER_CLAIMS_REPLAY_PROTECTION_ENABLED=true
gua.resolver.claims.trusted-keys[0].id=<mas-or-identity-key-id>
gua.resolver.claims.trusted-keys[0].public-key=<base64-x509-ed25519-public-key>
```

MAS/identity-service must generate a fresh nonce per signed routing-claims envelope. Reusing a nonce should
be treated as a client/auth bug: resolver replicas share the `routing_claim_nonce` table and will reject the
second use.

## Phase 5: Directory Availability

Do not rely indefinitely on one authority directory.

Choose one:

- HA Postgres and multiple authority pods,
- signed privacy-preserving directory shards,
- short-lived mirror caches with staleness budget,
- identity-service-assisted account routing for existing users.

Returning-user lookup should not silently become new-user placement during directory outage.

## Rollback

Set:

```text
GUA_RESOLVER_POLICY_ENABLED=false
```

This restores legacy roster-claim plus deterministic fallback behavior. Keep the code change because
deterministic fallback and security allowlist are improvements independent of policy.

## Backward Compatibility Notes

- `/resolve` request still requires only `phone`.
- `/resolve` response still has `exists`, `homeserver`, and `registerAt`.
- `trace` is opt-in and omitted otherwise.
- Existing Android, iOS, and web clients decode the legacy fields.
- Existing identity-service directory writes still use the same canonical signature string.
