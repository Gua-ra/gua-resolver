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
gua.resolver.claims.trusted-keys[0].id=<mas-or-identity-key-id>
gua.resolver.claims.trusted-keys[0].public-key=<base64-x509-ed25519-public-key>
```

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
