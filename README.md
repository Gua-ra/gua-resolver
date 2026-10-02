![gua-resolver](https://github.com/user-attachments/assets/01bd66c7-6250-42ce-a4d0-1f8ade952ca2)

gua-resolver is the routing front door of the Gua federation. Before login, a client asks it which homeserver an identifier leads to. It also serves the signed list of federated homeservers.

The resolver serves and verifies routing information. It does not authenticate anyone and never holds a credential.

## Endpoints

- `POST /resolve`: a phone number in, the homeserver to log in to or register at out. Rate limited per client and globally; over the limit it answers `429` with `Retry-After`.
- `GET /roster`: the signed list of federated homeservers. Its transparency log is at `/roster/log` and `/roster/log/consistency`.
- `GET /policy/routing`: the signed routing policy bundle, with `/policy/routing/status` and `/policy/log`.
- `GET /directory/lookup`, `GET /directory/checkpoint`: the mirror-facing directory read and its signed checkpoint.
- `GET /.well-known/gua-federation`, `GET /registry/homeservers/epoch/{current|n}`: the pinned federation genesis and the governance-signed membership epochs.
- `POST /placement/records`, `GET /placement/records`, `GET /placement/records/{accountId}`: placement record ingest and reads, mapped only when `placement.enabled` is on.
- `/authority/**`: admission, status changes, member attestation, policy validation and epoch submission. HTTP Basic, `ADMIN` role.
- `/actuator/health`, `/actuator/prometheus`, `/swagger-ui.html`.

## Run

Needs Postgres; Flyway applies `src/main/resources/db/migration`.

```sh
GUA_RESOLVER_ABUSE_TRACE_ENABLED=true ./gradlew bootRun   # :8095
curl -s localhost:8095/roster | jq
curl -s -XPOST localhost:8095/resolve -H 'content-type: application/json' \
  -d '{"phone":"+5511987654321","trace":true}' | jq
curl -s localhost:8095/policy/routing/status | jq
```

## Test

```sh
./gradlew test
```

Tests run on in-memory H2 and need no Docker.

## Deploy

`.github/workflows/ci-cd.yml` builds `ghcr.io/gua-ra/gua-resolver`. A merge to `main` deploys dev and stages prod behind approval of the `production` environment. A PR labelled `deploy:dev` rolls that branch onto dev.

## Configuration (`gua.resolver.*`)

Each key has a `GUA_RESOLVER_*` environment override, listed in `src/main/resources/application.yml`.

- `mode`: `AUTHORITY` or `MIRROR`.
- `authority.threshold`, `authority.trusted-keys[]`, `authority.signing-key-id`, `authority.signing-private-key`: roster signing and verification.
- `admin.username`, `admin.password-hash`: HTTP Basic for `/authority/**`.
- `directory.pepper`, `directory.fail-open-on-lookup-error`, `directory.checkpoint-interval`: the phone and username directory.
- `policy.enabled`, `policy.file`, `policy.require-signatures`, `policy.signature-threshold`, `policy.trusted-keys[]`, `policy.refresh-interval`: the routing policy bundle.
- `claims.audience`, `claims.max-clock-skew`, `claims.max-lifetime`, `claims.replay-protection-enabled`, `claims.require-subject-binding`, `claims.trusted-keys[]`: signed routing-claims envelopes.
- `genesis.file`, `genesis.transitions-file`, `genesis.expected-id`, `genesis.expected-chain-head`: the pinned federation genesis. A genesis id or chain head that differs from its pin fails startup.
- `governance.required`: when on, an admission lands `PENDING`, membership changes only through a governance-signed epoch, policy bundles verify only under the genesis governance keys, and claims only under `claims.trusted-keys`. Follow the [governance keys runbook](docs/runbooks/governance-keys.md) before turning it on.
- `roster.require-member-signature`, `roster.member-max-lifetime`: member self-signature enforcement. Follow the [member attestation runbook](docs/runbooks/member-attestation.md) before turning it on.
- `mirror.upstream-url`, `mirror.refresh-interval`, `mirror.cache-file`, `mirror.lookup-timeout`, `mirror.directory-cache-ttl`.
- `abuse.enabled`, `abuse.client-limit-for-period`, `abuse.client-refresh-period`, `abuse.client-burst`, `abuse.global-limit-for-period`, `abuse.global-refresh-period`, `abuse.global-burst`, `abuse.max-tracked-clients`, `abuse.client-expiry`: the `/resolve` rate limits. `abuse.trace-enabled` lets `"trace": true` return the decision trace.
- `placement.enabled`, `placement.ingest-enabled`, `placement.checkpoint-interval`, `placement.audit-interval`, `placement.metrics-interval`, `placement.max-validity`, `placement.default-page-size`, `placement.max-page-size`: placement record custody and ingest. Off by default.
- `dev-homeserver.*`: the homeserver seeded into an empty roster.

## Documentation

- [Architecture guide](docs/architecture/gua-identity-and-federation.md), and [what is not built yet](docs/architecture/planned-federation-work.md)
- Specifications: [signed federation objects](docs/specs/federation-signed-objects.md), [account identifiers and placement records](docs/specs/account-identifiers-and-placement-records.md). Test vectors sit beside them in `docs/specs/`.
- [Verification protocol](docs/verification/gua-resolver-verification-protocol.md)
- [Migration plan](docs/migrations/gua-resolver-migration-plan.md)
- Runbooks: [governance keys](docs/runbooks/governance-keys.md), [member attestation](docs/runbooks/member-attestation.md)
- [Where the former decision records went](docs/decisions/README.md)

Stack: Java 21, Spring Boot 3.5.6.
