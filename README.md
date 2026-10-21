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

**`POST /resolve`.** A phone number goes in. A homeserver to log in to or register at comes out. Today the resolver reads the phone directory first and evaluates the routing policy against the roster only for a phone with no account.

**`GET /roster`.** The signed list of federated homeservers, recorded in a transparency log. Each roster carries `k`-of-`n` authority signatures and a Merkle log checkpoint. Mirrors can serve it. An entry can also carry the member's own signature over the fields that homeserver controls, so the authority alone can no longer rewrite a member's address or key; the resolver verifies it before serving and records each accepted one in the log.

**`GET /policy/routing`.** Signed policy bundles. They keep routing rules separate from roster membership. A bundle can delegate zones to carriers, institutions and sign-on issuers. Institution and issuer rules need a routing-claims envelope that is signed, short-lived and replay-protected. A public client can carry such a claim but cannot create one on its own.

### Interim abuse controls

`POST /resolve` answers `exists` for any raw E.164 with no account session. The decision record ([ADM-001](docs/decisions/ADM-001-identifier-binding-placement-trust.md)) lists that as an enumeration oracle to close. Until the client verification phase changes the response, the endpoint carries these interim controls, all on by default and configured under `gua.resolver.abuse.*`:

- **Per-client rate limit.** A token bucket per client, keyed by the request's remote address as Tomcat reports it once `RemoteIpValve` has resolved the forwarded chain (`server.forward-headers-strategy=native`, pinned in `application.yml`). The pod receives `X-Forwarded-For` as caller-supplied entries, then the client address the public edge appended, then the internal hop the in-cluster ingress appended; the valve skips the internal hops, takes the client address, and leaves only the caller-supplied leftovers in the header, which the limiter never reads. IPv6 clients are keyed by /64. Default 20 requests per minute with a burst of 20.
- **Global ceiling.** A second bucket for the whole process, default 200 requests per second. Both buckets are per pod: the deployed resolver runs a single pod, and under the deployment's opt-in autoscaling profile (2 to 3 replicas) the effective in-service per-client rate becomes replicas x 20 per minute. The per-source limit shared across replicas is the Traefik `rateLimit` middleware on the resolver ingress, defined in the deployment manifests: 10 requests per second average with a burst of 30, per source address. The in-service buckets are the floor that holds for a request that reaches a pod without passing the ingress.
- **The 429 contract.** Over either limit the service answers `429 Too Many Requests` with a `Retry-After` header in seconds and the constant body `{"code":"rate_limited","message":"..."}`. The request body is not read, so a refused request reveals nothing about the phone.
- **Decision trace.** `"trace": true` returns the matched rule, policy id and version, delegated zone and roster version only when `abuse.trace-enabled` is `true`. It is off by default because the trace exposes policy internals to anonymous callers; the dev testbed runbook depends on it, so the dev deployment has to set `GUA_RESOLVER_ABUSE_TRACE_ENABLED=true`.
- **Observability.** `gua_resolver_resolve_ratelimited_total{scope="client"|"global"}` counts refusals, `gua_resolver_resolve_clients_tracked` gauges the distinct clients held (bounded by `abuse.max-tracked-clients`), and the first refusal per client per window logs a WARN carrying a truncated hash of the client key, never the phone.

The `exists` flag stays in the response contract: the iOS and Android clients choose login versus create from it, and it changes only when the client verification phase changes the response, as the decision record requires. `abuse.enabled=false` switches the rate limits off (the rollback lever); the trace switch is independent of it.

## How this relates to the target architecture

The code on `main` is the current implementation. The decision record defines the target. Three things differ in what this service serves today:

- **Resolution.** Today: for a new account the resolver evaluates policy on every request; for an existing account it reads the phone directory. Nothing writes that directory over HTTP any more (the member write endpoint was removed, as the decision record requires); the rows already there stay, and are still read, until placement records replace them. Target: the answer is backed by a committed, signed placement record.
- **Roster.** Today: the roster carries authority signatures and a log checkpoint, and an entry can also carry the member's own signature over its endpoint, key and search fields ([ADM-007](docs/decisions/ADM-007-canonical-encoding-and-member-entries.md)), which the authority verifies and commits to the log. Entries with no member signature are still served, because `roster.require-member-signature` is off, and clients do not check member signatures yet, so the protection currently holds against a resolver that rewrites its own database rather than against one that serves a client an entry it never logged. Target: every entry is self-signed and clients refuse entries without one.
- **Governance.** Today: the resolver can load a pinned federation genesis, publish it at `GET /.well-known/gua-federation`, and accept governance-signed membership epochs that it serves at `GET /registry/homeservers/epoch/*` and commits to the log. Policy bundles are signed offline, not by this process, and verify under those governance keys once `governance.required` is on; until then they verify under the operational key set the environment already runs on. `governance.required` is off in both environments until the key ceremony has run, so membership still changes on the operational key today. And with one operator holding both keys, what this separates is processes and custody, not principals: every independence guarantee still reduces to compromising Gua. Target: a second operator holds a governance key, and clients verify the chain before connecting.
- **Directory pepper.** Today: `directory.pepper` is a secret shared with identity-service. Target: blinded routing keys replace it. The migration plan has a phase for this. The construction is not chosen yet.

Mirror mode exists and is exercised in tests. How an independently operated resolver bootstraps and verifies its state is still an open decision. Nothing like that runs today.

How the pieces fit together is in the [architecture guide](docs/architecture/gua-identity-and-federation.md). The reasoning behind each target, and the open decisions, are in [ADM-001](docs/decisions/ADM-001-identifier-binding-placement-trust.md).

## Configuration (`gua.resolver.*`)

- `mode`: `AUTHORITY` or `MIRROR`.
- `authority.threshold` (`k`), `authority.trusted-keys[]` (`n`), `authority.signing-key-id`, `authority.signing-private-key`.
- `policy.enabled`, `policy.file`, `policy.require-signatures`, `policy.signature-threshold`, `policy.trusted-keys[]`. Which keys a bundle verifies under follows `governance.required` and nothing else. With it off: `policy.trusted-keys`, or `authority.trusted-keys` when that list is unset, which is the pre-cutover fallback an existing deployment is serving on. With it on: the genesis governance key set alone, no fallback, so a bundle still signed by the operational key is refused and the file policy source will not start.
- `claims.audience`, `claims.max-lifetime`, `claims.replay-protection-enabled`, `claims.trusted-keys[]`. Gated on `governance.required` like the policy trust root. With it on, an empty `claims.trusted-keys` rejects every routing-claims envelope and there is no fallback to the policy or authority keys. With it off, the pre-cutover chain (claims, then policy, then authority) is preserved. Nothing issues envelopes today, so a future claims issuer ships its public key into this list before the cutover.
- `genesis.file`, `genesis.transitions-file`, `genesis.expected-id`, `genesis.expected-chain-head`: the pinned federation genesis. The file is public and committed; `expected-id` is the pin, and a file that does not hash to it fails startup. `expected-chain-head` pins how far the governance key chain has run, so a truncated or removed transitions file fails startup too instead of quietly reinstating a key that was rotated out. Unset means governance is off.
- `governance.required`: the governance cutover. With it on, an admission lands `PENDING` and stays out of `/roster` until an epoch admits it, a suspend or revoke records intent only and appends a `STATUS_INTENT` log leaf, and only a governance-signed membership epoch changes a served status. The same flag also selects the routing-policy and routing-claims trust roots, so the whole cutover moves on one deliberate flip and setting it back to false rolls all of it back with no code rollout (`docs/runbooks/governance-keys.md`).
- `mirror.upstream-url`, `mirror.refresh-interval`, `mirror.cache-file`.
- `roster.require-member-signature`, `roster.member-max-lifetime`: the member self-signature transition. With the flag on, an ACTIVE entry carrying no valid member signature is excluded from `/roster`, from placement and from existing-account resolution, so every ACTIVE member is attested first (`docs/runbooks/member-attestation.md`); setting it back to false is the rollback. Env overrides take the form `GUA_RESOLVER_ROSTER_<KEY>`.
- `directory.pepper`: must match identity-service. Scheduled for replacement; see the migration plan.
- `abuse.enabled`, `abuse.client-limit-for-period`, `abuse.client-refresh-period`, `abuse.client-burst`, `abuse.global-limit-for-period`, `abuse.global-refresh-period`, `abuse.global-burst`, `abuse.max-tracked-clients`, `abuse.client-expiry`, `abuse.trace-enabled`: the interim `/resolve` abuse controls above. Every key has an env override of the form `GUA_RESOLVER_ABUSE_<KEY>`.

Both deployed environments run a single node in `AUTHORITY` mode with `k = 1` and `n = 1`. One operator holds every key. The `k`-of-`n` signing and the mirror mode work and are exercised in tests, but no multi-operator deployment exists yet.

## Run it locally

Needs Postgres; Flyway applies `src/main/resources/db/migration`.

```sh
GUA_RESOLVER_ABUSE_TRACE_ENABLED=true ./gradlew bootRun   # :8095
curl -s localhost:8095/roster | jq
curl -s -XPOST localhost:8095/resolve -H 'content-type: application/json' \
  -d '{"phone":"+5511987654321","trace":true}' | jq
curl -s localhost:8095/policy/routing/status | jq
```

## Test

- Java 21 and Spring Boot 3.5.6.
- Postgres for persistence. Flyway migrations live in `db/migration/`.
- H2 for tests.

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

## Reporting problems

- Bugs and requests: [GitHub issues](https://github.com/Gua-ra/gua-resolver/issues).
- Security problems: [SECURITY.md](SECURITY.md), never a public issue.
