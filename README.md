![gua-resolver](https://github.com/user-attachments/assets/01bd66c7-6250-42ce-a4d0-1f8ade952ca2)

gua-resolver is the routing front door of the Gua federation. Before login, a client asks it which homeserver an identifier leads to. It also serves the signed list of federated homeservers.

The resolver serves and verifies routing information. It does not authenticate anyone and it never holds a credential. It is public and read-mostly. Running a resolver grants no authority over the federation.

> **Which document do you want?**
> - How routing, placement and binding fit together: [architecture guide](docs/architecture/gua-identity-and-federation.md).
> - The frozen decisions behind the target design: [ADM-001](docs/decisions/ADM-001-identifier-binding-placement-trust.md).
> - How a client verifies what this service serves today: [verification protocol](docs/verification/gua-resolver-verification-protocol.md).
> - How the current code gets to the target: [migration plan](docs/migrations/gua-resolver-migration-plan.md).
>
> This README is the operational document. It describes what the code on `main` does. Where the target differs, the target is marked.

## What it does today

Callers use three endpoints.

**`POST /resolve`.** A phone number goes in. A homeserver to log in to or register at comes out. Today the resolver evaluates the routing policy against the roster on every request.

**`GET /roster`.** The signed list of federated homeservers, recorded in a transparency log. Each roster carries `k`-of-`n` authority signatures and a Merkle log checkpoint. Mirrors can serve it.

**`GET /policy/routing`.** Signed policy bundles. They keep routing rules separate from roster membership. A bundle can delegate zones to carriers, institutions and sign-on issuers. Institution and issuer rules need a routing-claims envelope that is signed, short-lived and replay-protected. A public client can carry such a claim but cannot create one on its own.

### Interim abuse controls

`POST /resolve` answers `exists` for any raw E.164 with no account session, which ADM-001 L16 names as the enumeration oracle to close. Until the client verification phase changes the response, the endpoint carries these interim controls, all on by default and configured under `gua.resolver.abuse.*`:

- **Per-client rate limit.** A token bucket per client, keyed by the last `X-Forwarded-For` address (the one the ingress appends; earlier entries are caller-controlled) or by the peer address when the header is absent. IPv6 clients are keyed by /64. Default 20 requests per minute with a burst of 20.
- **Global ceiling.** A second bucket for the whole process, default 200 requests per second. Both buckets are per pod; the limit shared across replicas is the ingress-level limiter, which lives in gua-deploy.
- **The 429 contract.** Over either limit the service answers `429 Too Many Requests` with a `Retry-After` header in seconds and the constant body `{"code":"rate_limited","message":"..."}`. The request body is not read, so a refused request reveals nothing about the phone.
- **Decision trace.** `"trace": true` returns the matched rule, policy id and version, delegated zone and roster version only when `abuse.trace-enabled` is `true`. It is off by default because the trace exposes policy internals to anonymous callers; the dev testbed runbook depends on it, so the dev deployment has to set `GUA_RESOLVER_ABUSE_TRACE_ENABLED=true`.
- **Observability.** `gua_resolver_resolve_ratelimited_total{scope="client"|"global"}` counts refusals, `gua_resolver_resolve_clients_tracked` gauges the distinct clients held (bounded by `abuse.max-tracked-clients`), and the first refusal per client per window logs a WARN carrying a truncated hash of the client key, never the phone.

The `exists` flag stays in the response contract: the iOS and Android clients choose login versus create from it, and it changes only when the client verification phase changes the response, per ADM-001 L16. `abuse.enabled=false` switches the rate limits off (the rollback lever); the trace switch is independent of it.

## How this relates to the target architecture

The code on `main` is the current implementation. The decision record defines the target. Three things differ in what this service serves today:

- **Resolution.** Today: the resolver evaluates policy on every request. Target: the answer is backed by a committed, signed placement record.
- **Roster.** Today: the roster carries authority signatures and a log checkpoint. Target: each entry is also self-signed by the member it describes.
- **Directory pepper.** Today: `directory.pepper` is a secret shared with identity-service. Target: blinded routing keys replace it. The migration plan has a phase for this. The construction is not chosen yet.

Mirror mode exists and is exercised in tests. How an independently operated resolver bootstraps and verifies its state is still an open decision. Nothing like that runs today.

How the pieces fit together is in the [architecture guide](docs/architecture/gua-identity-and-federation.md). The reasoning behind each target, and the open decisions, are in [ADM-001](docs/decisions/ADM-001-identifier-binding-placement-trust.md).

## Configuration (`gua.resolver.*`)

- `mode`: `AUTHORITY` or `MIRROR`.
- `authority.threshold` (`k`), `authority.trusted-keys[]` (`n`), `authority.signing-key-id`, `authority.signing-private-key`.
- `policy.enabled`, `policy.file`, `policy.require-signatures`, `policy.signature-threshold`.
- `claims.audience`, `claims.max-lifetime`, `claims.replay-protection-enabled`, `claims.trusted-keys[]`.
- `mirror.upstream-url`, `mirror.refresh-interval`, `mirror.cache-file`.
- `directory.pepper`: must match identity-service. Scheduled for replacement; see the migration plan.
- `abuse.enabled`, `abuse.client-limit-for-period`, `abuse.client-refresh-period`, `abuse.client-burst`, `abuse.global-limit-for-period`, `abuse.global-refresh-period`, `abuse.global-burst`, `abuse.max-tracked-clients`, `abuse.client-expiry`, `abuse.trace-enabled`: the interim `/resolve` abuse controls above. Every key has an env override of the form `GUA_RESOLVER_ABUSE_<KEY>`.

Both deployed environments run a single node in `AUTHORITY` mode with `k = 1` and `n = 1`. One operator holds every key. The `k`-of-`n` signing and the mirror mode work and are exercised in tests, but no multi-operator deployment exists yet.

## Run it locally

```sh
GUA_RESOLVER_ABUSE_TRACE_ENABLED=true ./gradlew bootRun   # :8095; the trace below is off unless enabled
curl -s localhost:8095/roster | jq
curl -s -XPOST localhost:8095/resolve -H 'content-type: application/json' \
  -d '{"phone":"+5511987654321"}' | jq
curl -s -XPOST localhost:8095/resolve -H 'content-type: application/json' \
  -d '{"phone":"+5511987654321","trace":true}' | jq
curl -s localhost:8095/policy/routing/status | jq
```

### Dependencies

- Postgres for persistence. Flyway migrations live in `db/migration/`.
- H2 for tests.

## Relationship to identity-service

Today identity-service is the single login provider and credential store for every homeserver. The resolver shares its directory pepper with identity-service. That is the current implementation, not the target.

Under the target, each homeserver's own auth service owns authentication. What remains of identity-service's role is decided in a follow-up record. The resolver's role does not change either way: it routes, and it never holds a credential.

Stack: Java 21, Spring Boot 3.5.6.
