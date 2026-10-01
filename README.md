![gua-resolver](https://github.com/user-attachments/assets/01bd66c7-6250-42ce-a4d0-1f8ade952ca2)

gua-resolver is the routing front door of the Gua federation. Before login, a client asks it which homeserver an identifier leads to. It also serves the signed list of federated homeservers.

The resolver serves and verifies routing information. It does not authenticate anyone and it never holds a credential. It is public and read-mostly. Running a resolver grants no authority over the federation.

> **Which document do you want?**
> - How routing, placement and binding fit together: [architecture guide](docs/architecture/gua-identity-and-federation.md).
> - The frozen decisions behind the target design: [ADM-001](docs/decisions/ADM-001-identifier-binding-placement-trust.md).
> - How a client verifies what this service serves today: [verification protocol](docs/verification/gua-resolver-verification-protocol.md).
> - How the current code gets to the target: [migration plan](docs/migrations/gua-resolver-migration-plan.md).
> - How an operator signs a homeserver's own roster entry: [member attestation runbook](docs/runbooks/member-attestation.md).
> - What a record label such as `ADM-001 L8`, `O9` or `phase 2` refers to: [decision record identifiers](docs/decisions/IDENTIFIERS.md).
>
> This README is the operational document. It describes what the code on `main` does. Where the target differs, the target is marked.

## What it does today

Clients use three endpoints; mirrors and verifiers also read `/roster/log`, `/roster/log/consistency`, `/policy/log`, `/policy/routing/status`, `/directory/lookup` and `/directory/checkpoint`.

**`POST /resolve`.** A phone number goes in. A homeserver to log in to or register at comes out. Today the resolver reads the phone directory first and evaluates the routing policy against the roster only for a phone with no account.

**`GET /roster`.** The signed list of federated homeservers, recorded in a transparency log. Each roster carries `k`-of-`n` authority signatures and a Merkle log checkpoint. Mirrors can serve it. An entry can also carry the member's own signature over the fields that homeserver controls, so the authority alone can no longer rewrite a member's address or key; the resolver verifies it before serving and records each accepted one in the log.

**`GET /policy/routing`.** Signed policy bundles. They keep routing rules separate from roster membership. A bundle can delegate zones to carriers, institutions and sign-on issuers. Institution and issuer rules need a routing-claims envelope that is signed, short-lived and replay-protected. A public client can carry such a claim but cannot create one on its own.

### Interim abuse controls

`POST /resolve` answers `exists` for any raw E.164 with no account session: the enumeration oracle that ADM-001 L16 requires closing. Until the client verification phase changes the response, the endpoint carries these interim controls, all on by default and configured under `gua.resolver.abuse.*`:

- **Per-client rate limit.** A token bucket per client, keyed by the request's remote address as Tomcat's `RemoteIpValve` resolves it from the forwarded chain (`server.forward-headers-strategy=native`, pinned in `application.yml`; `abuse/ClientKey.java` documents the chain handling). IPv6 clients are keyed by /64. Default 20 requests per minute with a burst of 20.
- **Global ceiling.** A second bucket for the whole process, default 200 requests per second. Both buckets are per pod; under the opt-in autoscaling profile in gua-deploy (`k8s/autoscaling/resolver-hpa.yaml`, 2 to 3 replicas) the effective per-client rate is replicas x 20 per minute. The per-source limit shared across replicas is the Traefik `rateLimit` middleware on the resolver ingress (gua-deploy `k8s/services/login-ingress.sh`): 10 requests per second average, burst 30, per source address. The in-service buckets are the floor for a request that reaches a pod without passing the ingress.
- **The 429 contract.** Over either limit the service answers `429 Too Many Requests` with a `Retry-After` header in seconds and the constant body `{"code":"rate_limited","message":"..."}`. The request body is not read, so a refused request reveals nothing about the phone.
- **Decision trace.** `"trace": true` returns the matched rule, policy id and version, delegated zone and roster version only when `abuse.trace-enabled` is `true`. It is off by default because the trace exposes policy internals to anonymous callers; the dev testbed runbook depends on it, so the dev deployment has to set `GUA_RESOLVER_ABUSE_TRACE_ENABLED=true`.
- **Observability.** `gua_resolver_resolve_ratelimited_total{scope="client"|"global"}` counts refusals, `gua_resolver_resolve_clients_tracked` gauges the distinct clients held (bounded by `abuse.max-tracked-clients`), and the first refusal per client per window logs a WARN carrying a truncated hash of the client key, never the phone.

The `exists` flag stays in the response contract: the iOS and Android clients choose login versus create from it, and it changes only when the client verification phase changes the response, per ADM-001 L16. `abuse.enabled=false` switches the rate limits off (the rollback lever); the trace switch is independent of it.

## How this relates to the target architecture

The code on `main` is the current implementation; ADM-001 defines the target. Dated status per decision lives in the [decision index](docs/decisions/README.md#implementation-status). What differs in what this service serves today:

- **Resolution.** Today the resolver evaluates policy per request for a new account and reads the phone directory for an existing one. Nothing writes that directory over HTTP (the member write endpoint was removed, ADM-001 L1b); the existing rows stay, and are read, until placement records replace them. Target: an answer backed by a committed, signed placement record.
- **Roster.** Today an entry can carry the member's own signature over its endpoint, key and search fields ([ADM-007](docs/decisions/ADM-007-canonical-encoding-and-member-entries.md)), which the authority verifies and logs. Unsigned entries are still served because `roster.require-member-signature` is off, and clients do not check member signatures yet, so the protection holds against a resolver that rewrites its own database, not against one that serves an entry it never logged. Target: every entry is self-signed and clients refuse entries without one.
- **Governance.** Today the resolver loads a pinned federation genesis, publishes it at `GET /.well-known/gua-federation`, and accepts governance-signed membership epochs served at `GET /registry/homeservers/epoch/*`. Policy bundles are signed offline and verify under the governance keys once `governance.required` is on; it is off in both environments until the key ceremony runs, so membership still changes on the operational key. With one operator holding both keys this separates processes and custody, not principals (ADM-001 standing rule). Target: a second operator holds a governance key, and clients verify the chain before connecting.
- **Directory pepper.** Today `directory.pepper` is a secret shared with identity-service. Target: blinded routing keys replace it (migration plan phase 8); the construction is not chosen yet.

Mirror mode exists and is exercised in tests. How an independently operated resolver bootstraps and verifies its state is open (ADM-001 O12); nothing like that runs today. How the pieces fit together is in the [architecture guide](docs/architecture/gua-identity-and-federation.md).

## Configuration (`gua.resolver.*`)

- `mode`: `AUTHORITY` or `MIRROR`.
- `authority.threshold` (`k`), `authority.trusted-keys[]` (`n`), `authority.signing-key-id`, `authority.signing-private-key`.
- `policy.enabled`, `policy.file`, `policy.require-signatures`, `policy.signature-threshold`, `policy.trusted-keys[]`. Which keys a bundle verifies under follows `governance.required` and nothing else. With it off: `policy.trusted-keys`, or `authority.trusted-keys` when that list is unset, which is the pre-cutover fallback an existing deployment is serving on. With it on: the genesis governance key set alone, no fallback, so a bundle still signed by the operational key is refused and the file policy source will not start (ADM-001 L8).
- `claims.audience`, `claims.max-lifetime`, `claims.replay-protection-enabled`, `claims.trusted-keys[]`. Gated on `governance.required` like the policy trust root. With it on, an empty `claims.trusted-keys` rejects every routing-claims envelope and there is no fallback to the policy or authority keys (ADM-001 L8). With it off, the pre-cutover chain (claims, then policy, then authority) is preserved. Nothing issues envelopes today, so a future claims issuer ships its public key into this list before the cutover.
- `genesis.file`, `genesis.transitions-file`, `genesis.expected-id`, `genesis.expected-chain-head`: the pinned federation genesis (ADM-001 L10). The file is public and committed; `expected-id` is the pin, and a file that does not hash to it fails startup. `expected-chain-head` pins how far the governance key chain has run, so a truncated or removed transitions file fails startup too instead of quietly reinstating a key that was rotated out. Unset means governance is off.
- `governance.required`: the governance cutover. With it on, an admission lands `PENDING` and stays out of `/roster` until an epoch admits it, a suspend or revoke records intent only and appends a `STATUS_INTENT` log leaf, and only a governance-signed membership epoch changes a served status. The same flag also selects the routing-policy and routing-claims trust roots, so the whole cutover moves on one deliberate flip and setting it back to false rolls all of it back with no code rollout (`docs/runbooks/governance-keys.md`).
- `mirror.upstream-url`, `mirror.refresh-interval`, `mirror.cache-file`.
- `roster.require-member-signature`, `roster.member-max-lifetime`: the member self-signature transition. With the flag on, an ACTIVE entry carrying no valid member signature is excluded from `/roster`, from placement and from existing-account resolution, so every ACTIVE member is attested first (`docs/runbooks/member-attestation.md`); setting it back to false is the rollback. Env overrides take the form `GUA_RESOLVER_ROSTER_<KEY>`.
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

Today identity-service is the single login provider and credential store for every homeserver, and the resolver shares its directory pepper with it. Under the target each homeserver's own auth service owns authentication (migration plan phase 7); the resolver routes and never holds a credential either way. The [architecture guide](docs/architecture/gua-identity-and-federation.md#authentication) is the canonical description.

Stack: Java 21, Spring Boot 3.5.6.
