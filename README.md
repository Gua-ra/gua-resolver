![gua-resolver](https://github.com/user-attachments/assets/01bd66c7-6250-42ce-a4d0-1f8ade952ca2)

gua-resolver is the routing front door of the Gua federation. Before login, a client asks it which homeserver an identifier leads to. It also serves the signed list of federated homeservers.

The resolver serves and verifies routing information. It does not authenticate anyone and it never holds a credential. It is public and read-mostly. Running a resolver grants no authority over the federation.

> **Which document do you want?**
> - How routing, placement and binding fit together: [architecture guide](docs/architecture/gua-identity-and-federation.md).
> - The frozen decisions behind the target design: [ADM-001](docs/decisions/ADM-001-identifier-binding-placement-trust.md).
> - How a client verifies what this service serves today: [verification protocol](docs/verification/gua-resolver-verification-protocol.md).
> - How the current code gets to the target: [migration plan](docs/migrations/gua-resolver-migration-plan.md).
> - How an operator signs a homeserver's own roster entry: [member attestation runbook](docs/runbooks/member-attestation.md).
>
> This README is the operational document. It describes what the code on `main` does. Where the target differs, the target is marked.

## What it does today

Clients use three endpoints; mirrors and verifiers also read `/roster/log`, `/roster/log/consistency`, `/policy/log`, `/policy/routing/status`, `/directory/lookup` and `/directory/checkpoint`.

**`POST /resolve`.** A phone number goes in. A homeserver to sign in or register at comes out. The resolver reads the phone directory and evaluates the routing policy against the roster on every request; a directory row decides the answer when there is one.

**`GET /roster`.** The signed list of federated homeservers, recorded in a transparency log. Each roster carries `k`-of-`n` authority signatures and a Merkle log checkpoint. Mirrors can serve it. An entry can also carry the member's own signature over the fields that homeserver controls, so the authority alone can no longer rewrite a member's address or key; the resolver verifies it before serving and records each accepted one in the log.

**`GET /policy/routing`.** Signed policy bundles. They keep routing rules separate from roster membership. A bundle can delegate zones to carriers, institutions and sign-on issuers. Institution and issuer rules need a routing-claims envelope that is signed, short-lived and replay-protected. A public client can carry such a claim but cannot create one on its own.

### Interim abuse controls

`POST /resolve` takes any raw E.164 with no account session. A number with a directory row and one without get the same response shape: `exists` is always `false`, `homeserver` is always `null`, and `registerAt` names the account's homeserver for a directory row or the placement decision otherwise. The directory lookup and placement both use the trimmed, validated number. Both cases run placement, and a directory row is resolved against the roster snapshot the request already loaded, so the work per request matches. A directory row whose homeserver is not `ACTIVE` in the roster (suspended, revoked or removed) answers `503` with `{"code":"homeserver_unavailable"}`, counted as `gua_resolver_resolve_total{outcome="homeserver_unavailable"}`, and never falls through to placement. The iOS and Android apps stop on that error. The web client currently falls back to its default server on any resolver error, so a web sign-in for such an account can still start at the wrong homeserver.

The answer can still tell a number with an account from one without:

- A directory row whose homeserver differs from the placement anyone can reproduce from the public roster and policy.
- Any directory row, while caller-supplied fields (`country`, `mccmnc`, `carrier`, `regionHint`) can move the placement for that number. A roster carrier or geo claim does that, and so does a weighted fallback over two or more homeservers that accept new accounts. Varying the fields moves a miss and never a hit.
- The `503 homeserver_unavailable` for an account on a homeserver that is not `ACTIVE`.
- While no homeserver accepts new accounts, a miss answers `503 no_placement_available` and a hit answers `200`. Pausing signups by clearing `acceptsNew` across the roster therefore exposes every directory row.
- `trace.source` wherever the decision trace is enabled, which includes dev.

The endpoint therefore keeps these interim controls, all on by default and configured under `gua.resolver.abuse.*`:

- **Per-client rate limit.** A token bucket per client, keyed by the request's remote address as Tomcat reports it once `RemoteIpValve` has resolved the forwarded chain (`server.forward-headers-strategy=native`, pinned in `application.yml`). The pod receives `X-Forwarded-For` as caller-supplied entries, then the client address the public edge appended, then the internal hop the in-cluster ingress appended; the valve skips the internal hops, takes the client address, and leaves only the caller-supplied leftovers in the header, which the limiter never reads. IPv6 clients are keyed by /64. Default 20 requests per minute with a burst of 20.
- **Global ceiling.** A second bucket for the whole process, default 200 requests per second. Both buckets are per pod: the deployed resolver runs a single pod, and under the opt-in autoscaling profile in gua-deploy (`k8s/autoscaling/resolver-hpa.yaml`, 2 to 3 replicas) the effective in-service per-client rate becomes replicas x 20 per minute. The per-source limit shared across replicas is the Traefik `rateLimit` middleware on the resolver ingress, defined in gua-deploy (`k8s/services/login-ingress.sh`, applied by its deploy script): 10 requests per second average with a burst of 30, per source address. The in-service buckets are the floor that holds for a request that reaches a pod without passing the ingress.
- **The 429 contract.** Over either limit the service answers `429 Too Many Requests` with a `Retry-After` header in seconds and the constant body `{"code":"rate_limited","message":"..."}`. The request body is not read, so a refused request reveals nothing about the phone.
- **Decision trace.** `"trace": true` returns the matched rule, policy id and version, delegated zone and roster version only when `abuse.trace-enabled` is `true`. It is off by default because the trace exposes policy internals and the answer's source to anonymous callers. The dev testbed runbook depends on it, so the dev deployment has to set `GUA_RESOLVER_ABUSE_TRACE_ENABLED=true`.
- **Observability.** `gua_resolver_resolve_ratelimited_total{scope="client"|"global"}` counts refusals, `gua_resolver_resolve_clients_tracked` gauges the distinct clients held (bounded by `abuse.max-tracked-clients`), and the first refusal per client per window logs a WARN carrying a truncated hash of the client key, never the phone.

`exists` and `homeserver` stay in the response because deployed clients decode them. With `exists` false the clients take the homeserver from `registerAt` and run the phone sign-in, where the identity provider finds an existing account by its number. Both apps also read `exists` as the signup signal for account genesis, so with their account-genesis flag on every returning sign-in would register a new genesis. That flag stays off until the apps decide signup after phone verification (see ADM-008, "Implementation status and direction"). `abuse.enabled=false` switches the rate limits off (the rollback lever); the trace switch is independent of it.

## How this relates to the target architecture

The code on `main` is the current implementation. The decision record defines the target. Three things differ in what this service serves today:

- **Resolution.** Today: for a new account the resolver evaluates policy on every request; for an existing account it reads the phone directory. Nothing writes that directory over HTTP any more (the member write endpoint was removed under ADM-001 L1b); the rows already there stay, and are still read, until placement records replace them. Target: the answer is backed by a committed, signed placement record.
- **Roster.** Today: the roster carries authority signatures and a log checkpoint, and an entry can also carry the member's own signature over its endpoint, key and search fields ([ADM-007](docs/decisions/ADM-007-canonical-encoding-and-member-entries.md)), which the authority verifies and commits to the log. Entries with no member signature are still served, because `roster.require-member-signature` is off, and clients do not check member signatures yet, so the protection currently holds against a resolver that rewrites its own database rather than against one that serves a client an entry it never logged. Target: every entry is self-signed and clients refuse entries without one.
- **Governance.** Today: the resolver can load a pinned federation genesis, publish it at `GET /.well-known/gua-federation`, and accept governance-signed membership epochs that it serves at `GET /registry/homeservers/epoch/*` and commits to the log. Policy bundles are signed offline, not by this process, and verify under those governance keys once `governance.required` is on; until then they verify under the operational key set the environment already runs on. `governance.required` is off in both environments until the key ceremony has run, so membership still changes on the operational key today. And with one operator holding both keys, what this separates is processes and custody, not principals: every independence guarantee still reduces to compromising Gua. Target: a second operator holds a governance key, and clients verify the chain before connecting.
- **Directory pepper.** Today: `directory.pepper` is a secret shared with identity-service. Target: blinded routing keys replace it. The migration plan has a phase for this. The construction is not chosen yet.

Mirror mode exists and is exercised in tests. How an independently operated resolver bootstraps and verifies its state is still an open decision. Nothing like that runs today.

How the pieces fit together is in the [architecture guide](docs/architecture/gua-identity-and-federation.md). The reasoning behind each target, and the open decisions, are in [ADM-001](docs/decisions/ADM-001-identifier-binding-placement-trust.md).

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

Today identity-service is the single login provider and credential store for every homeserver. The resolver shares its directory pepper with identity-service. That is the current implementation, not the target.

Under the target, each homeserver's own auth service owns authentication. What remains of identity-service's role is decided in a follow-up record. The resolver's role does not change either way: it routes, and it never holds a credential.

Stack: Java 21, Spring Boot 3.5.6.
