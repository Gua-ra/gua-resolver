# gua-resolver

<img width="1923" height="818" alt="524d9af7-6175-4a78-b62a-a168459ae6a1" src="https://github.com/user-attachments/assets/01bd66c7-6250-42ce-a4d0-1f8ade952ca2" />


The **federation routing front door** for Gua — the service clients hit *before* login to discover which
homeserver they belong to, and the service that tracks/trusts the set of federated homeservers.

It is deliberately separate from `identity-service` (the credential-holding IdP): the resolver is the
public, read-mostly, horizontally-scalable, **anyone-can-mirror** entry point to the federated network.

## Three responsibilities

1. **Resolution** — `POST /resolve` : verified phone → which homeserver to log in to, or where to register.
2. **Roster** — `GET /roster` : the signed, transparency-logged set of federated homeservers (mirrorable).
3. **Placement engine** — a pluggable, priority-ordered rule pipeline that decides where a *new* account
   lives. Operator-specific placement (a carrier claiming its numbers, a university claiming its affiliates)
   is **declarative data in the signed roster**, not code — adding one is a roster edit, no redeploy.


Persistence is Postgres (Flyway migration in `db/migration/`); tests run on in-memory H2.

### Modes & key config (`gua.resolver.*`)
- `mode: AUTHORITY | MIRROR`
- `authority.threshold` (k), `authority.trusted-keys[]` (n), `authority.signing-{key-id,private-key}`
- `directory.pepper` — **must match identity-service**
- `mirror.upstream-url`, `mirror.refresh-interval`

## Run (dev)

```sh
./gradlew bootRun        # :8095
curl -s localhost:8095/roster | jq
curl -s -XPOST localhost:8095/resolve -H 'content-type: application/json' \
  -d '{"phone":"+5511987654321"}' | jq    # -> register at the dev homeserver
```

Stack: Java 21 · Spring Boot 3.5.6
