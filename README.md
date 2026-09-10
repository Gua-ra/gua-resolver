![gua-resolver](https://github.com/user-attachments/assets/01bd66c7-6250-42ce-a4d0-1f8ade952ca2)

The federation **routing front door** for Gua: the service a client asks *before* login to find which homeserver an identifier leads to, and the service that serves the signed set of federated homeservers.

The resolver **serves and verifies routing information. It does not authenticate anyone.** It is public, read-mostly, and anyone can mirror it. Running a resolver grants no authority over the federation.

> **Which document do you want?**
> - What the resolver is and how routing, placement and binding fit together: [architecture guide](docs/architecture/gua-identity-and-federation.md).
> - The normative decisions: [ADM-001](docs/decisions/ADM-001-identifier-binding-placement-trust.md). Frozen.
> - How a client verifies what this service serves today: [verification protocol](docs/verification/gua-resolver-verification-protocol.md).
> - How the current implementation gets to the target: [migration plan](docs/migrations/gua-resolver-migration-plan.md).
>
> This README is the operational one. It describes **what the code on `main` does**. Where that differs from the target, the target is marked.

## What it does today

1. **Resolution.** `POST /resolve`: a phone number in, a homeserver to log in to or register at out. Today this is a per-request policy evaluation over the roster. *Target: an answer backed by a committed, signed placement record; see ADM-001 L6.*
2. **Roster.** `GET /roster`: the signed, transparency-logged set of federated homeservers, with `k`-of-`n` authority signatures and a Merkle log checkpoint. Mirrorable. *Target: each entry additionally self-signed by the member it describes; see ADM-001 L10.*
3. **Routing policy.** `GET /policy/routing`: signed policy bundles that split routing rules from roster membership, with delegated zones for carriers, institutions and sign-on issuers. Institution and issuer rules require a signed, short-lived, replay-protected routing-claims envelope; a public client can carry a claim but cannot self-assert one.

Persistence is Postgres (Flyway migrations in `db/migration/`); tests run on H2.

## Modes and key configuration (`gua.resolver.*`)

- `mode: AUTHORITY | MIRROR`
- `authority.threshold` (`k`), `authority.trusted-keys[]` (`n`), `authority.signing-{key-id,private-key}`
- `policy.enabled`, `policy.file`, `policy.require-signatures`, `policy.signature-threshold`
- `claims.audience`, `claims.max-lifetime`, `claims.replay-protection-enabled`, `claims.trusted-keys[]`
- `mirror.upstream-url`, `mirror.refresh-interval`, `mirror.cache-file`
- `directory.pepper`: must match identity-service. *Scheduled for replacement; see ADM-001 L15 and the migration plan.*

**Operational honesty:** both deployed environments run a single node in `AUTHORITY` mode with `k = 1`, `n = 1`, and one operator holds every key. The `k`-of-`n` and mirror machinery works and is exercised in tests; it is not yet a multi-operator deployment.

## Run (dev)

```sh
./gradlew bootRun        # :8095
curl -s localhost:8095/roster | jq
curl -s -XPOST localhost:8095/resolve -H 'content-type: application/json' \
  -d '{"phone":"+5511987654321"}' | jq
curl -s -XPOST localhost:8095/resolve -H 'content-type: application/json' \
  -d '{"phone":"+5511987654321","trace":true}' | jq
curl -s localhost:8095/policy/routing/status | jq
```

## Relationship to identity-service

Today identity-service is the single login provider and credential store for every homeserver, and the resolver's directory pepper is shared with it. That is the **current implementation**, not the target. Under ADM-001 each homeserver's own auth service owns authentication, and identity-service's remaining role is decided in a follow-up record. The resolver's role does not change: it routes, and it never holds a credential.

Stack: Java 21 · Spring Boot 3.5.6
