# gua-resolver

The **federation routing front door** for Gua — the service clients hit *before* login to discover which
homeserver they belong to, and the service that tracks/trusts the set of federated homeservers.

It is deliberately separate from `identity-service` (the credential-holding IdP): the resolver is the
public, read-mostly, horizontally-scalable, **anyone-can-mirror** entry point to the federated network.

> **Full design:** [`docs/FEDERATION_ROUTING_DESIGN.md`](docs/FEDERATION_ROUTING_DESIGN.md) — resolution,
> the signed/transparency-logged roster, the trust model (verifiability without a PoW blockchain), and the
> pluggable placement rule engine.

## Three responsibilities

1. **Resolution** — `POST /resolve` : verified phone → which homeserver to log in to, or where to register.
   This replaces the clients' hardcoded `GuaDefaultAccountProvider`.
2. **Roster** — `GET /roster` : the signed, transparency-logged set of federated homeservers (mirrorable).
3. **Placement engine** — a pluggable, priority-ordered rule pipeline that decides where a *new* account
   lives. Operator-specific placement (a carrier claiming its numbers, a university claiming its affiliates)
   is **declarative data in the signed roster**, not code — adding one is a roster edit, no redeploy.

## Status — Phase 1 (scaffold)

Wired and coherent; the trust/persistence layers are stubbed for the single-homeserver dev cutover:

- `placement/` — `PlacementRule` SPI + `PlacementEngine` + built-in `ClaimRule` (declarative carrier/
  affiliation/prefix claims) and `WeightedFallbackRule`. **Real and extensible now.**
- `roster/` — `SignedRoster` / `RosterEntry` / `RosterStore` / `TransparencyLog` contracts; dev
  `InMemoryRosterStore` returns the single dev homeserver (unsigned). The authority-signed,
  threshold + Merkle-log store is the next pass.
- `service/` + `api/` — `/resolve` + `/roster` over a stub directory (everyone routes to the dev
  homeserver until the shared peppered-HMAC directory is wired).

### Next passes
- Authority-signed roster: Ed25519 threshold (k-of-n) signatures + Merkle transparency log + admission flow.
- Persistent, shared phone→homeserver directory (peppered HMAC, rate-limited, no bulk export) + Redis cache.
- `identity-service` calls `placementFor(...)` at provisioning and writes directory entries.
- iOS + web clients: pre-auth `POST /resolve` step replacing `GuaDefaultAccountProvider`.

## Run (dev)

```sh
./gradlew bootRun        # :8090
curl -s localhost:8090/roster | jq
curl -s -XPOST localhost:8090/resolve -H 'content-type: application/json' \
  -d '{"phone":"+5511987654321"}' | jq    # -> register at the dev homeserver
```

Stack: Java 21 · Spring Boot 3.5.6 (matches identity-service). Package root `global.gua.resolver`.
