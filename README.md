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

## Status

The trust + persistence layers are **implemented**, not stubbed:

- `placement/` — `PlacementRule` SPI + `PlacementEngine` + built-in `ClaimRule` (declarative carrier/
  affiliation/prefix claims) and `WeightedFallbackRule`. Extensible: a new strategy is a new bean.
- `crypto/` — JDK-native **Ed25519** (sign/verify) and an **RFC 6962 Merkle tree** (root + consistency
  proofs) — the tamper-evidence primitive, no PoW/blockchain.
- `roster/` — **authority-signed roster** with **k-of-n threshold** Ed25519 signatures
  (`RosterSigner`/`RosterVerifier`) over deterministic `CanonicalRoster` bytes, anchored to a persistent
  **Merkle transparency log** (`JdbcTransparencyLog`). Two modes: `AuthorityRosterStore` (owns + signs) and
  `MirrorRosterStore` (pulls upstream, **verifies threshold sigs + log consistency** before serving).
- `admission/` — the authority's **admission control**: key-possession proof, pluggable
  `DomainOwnershipVerifier`, and **claim non-overlap** validation; every admit/suspend/revoke is appended
  to the transparency log and the roster is re-signed.
- `directory/` — the **persistent, shared phone→homeserver directory** addressed only by **peppered
  HMAC** (`PhoneHasher`); writes are authenticated by the hosting homeserver's **membership credential**
  (its roster signing key — it can only write its own accounts); reads are rate-limited and a mirror
  **queries** it (`RemoteDirectoryStore`) rather than replicating the phone graph.
- `service/` + `api/` — `/resolve`, `/roster`, `/roster/log(/consistency)`, `/directory/entries|lookup`,
  `/authority/admission`, `/authority/roster/{id}/status`.

Persistence is Postgres (Flyway migration in `db/migration/`); tests run on in-memory H2. Phase 1 seeds the
single configured dev homeserver on a fresh DB (logged + signed from entry #1).

### Modes & key config (`gua.resolver.*`)
- `mode: AUTHORITY | MIRROR`
- `authority.threshold` (k), `authority.trusted-keys[]` (n), `authority.signing-{key-id,private-key}`
- `directory.pepper` — **must match identity-service**
- `mirror.upstream-url`, `mirror.refresh-interval`

### Still external to this repo
- `identity-service` calls `placementFor(...)` at provisioning and `POST /directory/entries` (its phone
  OTP IdP already shares the pepper).
- iOS + web pre-auth `POST /resolve` step — already wired in those clients.

## Run (dev)

```sh
./gradlew bootRun        # :8095
curl -s localhost:8095/roster | jq
curl -s -XPOST localhost:8095/resolve -H 'content-type: application/json' \
  -d '{"phone":"+5511987654321"}' | jq    # -> register at the dev homeserver
```

Stack: Java 21 · Spring Boot 3.5.6 (matches identity-service). Package root `global.gua.resolver`.
