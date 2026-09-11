# Governance keys

How the federation genesis is created, where the governance private key lives, and how a membership epoch or
a policy bundle gets signed. Background: [ADM-001](../decisions/ADM-001-identifier-binding-placement-trust.md)
L10 (federation genesis) and L8 (thresholds count trust domains, never keys), and the Phase 2 objects section
of [ADM-007](../decisions/ADM-007-canonical-encoding-and-member-entries.md).

Run this once per environment, dev first. Dev and prod get separate keys and separate genesis objects, and a
dev key is never used in prod.

## What this buys, stated honestly

With one operator, the governance key and the resolver's operational key are held by the same party. Phase 2
separates **processes and custody**: governance signing happens on a machine outside the cluster, with a key
the resolver has never held, and the resolver refuses membership changes that carry no governance signature.
It does not separate **principals**. Every independence guarantee still reduces to compromising Gua, which is
the ADM-001 standing rule and does not change until a second operator holds a governance key.

So the genesis records `operatorId` on every key and the threshold counts operators rather than keys. At one
operator the count is 1 however many keys are listed. That is the honest number, and it is what a second key
holder later turns into a real guarantee. A threshold that counted keys would let one party holding two keys
claim a 2-of-2 that means nothing, which is the defect ADM-001 L8 names.

## Custody

- The governance private key is generated on an operator-controlled machine **outside the cluster** and never
  leaves it.
- It is **never** placed in a Kubernetes Secret in a resolver namespace, never in a ConfigMap, never in a
  repository, never in CI. The resolver has no configuration field that would hold one, deliberately.
- It is stored **encrypted at rest** on that machine, with an **offline backup** kept separately from it.
- Signing is a manual step with the tool below. There is no automated path, and adding one would put the key
  back next to the service it is meant to be independent of.
- Only the **public** half travels: it is written into the genesis file, which is public and committed.
- Loss or compromise is handled by creating a **new genesis** and re-pinning it in client builds. There is no
  in-band recovery and none is claimed; catastrophic key loss stays ADM-001 O13.

A second key holder is not required for Phase 2, and this document does not pretend one exists.

## 1. Generate the governance key

On the custody machine:

```sh
umask 077
./gradlew -q --console=plain govTool \
  --args='keygen --operator gua --key-id gua-governance-1 --private-key-out governance.key'
```

It prints the public key entry on standard output and writes the private half to `governance.key`, owner
only. Nothing prints the private key. Back it up offline and encrypted now, before it is the only copy.

`--operator` is the trust domain that holds the key. Use one stable value per operator, not per key: two keys
held by the same party must carry the **same** `operatorId`, or the threshold count becomes a lie.

## 2. Create and sign the genesis

The fields file is public information:

```json
{
  "federationLabel": "gua-dev",
  "threshold": 1,
  "keys": [
    { "keyId": "gua-governance-1", "publicKey": "<base64 X.509 public half>", "operatorId": "gua" }
  ]
}
```

```sh
./gradlew -q --console=plain govTool --args='genesis create --fields fields.json' > genesis.unsigned.json

< governance.key ./gradlew -q --console=plain govTool \
  --args='genesis sign --genesis genesis.unsigned.json --key-id gua-governance-1 --private-key-file -' \
  > genesis.json
```

The tool prints the `genesisId` and its fingerprint on standard error. Record both.

A v1 genesis is signed by the keys it enumerates, which ADM-001 L10 locks and explains: verifying it against
itself proves only that its own keys signed it. That is why the next step is not optional.

## 3. Publish the fingerprint through independent channels

The genesis file is public and committed to gua-deploy; the **pin** is what makes it a trust root.

- Record `genesisId` as the resolver's `GUA_RESOLVER_GENESIS_EXPECTED_ID`. A file that does not hash to the
  pinned id fails startup, so whoever controls the mount cannot swap in another validly signed genesis.
- Publish the fingerprint on the public landing page and in the gua-deploy README, so the value can be
  compared across channels that are not the resolver serving it.
- Clients pin the genesis JSON and its id per environment at build time.

Comparing the fingerprint served at `/.well-known/gua-federation` against a channel the resolver does not
control is the whole point. A genesis nobody compared out of band is a document, not a root.

## 4. Deploy order

Do not reorder these. Steps 3 and 4 below are the ones that take an environment down if inverted.

1. Deploy the resolver with the genesis file mounted, `GUA_RESOLVER_GENESIS_EXPECTED_ID` set, and
   `GUA_RESOLVER_GOVERNANCE_REQUIRED=false`. Verify `/.well-known/gua-federation` serves the expected id and
   fingerprint. Nothing has changed for clients yet.
2. Sign membership epoch 1 (section 5) and submit it. Verify `/registry/homeservers/epoch/current` and the
   `MEMBERSHIP_EPOCH` leaf in `/roster/log`.
3. **Re-sign any live routing policy bundle with the governance key** (section 6) and update the policy
   ConfigMap, *before* the fail-closed policy verifier reaches that environment. A bundle still signed by the
   operational key will not verify, the file policy source refuses to start with no loadable bundle, and the
   resolver will not come up. An environment with policy disabled skips this step.
4. Set `GUA_RESOLVER_GOVERNANCE_REQUIRED=true` and restart. Verify that a direct admission now lands
   `PENDING`, that a suspend records intent without changing what is served, and that only an epoch moves a
   status.
5. Soak, then do the same in the next environment.

**Rollback** at any point is `GUA_RESOLVER_GOVERNANCE_REQUIRED=false` and a restart: the direct admission path
returns, no code rollout and no schema change. The published genesis and any client pin stay and are
harmless, because nothing enforces them on the client side yet. Reverting the fail-closed policy commit
restores in-process signing.

## 5. Sign a membership epoch

The resolver builds the membership; the operator signs it. An epoch **ratifies**, it does not originate: the
resolver rebuilds the pending membership at submission and refuses an epoch whose content hash is anything
else. So a change is proposed through the admin API first (an admission, or a status change that records
intent), and then signed.

```sh
curl --fail-with-body -s -u "$ADMIN_USER" \
  "$RESOLVER/authority/registry/homeservers/pending" > pending.json

< governance.key ./gradlew -q --console=plain govTool \
  --args='epoch sign --pending pending.json --key-id gua-governance-1 --private-key-file -' > epoch.json

curl --fail-with-body -u "$ADMIN_USER" -X POST "$RESOLVER/authority/registry/homeservers/epoch" \
  -H 'content-type: application/json' --data-binary @epoch.json
```

`curl` prompts for the admin password; do not put it on the command line. Read `pending.json` before signing
it: it is the membership you are about to make true, and the tool recomputes its content hash rather than
trusting the one the resolver served.

Each member entry carries `memberEntryHash`, the hash of that homeserver's own self-signed entry. Governance
signs that hash, not the member's fields, so it can admit, suspend or revoke a member and cannot rewrite one.
A member that has not attested yet has no hash; attest it first (`docs/runbooks/member-attestation.md`) if you
want the epoch to bind its identity.

## 6. Sign a routing policy bundle

Policy signing left the resolver process in Phase 2. Validate first, against the live roster:

```sh
curl --fail-with-body -u "$ADMIN_USER" -X POST "$RESOLVER/authority/policy/validate" \
  -H 'content-type: application/json' --data-binary @bundle.json
```

The response reports whether the structure is valid, whether the signatures verify under the governance keys
this resolver trusts, and which zones will actually route. Then sign:

```sh
< governance.key ./gradlew -q --console=plain govTool \
  --args='policy sign --policy bundle.json --key-id gua-governance-1 --private-key-file -' > signed.json
```

Ship `signed.json` as the policy ConfigMap. Re-run validate afterwards and confirm `signaturesVerified` is
true before the resolver restarts, because the file policy source refuses to start with no loadable bundle.

## 7. Rotate a governance key

A transition installs a new key set and must satisfy the **outgoing** set's threshold and the **incoming**
set's. The outgoing signatures authorise the change; the incoming ones prove the new keys are actually held,
so governance cannot be handed to a key nobody can use.

Build the transition naming `genesisId`, the next `index`, `previousHash` (the genesis id at index 1, the
previous transition's hash after that), `newThreshold` and `newKeys`. Then run `transition sign` once per key
holder, with each holder's own key, and merge the signature lists into one object. Add the file to
`GUA_RESOLVER_GENESIS_TRANSITIONS_FILE` as a JSON array in chain order and restart; the resolver verifies the
whole chain at startup and refuses to start on a broken one.

The genesis itself never changes. Losing every key in the current set is not recoverable by transition, and
the answer is a new genesis and a client re-pin.

## When something is refused

- `refusing to start on an unpinned genesis`: the file does not hash to `GUA_RESOLVER_GENESIS_EXPECTED_ID`.
  Either the file changed or the pin is stale. Do not adjust the pin to match the file without finding out
  which.
- `carries valid signatures from 0 operator(s), need 1`: the object was signed by a key the genesis does not
  enumerate, or the bytes changed after signing.
- `the signed membership is not the membership this resolver built`: state moved between fetching the pending
  content and submitting. Fetch it again and re-sign.
- `does not continue the chain`: the epoch number or the previous hash is stale. Fetch the pending content
  again.
- `governance threshold N exceeds the M distinct operator(s)`: the threshold can never be met. Either add a
  key held by a genuinely different operator, or lower the threshold to the truth.
- `gua.resolver.governance.required is on but no gua.resolver.genesis.file is configured`: the flag promises
  governance the resolver cannot perform. Mount the genesis first.
