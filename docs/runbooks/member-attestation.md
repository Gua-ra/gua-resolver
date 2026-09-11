# Member attestation

How a homeserver operator signs its own roster entry, and how the resolver is switched over to requiring
that signature. Background: [ADM-007](../decisions/ADM-007-canonical-encoding-and-member-entries.md); the
verification rules a client would apply are section 1a of the
[verification protocol](../verification/gua-resolver-verification-protocol.md).

Run this once per environment, dev first.

## Deploy order

Do not invert steps 2 and 4.

1. Ship the code with `gua.resolver.roster.require-member-signature` off. This is the default, and nothing
   changes for clients: unattested entries are served exactly as before.
2. Attest every ACTIVE member (steps 1 to 3 below).
3. Verify (step 4 below): every ACTIVE entry reports `ok`, the log carries a `MEMBER_ATTEST` leaf per entry,
   and `gua_resolver_roster_homeservers{status="unattested"}` is 0.
4. Set the flag to true, restart, soak.
5. Rollback at any point: set the flag back to false and restart. No code rollout, no schema change; the V4
   columns are additive and nullable and stay where they are.

With the flag on, an ACTIVE entry that carries no valid member signature leaves `/roster`, placement and
existing-account resolution. For a production homeserver that means its returning users cannot log in, which
is why the flag is flipped only after the gauge reads 0.

One more check before flipping: if a live routing policy bundle names a homeserver that would be excluded,
the policy source refuses to load and the resolver will not start. Attest every homeserver named in the live
bundle, or update the bundle first.

## What you need

- The member's Ed25519 private key (base64 PKCS#8), held by that homeserver's operator in its own namespace.
  The concrete secret names per environment are in gua-deploy, not here.
- Admin credentials for `/authority/**` on the resolver.
- The resolver base URL for the environment. `$RESOLVER` and `$ID` (the federation id) below.

The resolver never holds a member private key, and no step here writes one to a repository, a log or the
shell history.

## 1. Describe the entry

The fields file is public information: it is what the member is about to sign.

```json
{
  "id": "example",
  "serverName": "example.gua.test",
  "baseUrl": "https://matrix.example.gua.test",
  "masIssuer": "https://account.example.gua.test/",
  "signingKey": "<base64 X.509 public half of the key you will sign with>",
  "region": "BR",
  "searchVisibility": "GLOBAL",
  "searchGroups": [],
  "keyId": "example-1",
  "sequence": 1,
  "notBefore": "2026-09-11T00:00:00Z",
  "lifetimeDays": 400
}
```

- `serverName` must equal the stored one. A different server name is a new identity, which is a fresh
  admission, not an attestation.
- `sequence` starts at 1 and must be greater than the accepted one on every later attestation.
- `region` absent and `region` empty are different signed bytes. Send what the entry should carry.
- The validity window may not exceed 400 days. Re-attest before it expires: an expired attestation counts as
  unattested, and with the flag on the entry drops out.
- `weight`, `acceptsNew`, `claims` and `status` are not in the file. The authority keeps them.

## 2. Sign it

The key is piped in; the tool has no flag that takes a key as a value, because an argument would land in the
shell history and the process list.

```sh
umask 077
<read the key from your secret store> | ./gradlew -q --console=plain memberEntryTool \
  --args='sign --fields fields.json --private-key-file -' > attest.json
```

From the service image instead of a checkout:

```sh
<read the key from your secret store> | java -cp /app/app.jar \
  -Dloader.main=global.gua.resolver.tools.MemberEntryTool \
  org.springframework.boot.loader.launch.PropertiesLauncher \
  sign --fields fields.json --private-key-file -
```

Start the command line with a space (or run it with history disabled) so the pipeline is not recorded. The
tool prints the request body on standard output and the entry hash on standard error; neither contains key
material, so `attest.json` can be read and reviewed before it is sent. If you do have to stage a key in a
file, put it on a memory-backed filesystem with `umask 077` and delete it afterwards; the tool warns when a
key file is readable beyond its owner.

## 3. Send it

```sh
curl --fail-with-body -u "$ADMIN_USER" -X POST "$RESOLVER/authority/roster/$ID/member" \
  -H 'content-type: application/json' --data-binary @attest.json
```

`curl` prompts for the admin password; do not put it on the command line. The response is the freshly signed
roster.

## 4. Verify

```sh
curl -s "$RESOLVER/roster" > roster.json
./gradlew -q --console=plain memberEntryTool --args='verify --roster roster.json'
```

Every ACTIVE entry must report `ok`. Then check the three other surfaces:

- **Tamper check.** Edit `baseUrl` in a copy of `roster.json` and run `verify` against the copy. It must
  report `invalid` and exit non-zero. That is the property being bought: an authority that rewrites a
  member's address cannot produce a signature for it.
- **Log.** `curl -s "$RESOLVER/roster/log"` carries a `MEMBER_ATTEST` event per attestation whose
  `payloadHash` equals the entry hash the tool printed.
- **Metric.** `gua_resolver_roster_homeservers{status="unattested"}` is 0. The resolver also names unattested
  ACTIVE entries in a WARN at startup while the flag is off.

## 5. Flip the flag

Set `GUA_RESOLVER_ROSTER_REQUIRE_MEMBER_SIGNATURE=true` in the environment's resolver configuration (in
gua-deploy) and restart. Then confirm: login and registration still resolve, the unattested gauge stays 0,
and no `Excluding ACTIVE homeserver` ERROR lines appear. Soak before doing the same in the next environment.

## Key rotation

Generate the new key on the operator machine, never in the resolver's namespace:

```sh
openssl genpkey -algorithm ed25519 -outform DER | base64   # private, PKCS#8
openssl pkey -in <the same key> -pubout -outform DER | base64   # public, X.509
```

In the fields file set `signingKey` to the new public key, `keyId` to a new label, `sequence` to the next
number, and `previousKeyId` to the old label. Add `previousSigningKey` (the old public key) if you want the
tool to check the chain locally as well. Then sign with both keys, the new one first:

```sh
<read both keys, new first, one per line> | ./gradlew -q --console=plain memberEntryTool \
  --args='rotate --fields fields.json --private-key-file - --previous-private-key-file -' > attest.json
```

Post it the same way. The entry that comes back names the new key, and the log records the rotation.

**If the old key is lost there is no self-signed path.** The entry is revoked and the operator is admitted
afresh, which is a new identity to clients. The unique index on `server_name` means the same server name
cannot simply be re-admitted while the old entry exists.

## When it is refused

The response body carries the reason.

- `signature by keyId ... does not verify`: the fields sent are not the fields signed. A stale fields file, a
  substituted value, or the wrong key.
- `sequence must be greater than the accepted N`: fetch `/roster`, read the current sequence, raise it.
- `key rotation is not signed by the previous key`: use `rotate`, with the previous key available.
- `a rotated key needs a new keyId`: one key id names one key.
- `has no registered key to anchor an attestation`: the entry was seeded with an empty signing key, so there
  is nothing to prove possession against. It has to be revoked and the operator admitted afresh.
- `is revoked: a revoked member is admitted afresh, never re-attested`.
- `validity window exceeds the maximum lifetime of 400 days`.
- `a member self-signature is required`: the flag is already on and a legacy admission was attempted.
- `malformed_request`: the body did not parse strictly (an unknown field, a duplicate key, invalid UTF-8).
  The signed sub-object is parsed strictly on purpose, so nothing rides along outside the signature.
