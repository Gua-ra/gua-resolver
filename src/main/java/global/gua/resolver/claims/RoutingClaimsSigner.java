package global.gua.resolver.claims;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import global.gua.resolver.crypto.Ed25519;

/** Small signing helper used by tests and offline bootstrap tooling. */
public final class RoutingClaimsSigner {

    private RoutingClaimsSigner() {}

    public static RoutingClaimsEnvelope sign(RoutingClaimsEnvelope unsigned, String keyId,
                                             String privateKeyB64) {
        PrivateKey privateKey = Ed25519.privateKey(privateKeyB64);
        var signature = new RoutingClaimsEnvelope.ClaimSignature(
                keyId, Ed25519.sign(privateKey, CanonicalRoutingClaims.bytes(unsigned)));
        List<RoutingClaimsEnvelope.ClaimSignature> signatures =
                new ArrayList<>(unsigned.signatures() == null ? List.of() : unsigned.signatures());
        signatures.removeIf(s -> s.keyId().equals(keyId));
        signatures.add(signature);
        return new RoutingClaimsEnvelope(unsigned.schemaVersion(), unsigned.issuer(), unsigned.audience(),
                unsigned.issuedAt(), unsigned.expiresAt(), unsigned.nonce(), unsigned.subject(),
                unsigned.affiliations(), unsigned.attributes(), signatures);
    }
}
