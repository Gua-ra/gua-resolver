package global.gua.resolver.claims;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CanonicalRoutingClaimsTest {

    private static RoutingClaimsEnvelope env(List<String> affiliations, Map<String, String> attributes) {
        return new RoutingClaimsEnvelope(RoutingClaimsEnvelope.SCHEMA_VERSION, "iss", "aud",
                Instant.ofEpochMilli(1000), Instant.ofEpochMilli(2000), "nonce", "+5511987654321",
                affiliations, attributes, List.of());
    }

    @Test
    void encodingIsInjectiveAcrossAmbiguousAttributeSplits() {
        // {"a":"b|c=d"} and {"a":"b","c":"d"} previously canonicalized to the identical string "a=b|c=d",
        // letting one signature cover a different claim set. They must now produce different signed bytes.
        byte[] one = CanonicalRoutingClaims.bytes(env(List.of(), Map.of("a", "b|c=d")));
        byte[] two = CanonicalRoutingClaims.bytes(env(List.of(), Map.of("a", "b", "c", "d")));
        assertThat(one).isNotEqualTo(two);
    }

    @Test
    void encodingIsInjectiveAcrossAmbiguousAffiliationSplits() {
        byte[] one = CanonicalRoutingClaims.bytes(env(List.of("x|y"), Map.of()));
        byte[] two = CanonicalRoutingClaims.bytes(env(List.of("x", "y"), Map.of()));
        assertThat(one).isNotEqualTo(two);
    }

    @Test
    void identicalEnvelopesProduceIdenticalBytes() {
        assertThat(CanonicalRoutingClaims.bytes(env(List.of("x"), Map.of("k", "v"))))
                .isEqualTo(CanonicalRoutingClaims.bytes(env(List.of("x"), Map.of("k", "v"))));
    }
}
