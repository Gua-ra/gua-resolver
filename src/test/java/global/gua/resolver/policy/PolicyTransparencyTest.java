package global.gua.resolver.policy;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import global.gua.resolver.roster.JdbcTransparencyLog;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The authority appends every adopted policy version to the transparency log, idempotently, and the
 * published checkpoint + consistency proofs cover those policy leaves (so policy cannot be equivocated).
 */
@SpringBootTest
class PolicyTransparencyTest {

    @Autowired
    private JdbcTransparencyLog log;

    @Autowired
    private PolicyTransparencyListener listener;

    private static RoutingPolicyBundle bundle(String id, long version) {
        return new RoutingPolicyBundle(RoutingPolicyBundle.SCHEMA_VERSION, id, version,
                Instant.now(), null, null, List.of(), List.of(),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true), List.of(), List.of());
    }

    @Test
    void adoptingPolicyVersionsAppendsIdempotentAuditableLeaves() {
        SignedRoster.LogCheckpoint before = log.head();
        int policyEventsBefore = log.eventsOfType(PolicyTransparencyListener.EVENT_TYPE).size();

        RoutingPolicyBundle v1 = bundle("prod-policy", 1);
        listener.onPolicyAdopted(v1);
        listener.onPolicyAdopted(v1);   // same content -> must NOT append again (idempotent)
        SignedRoster.LogCheckpoint afterV1 = log.head();
        listener.onPolicyAdopted(bundle("prod-policy", 2));   // new version -> appends
        SignedRoster.LogCheckpoint afterV2 = log.head();

        assertThat(log.eventsOfType(PolicyTransparencyListener.EVENT_TYPE).size())
                .isEqualTo(policyEventsBefore + 2);
        // the log grew by exactly two leaves (v1 once, v2 once) and each head extends the previous
        assertThat(afterV2.size()).isEqualTo(before.size() + 2);
        assertThat(log.verifyConsistency(before, afterV1)).isTrue();
        assertThat(log.verifyConsistency(afterV1, afterV2)).isTrue();

        assertThat(log.eventsOfType(PolicyTransparencyListener.EVENT_TYPE))
                .anyMatch(e -> "prod-policy:v2".equals(e.homeserverId()));
    }
}
