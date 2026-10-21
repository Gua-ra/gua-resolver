package global.gua.resolver.governance;

import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.roster.RosterEntry;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RegistryMemberTest {

    private static RegistryMember member(RosterEntry.Status status, long weight) {
        return new RegistryMember("hs", status, null, weight, true, List.of());
    }

    @Test
    void aPendingStatusIsNotAGovernedStatus() {
        assertThatThrownBy(() -> member(RosterEntry.Status.PENDING, 1).validateShape())
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("ACTIVE, SUSPENDED or REVOKED");
    }

    @Test
    void aWeightWiderThanTheRosterColumnIsRefusedRatherThanNarrowed() {
        assertThatCode(() -> member(RosterEntry.Status.ACTIVE, Integer.MAX_VALUE).validateShape())
                .doesNotThrowAnyException();

        assertThatThrownBy(() -> member(RosterEntry.Status.ACTIVE, Integer.MAX_VALUE + 1L).validateShape())
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("exceeds the largest weight");
    }

    @Test
    void aNegativeWeightIsRefused() {
        assertThatThrownBy(() -> member(RosterEntry.Status.ACTIVE, -1).validateShape())
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("must not be negative");
    }
}
