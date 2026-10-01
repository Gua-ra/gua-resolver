package global.gua.resolver.governance;

import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.crypto.Ed25519;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GovernanceVerifierTest {

    private static final byte[] MESSAGE = "governance object".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @Test
    void twoKeysHeldByOneOperatorCountOnce() {
        GovernanceFixtures.Holder first = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        GovernanceFixtures.Holder second = GovernanceFixtures.Holder.of("gov-2", "operator-a");
        GovernanceKeySet keys = GovernanceKeySet.of("genesis", 1,
                List.of(first.key(), second.key()));

        GovernanceVerifier.Outcome outcome = GovernanceVerifier.count(keys, MESSAGE,
                List.of(first.sign(MESSAGE), second.sign(MESSAGE)));

        assertThat(outcome.operators()).isEqualTo(1);
        assertThat(outcome.countedOperators()).containsExactly("operator-a");
        assertThat(outcome.valid()).isTrue();
    }

    @Test
    void aThresholdOfTwoIsNotMetByOneOperatorHoldingTwoKeys() {
        GovernanceFixtures.Holder first = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        GovernanceFixtures.Holder second = GovernanceFixtures.Holder.of("gov-2", "operator-a");

        assertThatThrownBy(() -> GovernanceKeySet.of("genesis", 2, List.of(first.key(), second.key())))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("exceeds the 1 distinct operator");
    }

    @Test
    void twoOperatorsMeetAThresholdOfTwoAndOneAloneDoesNot() {
        GovernanceFixtures.Holder a = GovernanceFixtures.Holder.of("gov-a", "operator-a");
        GovernanceFixtures.Holder b = GovernanceFixtures.Holder.of("gov-b", "operator-b");
        GovernanceKeySet keys = GovernanceKeySet.of("genesis", 2, List.of(a.key(), b.key()));

        assertThat(GovernanceVerifier.count(keys, MESSAGE, List.of(a.sign(MESSAGE), b.sign(MESSAGE)))
                .valid()).isTrue();
        assertThat(GovernanceVerifier.count(keys, MESSAGE, List.of(a.sign(MESSAGE))).valid()).isFalse();
        assertThatThrownBy(() -> GovernanceVerifier.require(keys, MESSAGE, List.of(a.sign(MESSAGE)), "epoch"))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("from 1 operator(s), need 2");
    }

    @Test
    void signaturesFromUnknownKeysAndOverOtherBytesAreNotCounted() {
        GovernanceFixtures.Holder known = GovernanceFixtures.Holder.of("gov-1", "operator-a");
        GovernanceFixtures.Holder stranger = GovernanceFixtures.Holder.of("gov-x", "operator-z");
        GovernanceKeySet keys = GovernanceKeySet.of("genesis", 1, List.of(known.key()));

        assertThat(GovernanceVerifier.count(keys, MESSAGE, List.of(stranger.sign(MESSAGE))).operators())
                .isZero();

        GovernanceSignature wrongBytes = new GovernanceSignature("gov-1",
                Ed25519.sign(Ed25519.privateKey(known.privateKeyB64()), "other".getBytes(
                        java.nio.charset.StandardCharsets.UTF_8)));
        assertThat(GovernanceVerifier.count(keys, MESSAGE, List.of(wrongBytes)).operators()).isZero();
    }

    @Test
    void aKeyWithoutAnOperatorIdIsRefused() {
        GovernanceKey orphan = new GovernanceKey("gov-1", GovernanceKey.ALG,
                Ed25519.generate().publicKeyB64(), null);

        assertThatThrownBy(() -> GovernanceKeySet.of("genesis", 1, List.of(orphan)))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("needs an operatorId");
    }

    @Test
    void anUnsupportedAlgorithmIsRefused() {
        GovernanceKey rsa = new GovernanceKey("gov-1", "RSA", Ed25519.generate().publicKeyB64(), "operator-a");

        assertThatThrownBy(() -> GovernanceKeySet.of("genesis", 1, List.of(rsa)))
                .isInstanceOf(GovernanceException.class)
                .hasMessageContaining("unsupported governance key alg");
    }
}
