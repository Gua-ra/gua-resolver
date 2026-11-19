package global.gua.resolver.governance;

import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.crypto.CanonicalEncoder.CanonicalEncodingException;
import global.gua.resolver.crypto.Ed25519;

import static global.gua.resolver.governance.CheckpointKey.Role.RESOLVER;
import static global.gua.resolver.governance.CheckpointKey.Role.WITNESS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WitnessRegistryContentTest {

    private static final CheckpointKey RESOLVER_KEY = key("resolver-1", "gua", RESOLVER);
    private static final CheckpointKey WITNESS_B = key("witness-b", "operator-b", WITNESS);
    private static final CheckpointKey WITNESS_C = key("witness-c", "operator-c", WITNESS);

    private static CheckpointKey key(String keyId, String operatorId, CheckpointKey.Role role) {
        return new CheckpointKey(keyId, GovernanceKey.ALG, Ed25519.generate().publicKeyB64(), operatorId, role,
                null);
    }

    private static WitnessRegistryContent list(long requiredWitnesses, CheckpointKey... keys) {
        return new WitnessRegistryContent(WitnessRegistryContent.SCHEMA, requiredWitnesses, List.of(keys));
    }

    @Test
    void aWitnessRunByTheResolversOperatorNeverCounts() {
        WitnessRegistryContent sameOperator = list(0, RESOLVER_KEY, key("witness-gua", "gua", WITNESS));
        assertThatCode(sameOperator::validateShape).doesNotThrowAnyException();
        assertThat(sameOperator.countedWitnessOperators()).isEmpty();
        assertThatThrownBy(() -> list(1, RESOLVER_KEY, key("witness-gua", "gua", WITNESS)).validateShape())
                .isInstanceOf(GovernanceException.class);
    }

    @Test
    void requiredWitnessesIsZeroOrMoreThanHalfOfTheOperatorsThatCount() {
        assertThatCode(() -> list(0, RESOLVER_KEY, WITNESS_B, WITNESS_C).validateShape())
                .doesNotThrowAnyException();
        assertThatCode(() -> list(2, RESOLVER_KEY, WITNESS_B, WITNESS_C).validateShape())
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> list(1, RESOLVER_KEY, WITNESS_B, WITNESS_C).validateShape())
                .isInstanceOf(GovernanceException.class);
        assertThatThrownBy(() -> list(3, RESOLVER_KEY, WITNESS_B, WITNESS_C).validateShape())
                .isInstanceOf(GovernanceException.class);
        assertThatThrownBy(() -> list(-1, RESOLVER_KEY).validateShape()).isInstanceOf(GovernanceException.class);
    }

    @Test
    void twoWitnessKeysOfOneOperatorCountOnce() {
        WitnessRegistryContent oneOperator = list(1, RESOLVER_KEY, WITNESS_B, key("witness-b2", "operator-b", WITNESS));
        assertThatCode(oneOperator::validateShape).doesNotThrowAnyException();
        assertThat(oneOperator.countedWitnessOperators()).containsExactly("operator-b");
    }

    @Test
    void theListNeedsAResolverKeyAndNamesEachPublicKeyOnce() {
        assertThatThrownBy(() -> list(0, WITNESS_B).validateShape()).isInstanceOf(GovernanceException.class);
        CheckpointKey sameKey = new CheckpointKey("witness-twin", GovernanceKey.ALG, RESOLVER_KEY.publicKey(),
                "operator-b", WITNESS, null);
        assertThatThrownBy(() -> list(0, RESOLVER_KEY, sameKey).validateShape())
                .isInstanceOf(GovernanceException.class);
    }

    @Test
    void anotherSpellingOfTheSameKeyIsTheSameKey() {
        String unpadded = RESOLVER_KEY.publicKey().replace("=", "");
        CheckpointKey respelled = new CheckpointKey("witness-twin", GovernanceKey.ALG, unpadded, "operator-b",
                WITNESS, null);
        assertThatThrownBy(() -> list(0, RESOLVER_KEY, respelled).validateShape())
                .isInstanceOf(GovernanceException.class);
        CheckpointKey invalid = new CheckpointKey("witness-bad", GovernanceKey.ALG, "not a key", "operator-b",
                WITNESS, null);
        assertThatThrownBy(() -> list(0, RESOLVER_KEY, invalid).validateShape())
                .isInstanceOf(GovernanceException.class);
    }

    @Test
    void aDuplicateKeyIdHasNoCanonicalEncoding() {
        CheckpointKey reusedId = key("resolver-1", "operator-b", WITNESS);
        assertThatThrownBy(() -> CanonicalWitnessRegistryContent.bytes(list(0, RESOLVER_KEY, reusedId)))
                .isInstanceOf(CanonicalEncodingException.class);
    }
}
