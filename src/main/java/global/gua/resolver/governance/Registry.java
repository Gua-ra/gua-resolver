package global.gua.resolver.governance;

import java.util.Arrays;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The four registries ADM-001 L10 fixes under the governance root. They are versioned separately, each with
 * its own epoch chain, so a verifier rotation is not a membership epoch and neither drags the other forward.
 *
 * <p>The constant's wire name is its canonical name: it is what the genesis enumerates and what a
 * {@code gua-registry-epoch.v1} object carries in its canonical bytes. Only {@link #HOMESERVERS} has a code
 * path in Phase 2; the other three exist so the shape is fixed before accreditations (Phase 5) and witnesses
 * (Phase 9) need it, and their content must be empty until then.
 */
public enum Registry {

    HOMESERVERS("HomeserverRegistry"),
    VERIFIERS("VerifierRegistry"),
    POLICY("PolicyRegistry"),
    WITNESSES("WitnessRegistry");

    private final String wireName;

    Registry(String wireName) {
        this.wireName = wireName;
    }

    /** The canonical name: what the genesis lists and what the canonical epoch bytes carry. */
    @JsonValue
    public String wireName() {
        return wireName;
    }

    @JsonCreator
    public static Registry of(String wireName) {
        return Arrays.stream(values())
                .filter(r -> r.wireName.equals(wireName))
                .findFirst()
                .orElseThrow(() -> new GovernanceException("unknown registry: " + wireName));
    }

    /** The four canonical names, in the order a v1 genesis enumerates them. */
    public static java.util.List<String> allWireNames() {
        return Arrays.stream(values()).map(Registry::wireName).toList();
    }
}
