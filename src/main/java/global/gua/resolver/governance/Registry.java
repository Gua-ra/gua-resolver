package global.gua.resolver.governance;

import java.util.Arrays;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** Only HOMESERVERS has a code path; the content of the other registries must stay empty. */
public enum Registry {

    HOMESERVERS("HomeserverRegistry"),
    VERIFIERS("VerifierRegistry"),
    POLICY("PolicyRegistry"),
    WITNESSES("WitnessRegistry");

    private final String wireName;

    Registry(String wireName) {
        this.wireName = wireName;
    }

    /** The wire name is the canonical name carried in signed bytes. */
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

    public static java.util.List<String> allWireNames() {
        return Arrays.stream(values()).map(Registry::wireName).toList();
    }
}
