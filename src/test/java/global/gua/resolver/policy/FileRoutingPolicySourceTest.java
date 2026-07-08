package global.gua.resolver.policy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;

class FileRoutingPolicySourceTest {

    private static final Homeserver CARRIER = new Homeserver(
            "carrier", "vivo.gua.global", "https://carrier", "https://carrier/auth", "BR", 1, true, "");

    private final ObjectMapper mapper = JsonMapper.builder().addModule(new JavaTimeModule()).build();
    private final Ed25519.KeyPairB64 key = Ed25519.generate();

    @Test
    void rejectsPolicyRollbackToALowerVersion(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("policy.json");
        writePolicy(file, 5);
        FileRoutingPolicySource source = source(file, Clock.systemUTC());
        assertThat(source.current()).map(RoutingPolicyBundle::version).contains(5L);

        // An attacker/stale mirror swaps in a validly-signed but OLDER policy; it must be rejected.
        writePolicy(file, 4);
        source.refresh();

        assertThat(source.current()).map(RoutingPolicyBundle::version).contains(5L);
        assertThat(source.status().message()).contains("rollback");
    }

    @Test
    void stopsServingAnExpiredPolicy(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("policy.json");
        Instant base = Instant.now();
        writePolicy(file, 1, base.minusSeconds(60), base.plusSeconds(60));
        MutableClock clock = new MutableClock(base);
        FileRoutingPolicySource source = source(file, clock);
        assertThat(source.current()).isPresent();

        // Time advances past the policy's signed expiry; it must degrade to "no policy", not keep applying.
        clock.set(base.plusSeconds(120));
        assertThat(source.current()).isEmpty();
        assertThat(source.status().available()).isFalse();
    }

    @Test
    void allowsRecoveryToALowerVersionOnceTheCurrentPolicyHasExpired(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("policy.json");
        Instant base = Instant.now();
        MutableClock clock = new MutableClock(base);
        writePolicy(file, 5, base.minusSeconds(60), base.plusSeconds(60));   // v5 valid until base+60s
        FileRoutingPolicySource source = source(file, clock);
        assertThat(source.current()).map(RoutingPolicyBundle::version).contains(5L);

        clock.set(base.plusSeconds(120));                                    // v5 expires
        assertThat(source.current()).isEmpty();

        // An operator recovers by publishing a good, in-window v4; rollback protection must NOT block it,
        // because the expired v5 no longer floors the version.
        writePolicy(file, 4, base.minusSeconds(60), base.plusSeconds(3600));
        source.refresh();
        assertThat(source.current()).map(RoutingPolicyBundle::version).contains(4L);
    }

    private FileRoutingPolicySource source(Path file, Clock clock) {
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setEnabled(true);
        props.getPolicy().setFile(file.toString());
        props.getPolicy().setRequireSignatures(true);
        props.getPolicy().setSignatureThreshold(1);
        props.getPolicy().setSigningKeyId("policy-a");
        props.getPolicy().setSigningPrivateKey(key.privateKeyB64());
        ResolverProperties.TrustedKey trusted = new ResolverProperties.TrustedKey();
        trusted.setId("policy-a");
        trusted.setPublicKey(key.publicKeyB64());
        props.getPolicy().setTrustedKeys(List.of(trusted));
        return new FileRoutingPolicySource(props, mapper, roster(), new RoutingPolicyValidator(),
                new RoutingPolicyVerifier(props), List.of(), clock);
    }

    private void writePolicy(Path file, long version) throws Exception {
        writePolicy(file, version, Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));
    }

    private void writePolicy(Path file, long version, Instant notBefore, Instant expiresAt) throws Exception {
        ResolverProperties props = new ResolverProperties();
        props.getPolicy().setSigningKeyId("policy-a");
        props.getPolicy().setSigningPrivateKey(key.privateKeyB64());
        RoutingPolicyBundle unsigned = new RoutingPolicyBundle(
                RoutingPolicyBundle.SCHEMA_VERSION, "delegated-br", version,
                Instant.now(), notBefore, expiresAt,
                List.of(new DelegationZone("carrier-zone", DelegationZone.ScopeType.PHONE_PREFIX,
                        "+55119", "carrier:vivo", "delegate-vivo", "DPUB", List.of("carrier"), null, null)),
                List.of(new RoutingPolicyRule("carrier-rule", 10, RoutingPolicyRule.MatchType.PHONE_PREFIX,
                        "+551198", null, null, "carrier", "carrier-zone", "portable carrier rule",
                        RoutingPolicyRule.AssignmentPolicy.PORTABLE, true)),
                new RoutingPolicyBundle.FallbackStrategy("legacy-weighted", true), List.of(), List.of());
        RoutingPolicyBundle signed = new RoutingPolicySigner(props).sign(unsigned);
        Files.writeString(file, mapper.writeValueAsString(signed));
    }

    private RosterStore roster() {
        SignedRoster roster = new SignedRoster(2, Instant.now(),
                List.of(new RosterEntry(CARRIER, List.of(), Instant.now(), RosterEntry.Status.ACTIVE)),
                new SignedRoster.LogCheckpoint("root", 1), List.of());
        return new RosterStore() {
            @Override public SignedRoster current() { return roster; }
            @Override public SignedRoster refresh() { return roster; }
        };
    }

    private static final class MutableClock extends Clock {
        private volatile Instant now;

        MutableClock(Instant now) { this.now = now; }

        void set(Instant now) { this.now = now; }

        @Override public Instant instant() { return now; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
    }
}
