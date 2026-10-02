package global.gua.resolver.roster;

import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.ObjectMapper;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;

import static org.assertj.core.api.Assertions.assertThat;

class MirrorRosterStoreTest {

    @TempDir
    java.nio.file.Path tempDir;

    private static final Ed25519.KeyPairB64 MEMBER_KEY = Ed25519.generate();
    private static final Instant NOT_BEFORE =
            Instant.now().truncatedTo(ChronoUnit.MILLIS).minus(Duration.ofDays(1));

    @Test
    void mirrorCanColdStartFromCachedVerifiedRosterWhenUpstreamIsUnavailable() throws Exception {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        ResolverProperties props = props(kp, tempDir.resolve("roster-cache.json").toString(), false);
        SignedRoster signed = new RosterSigner(props).sign(4, Instant.now(), List.of(entry("dev")),
                new SignedRoster.LogCheckpoint("root", 4));
        ObjectMapper json = mapper();
        Files.writeString(java.nio.file.Path.of(props.getMirror().getCacheFile()),
                json.writeValueAsString(signed));

        MirrorRosterStore store = new MirrorRosterStore(props, new RosterVerifier(props),
                WebClient.builder(), json);

        assertThat(store.current().version()).isEqualTo(4);
        assertThat(store.current().entries()).hasSize(1);
    }

    @Test
    void anUnattestedEntryIsRoutableOnlyWhileTheTransitionFlagIsOff() throws Exception {
        assertThat(routableIds(cachedRoster(attested("hs-attested"), entry("hs-unattested")), false))
                .containsExactlyInAnyOrder("hs-attested", "hs-unattested");
        assertThat(routableIds(cachedRoster(attested("hs-attested"), entry("hs-unattested")), true))
                .containsExactly("hs-attested");
    }

    @Test
    void anEntryWhoseBaseUrlTheAuthoritySubstitutedIsDroppedWhenTheFlagIsOn() throws Exception {
        RosterEntry substituted = substitutedBaseUrl(attested("hs-moved"));

        // The upstream signature covers the substitution, so only the member signature catches it.
        assertThat(routableIds(cachedRoster(substituted), false)).containsExactly("hs-moved");
        assertThat(routableIds(cachedRoster(substituted), true)).isEmpty();
    }

    @Test
    void theUpstreamDocumentIsStillServedVerbatimSoClientsCanVerifyIt() throws Exception {
        Ed25519.KeyPairB64 authority = Ed25519.generate();
        ResolverProperties props = props(authority, tempDir.resolve("served.json").toString(), true);
        writeCache(props, authority, attested("hs-attested"), entry("hs-unattested"));

        MirrorRosterStore store = new MirrorRosterStore(props, new RosterVerifier(props),
                WebClient.builder(), mapper());

        assertThat(store.served().entries()).hasSize(2);
        assertThat(store.current().entries()).hasSize(1);
        assertThat(new RosterVerifier(props).isVerified(store.served())).isTrue();
        assertThat(store.unattestedActiveCount()).isEqualTo(1);
    }

    /** Build a mirror over a cached roster and report which entries it will route to. */
    private List<String> routableIds(RosterEntry[] entries, boolean requireMemberSignature) throws Exception {
        Ed25519.KeyPairB64 authority = Ed25519.generate();
        ResolverProperties props = props(authority,
                tempDir.resolve("cache-" + System.nanoTime() + ".json").toString(), requireMemberSignature);
        writeCache(props, authority, entries);

        MirrorRosterStore store = new MirrorRosterStore(props, new RosterVerifier(props),
                WebClient.builder(), mapper());

        return store.current().entries().stream().map(e -> e.homeserver().id()).toList();
    }

    private static RosterEntry[] cachedRoster(RosterEntry... entries) {
        return entries;
    }

    private static void writeCache(ResolverProperties props, Ed25519.KeyPairB64 authority,
                                   RosterEntry... entries) throws Exception {
        SignedRoster signed = new RosterSigner(props).sign(7, Instant.now(), List.of(entries),
                new SignedRoster.LogCheckpoint("root", 7));
        Files.writeString(java.nio.file.Path.of(props.getMirror().getCacheFile()),
                mapper().writeValueAsString(signed));
    }

    private static ObjectMapper mapper() {
        return new ObjectMapper().findAndRegisterModules();
    }

    private static ResolverProperties props(Ed25519.KeyPairB64 kp, String cacheFile,
                                            boolean requireMemberSignature) {
        ResolverProperties props = new ResolverProperties();
        props.getMirror().setUpstreamUrl("http://127.0.0.1:9");
        props.getMirror().setCacheFile(cacheFile);
        props.getAuthority().setSigningKeyId("auth-a");
        props.getAuthority().setSigningPrivateKey(kp.privateKeyB64());
        ResolverProperties.TrustedKey trusted = new ResolverProperties.TrustedKey();
        trusted.setId("auth-a");
        trusted.setPublicKey(kp.publicKeyB64());
        props.getAuthority().setTrustedKeys(List.of(trusted));
        props.getRoster().setRequireMemberSignature(requireMemberSignature);
        return props;
    }

    private static RosterEntry entry(String id) {
        Homeserver hs = new Homeserver(id, id + ".gua.global", "https://" + id,
                "https://" + id + "/auth", "BR", 1, true, "");
        return new RosterEntry(hs, List.of(), Instant.now(), RosterEntry.Status.ACTIVE);
    }

    /** An entry carrying a valid member self-signature over its own fields. */
    private static RosterEntry attested(String id) {
        Homeserver hs = new Homeserver(id, id + ".gua.global", "https://" + id, "https://" + id + "/auth",
                "BR", 1, true, MEMBER_KEY.publicKeyB64(), Homeserver.SearchVisibility.GLOBAL, List.of());
        MemberAttestation member = MemberEntrySigner.sign(hs,
                new MemberAttestation(CanonicalMemberEntry.SCHEMA, CanonicalMemberEntry.ALG, id + "-1", 1,
                        NOT_BEFORE, NOT_BEFORE.plus(Duration.ofDays(200)), List.of()),
                id + "-1", MEMBER_KEY.privateKeyB64());
        return new RosterEntry(hs, List.of(), Instant.now(), RosterEntry.Status.ACTIVE, member);
    }

    /** The same entry with its baseUrl rewritten after the member signed it. */
    private static RosterEntry substitutedBaseUrl(RosterEntry original) {
        Homeserver h = original.homeserver();
        Homeserver moved = new Homeserver(h.id(), h.serverName(), "https://attacker.gua.global",
                h.masIssuer(), h.region(), h.weight(), h.acceptsNew(), h.signingKey(),
                h.searchVisibility(), h.searchGroups());
        return new RosterEntry(moved, original.claims(), original.admittedAt(), original.status(),
                original.member());
    }
}
