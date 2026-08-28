package global.gua.resolver.roster;

import java.nio.file.Files;
import java.time.Instant;
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

    @Test
    void mirrorCanColdStartFromCachedVerifiedRosterWhenUpstreamIsUnavailable() throws Exception {
        Ed25519.KeyPairB64 kp = Ed25519.generate();
        ResolverProperties props = props(kp, tempDir.resolve("roster-cache.json").toString());
        SignedRoster signed = new RosterSigner(props).sign(4, Instant.now(), List.of(entry("dev")),
                new SignedRoster.LogCheckpoint("root", 4));
        ObjectMapper json = new ObjectMapper().findAndRegisterModules();
        Files.writeString(java.nio.file.Path.of(props.getMirror().getCacheFile()),
                json.writeValueAsString(signed));

        MirrorRosterStore store = new MirrorRosterStore(props, new RosterVerifier(props),
                WebClient.builder(), json);

        assertThat(store.current().version()).isEqualTo(4);
        assertThat(store.current().entries()).hasSize(1);
    }

    private static ResolverProperties props(Ed25519.KeyPairB64 kp, String cacheFile) {
        ResolverProperties props = new ResolverProperties();
        props.getMirror().setUpstreamUrl("http://127.0.0.1:9");
        props.getMirror().setCacheFile(cacheFile);
        props.getAuthority().setSigningKeyId("auth-a");
        props.getAuthority().setSigningPrivateKey(kp.privateKeyB64());
        ResolverProperties.TrustedKey trusted = new ResolverProperties.TrustedKey();
        trusted.setId("auth-a");
        trusted.setPublicKey(kp.publicKeyB64());
        props.getAuthority().setTrustedKeys(List.of(trusted));
        return props;
    }

    private static RosterEntry entry(String id) {
        Homeserver hs = new Homeserver(id, id + ".gua.global", "https://" + id,
                "https://" + id + "/auth", "BR", 1, true, "");
        return new RosterEntry(hs, List.of(), Instant.now(), RosterEntry.Status.ACTIVE);
    }
}
