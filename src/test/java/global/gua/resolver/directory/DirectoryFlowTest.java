package global.gua.resolver.directory;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import global.gua.resolver.crypto.Ed25519;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The shared directory has no HTTP write path (ADM-001 L1b). The regression here replays the request the
 * removed {@code POST /directory/entries} used to accept: the seeded dev homeserver binds a phone and a
 * username to itself, signed with its membership credential (the Ed25519 key in its roster entry). It must
 * be refused and write nothing. The read paths that still serve rows written before the removal
 * ({@code GET /directory/lookup}, {@code POST /resolve}) keep working against rows seeded through the
 * store interface.
 */
@SpringBootTest
@AutoConfigureMockMvc
class DirectoryFlowTest {

    // Private key matching gua.resolver.dev-homeserver.signing-key in the test application.yml.
    private static final String DEV_HS_PRIVATE_KEY =
            "MC4CAQAwBQYDK2VwBCIEIO6hhcxLXz/Gn0yeK3Nr8GK3CgdQlO4D3GMoaoPzQsup";

    @Autowired MockMvc mockMvc;
    @Autowired JdbcDirectoryStore directory;
    @Autowired PhoneHasher hasher;

    private static String sign(String canonical) {
        return Ed25519.sign(Ed25519.privateKey(DEV_HS_PRIVATE_KEY),
                canonical.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void validlySignedDirectoryWriteIsRefusedAndWritesNothing() throws Exception {
        String phone = "+5511987654321";
        String username = "sec002-alice";
        // Exactly the payload the removed endpoint accepted: an ACTIVE roster member's valid
        // membership-credential signature over the old canonical string.
        String sig = sign("directory-write.v1|dev|" + phone + "|" + username);
        String body = """
                {"homeserverId":"dev","e164Phone":"%s","username":"%s","signature":"%s"}
                """.formatted(phone, username, sig);

        assertThat(directory.homeserverIdForPhone(phone)).isEmpty();
        assertThat(directory.homeserverIdForUsername(username)).isEmpty();
        DirectoryCheckpoint before = directory.checkpoint();

        mockMvc.perform(post("/directory/entries").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().is4xxClientError());

        // Nothing was written: neither row exists and the directory's Merkle root is unchanged.
        assertThat(directory.homeserverIdForPhone(phone)).isEmpty();
        assertThat(directory.homeserverIdForPhoneHash(hasher.hashPhone(phone))).isEmpty();
        assertThat(directory.homeserverIdForUsername(username)).isEmpty();
        DirectoryCheckpoint after = directory.checkpoint();
        assertThat(after.merkleRoot()).isEqualTo(before.merkleRoot());
        assertThat(after.size()).isEqualTo(before.size());

        // /resolve still answers register for that number.
        mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"phone\":\"" + phone + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(false))
                .andExpect(jsonPath("$.registerAt.serverName").value("gua.local"));
    }

    @Test
    void existingRowsAreStillServedByLookupAndResolve() throws Exception {
        String phone = "+5511900000002";
        directory.putPhone(phone, "dev");
        try {
            mockMvc.perform(get("/directory/lookup").queryParam("phoneHash", hasher.hashPhone(phone)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.homeserverId").value("dev"));

            mockMvc.perform(post("/resolve").contentType(MediaType.APPLICATION_JSON)
                            .content("{\"phone\":\"" + phone + "\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.exists").value(true))
                    .andExpect(jsonPath("$.homeserver.serverName").value("gua.local"));
        } finally {
            directory.removePhone(phone);
        }
    }
}
