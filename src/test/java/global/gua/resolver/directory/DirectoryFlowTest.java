package global.gua.resolver.directory;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import global.gua.resolver.crypto.Ed25519;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The shared directory's write path (§4): the seeded dev homeserver registers one of its accounts' phone
 * number, signed with its membership credential (the Ed25519 key in its roster entry); the resolver then
 * routes that phone to it. A write signed by the wrong key is rejected, and the phone is only ever stored
 * as a peppered HMAC. Dirties the context (mutates the directory).
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext
class DirectoryFlowTest {

    // Private key matching gua.resolver.dev-homeserver.signing-key in the test application.yml.
    private static final String DEV_HS_PRIVATE_KEY =
            "MC4CAQAwBQYDK2VwBCIEIO6hhcxLXz/Gn0yeK3Nr8GK3CgdQlO4D3GMoaoPzQsup";

    @Autowired MockMvc mockMvc;
    @Autowired DirectoryStore directory;
    @Autowired PhoneHasher hasher;

    private static String sign(String canonical) {
        return Ed25519.sign(Ed25519.privateKey(DEV_HS_PRIVATE_KEY),
                canonical.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void homeserverWritesItsOwnAccountAndItResolves() throws Exception {
        String phone = "+5511987654321";
        String sig = sign("directory-write.v1|dev|" + phone + "|");
        String body = """
                {"homeserverId":"dev","e164Phone":"%s","signature":"%s"}
                """.formatted(phone, sig);

        mockMvc.perform(post("/directory/entries").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isNoContent());

        // The phone is stored only as a peppered HMAC and now resolves to the dev homeserver.
        org.assertj.core.api.Assertions.assertThat(directory.homeserverIdForPhone(phone)).contains("dev");
        org.assertj.core.api.Assertions.assertThat(directory.homeserverIdForPhoneHash(hasher.hashPhone(phone)))
                .contains("dev");
    }

    @Test
    void rejectsWriteSignedWithTheWrongKey() throws Exception {
        String phone = "+5511000000000";
        String wrongSig = Ed25519.sign(Ed25519.privateKey(Ed25519.generate().privateKeyB64()),
                ("directory-write.v1|dev|" + phone + "|").getBytes(StandardCharsets.UTF_8));
        String body = """
                {"homeserverId":"dev","e164Phone":"%s","signature":"%s"}
                """.formatted(phone, wrongSig);

        mockMvc.perform(post("/directory/entries").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnauthorized());
    }
}
