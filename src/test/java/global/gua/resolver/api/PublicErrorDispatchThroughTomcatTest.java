package global.gua.resolver.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the public endpoints answer when they have nothing to serve, asserted through a real listener.
 *
 * <p>MockMvc does not perform the ERROR dispatch, so a MockMvc test sees the 404 the controller raised and
 * stops there. A real container re-dispatches to {@code /error} to render it, Spring Security filters that
 * dispatch as well, and if {@code /error} is not permitted the render is denied: the caller gets 401 with an
 * empty body instead of the 404. That is invisible to every MockMvc test in this suite, which is why these
 * assertions are made over a socket.
 *
 * <p>It matters for exactly the two endpoints this phase adds, because both have a legitimate empty state:
 * before the key ceremony there is no genesis, and before the first epoch there is no epoch. An operator
 * following docs/runbooks/governance-keys.md curls them at that point, and "authenticate first" would send
 * them after an auth problem that does not exist.
 *
 * <p>No genesis is configured here on purpose: this is the pre-cutover state of a deployed environment.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext
class PublicErrorDispatchThroughTomcatTest {

    @DynamicPropertySource
    static void ownDatabaseAndNoGenesis(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url",
                () -> "jdbc:h2:mem:error-dispatch;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE");
    }

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate http;

    /** GET over a real socket, asking for JSON so the error render is content-negotiated deterministically. */
    private ResponseEntity<String> get(String path) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(java.util.List.of(MediaType.APPLICATION_JSON));
        return http.exchange("http://127.0.0.1:" + port + path, HttpMethod.GET,
                new HttpEntity<>(headers), String.class);
    }

    @Test
    void noGenesisYetIsANotFoundAndNotAnAuthPrompt() {
        ResponseEntity<String> response = get("/.well-known/gua-federation");

        assertThat(response.getStatusCode().value()).isEqualTo(HttpStatus.NOT_FOUND.value());
        // The empty body is half the defect: a 401 with nothing in it tells the operator nothing at all.
        assertThat(response.getBody()).isNotNull().contains("404");
    }

    @Test
    void anEpochThatDoesNotExistIsANotFoundAndNotAnAuthPrompt() {
        assertThat(get("/registry/homeservers/epoch/99").getStatusCode().value())
                .isEqualTo(HttpStatus.NOT_FOUND.value());
        assertThat(get("/registry/homeservers/epoch/current").getStatusCode().value())
                .isEqualTo(HttpStatus.NOT_FOUND.value());
    }

    @Test
    void theAdminSurfaceIsStillDeniedThroughTheSameDispatch() {
        // Permitting the error render must not have permitted anything that produces one.
        assertThat(get("/authority/registry/homeservers/pending").getStatusCode().value())
                .isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    void anUnmappedPathIsStillDeniedRatherThanDescribed() {
        // Deny-by-default is unchanged: an unmapped path is refused, not answered with a 404 that would
        // tell an anonymous caller which paths exist.
        assertThat(get("/authority/whatever").getStatusCode().value())
                .isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(get("/not-a-resolver-endpoint").getStatusCode().value())
                .isEqualTo(HttpStatus.UNAUTHORIZED.value());
    }
}
