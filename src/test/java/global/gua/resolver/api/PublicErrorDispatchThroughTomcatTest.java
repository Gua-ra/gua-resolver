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
 * <p>MockMvc does not perform the ERROR dispatch. A real container re-dispatches to {@code /error} to render
 * a 404, Spring Security filters that dispatch as well, and if {@code /error} is not permitted the caller
 * gets a 401 with an empty body instead. No genesis is configured here on purpose.
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
