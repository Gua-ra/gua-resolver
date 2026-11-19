package global.gua.resolver.api;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.annotation.DirtiesContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CORS as a browser sees it through a real listener, where error responses take the ERROR dispatch that
 * MockMvc skips. Uses java.net.http because HttpURLConnection drops the Origin header.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "gua.resolver.cors.allowed-origins=https://chat.example.test",
        "gua.resolver.abuse.client-limit-for-period=2",
        "gua.resolver.abuse.client-burst=2",
        "gua.resolver.abuse.client-refresh-period=PT1H",
        "spring.datasource.url=jdbc:h2:mem:cors-tomcat;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
})
@DirtiesContext
class CorsThroughTomcatTest {

    private static final String ORIGIN = "https://chat.example.test";
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    @LocalServerPort
    private int port;

    private HttpRequest.Builder request(String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).header("Origin", ORIGIN);
    }

    private HttpResponse<String> send(HttpRequest request) throws Exception {
        return HTTP.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> resolve() throws Exception {
        return send(request("/resolve").header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"phone\":\"+5511987654321\"}")).build());
    }

    @Test
    void preflightsSpendNoRateLimitTokensAndA429StillCarriesTheHeader() throws Exception {
        for (int i = 0; i < 5; i++) {
            HttpResponse<String> preflight = send(request("/resolve")
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "content-type")
                    .method("OPTIONS", HttpRequest.BodyPublishers.noBody()).build());
            assertThat(preflight.statusCode()).isEqualTo(200);
        }
        assertThat(resolve().statusCode()).isEqualTo(200);
        assertThat(resolve().statusCode()).isEqualTo(200);

        HttpResponse<String> limited = resolve();
        assertThat(limited.statusCode()).isEqualTo(429);
        assertThat(limited.headers().firstValue("Access-Control-Allow-Origin")).hasValue(ORIGIN);
        assertThat(limited.headers().firstValue("Access-Control-Expose-Headers")).hasValue("Retry-After");
    }

    @Test
    void aMissingPolicyIsANotFoundTheBrowserCanRead() throws Exception {
        HttpResponse<String> response = send(request("/policy/routing").GET().build());

        assertThat(response.statusCode()).isEqualTo(404);
        assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).hasValue(ORIGIN);
    }
}
