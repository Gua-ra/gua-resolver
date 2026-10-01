package global.gua.resolver.abuse;

import java.io.IOException;
import java.util.Properties;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.core.env.Environment;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.annotation.DirtiesContext;

import static org.assertj.core.api.Assertions.assertThat;

/** Uses a real Tomcat listener: MockMvc never runs RemoteIpValve. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "gua.resolver.abuse.client-limit-for-period=2",
        "gua.resolver.abuse.client-burst=2",
        "gua.resolver.abuse.client-refresh-period=PT1H",
        "gua.resolver.abuse.trace-enabled=false"
})
@DirtiesContext
class ClientKeyThroughTomcatTest {

    private static final String BODY = "{\"phone\":\"+5511987654321\"}";
    private static final String INTERNAL_HOP = "10.0.0.1";

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate http;

    @Autowired
    private Environment environment;

    private ResponseEntity<String> resolve(String forwardedFor) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        if (forwardedFor != null) {
            headers.set("X-Forwarded-For", forwardedFor);
        }
        // The IPv4 literal pins the socket peer to 127.0.0.1.
        return http.postForEntity("http://127.0.0.1:" + port + "/resolve", new HttpEntity<>(BODY, headers),
                String.class);
    }

    private HttpStatus status(String forwardedFor) {
        return HttpStatus.valueOf(resolve(forwardedFor).getStatusCode().value());
    }

    @Test
    void theStrategyIsPinnedToNativeInTheRunningContextAndInEveryProfileOnTheClasspath() throws IOException {
        assertThat(environment.getProperty("server.forward-headers-strategy")).isEqualTo("native");

        Resource[] profiles = new PathMatchingResourcePatternResolver().getResources("classpath*:application.yml");
        assertThat(profiles).as("the shipped profile and the test profile are both on the classpath").hasSizeGreaterThanOrEqualTo(2);
        for (Resource profile : profiles) {
            YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
            yaml.setResources(profile);
            Properties properties = yaml.getObject();
            assertThat(properties).isNotNull();
            assertThat(properties.getProperty("server.forward-headers-strategy"))
                    .as("server.forward-headers-strategy in %s", profile.getDescription())
                    .isEqualTo("native");
        }
    }

    @Test
    void theValveKeysOnTheAddressTheEdgeAppendedNotOnTheInternalHop() {
        assertThat(status("203.0.113.9, " + INTERNAL_HOP)).isEqualTo(HttpStatus.OK);
        assertThat(status("203.0.113.9, " + INTERNAL_HOP)).isEqualTo(HttpStatus.OK);
        assertThat(status("203.0.113.9, " + INTERNAL_HOP)).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(status("203.0.113.10, " + INTERNAL_HOP)).isEqualTo(HttpStatus.OK);

        assertThat(status("203.0.113.10, " + INTERNAL_HOP + ", 172.16.0.1")).isEqualTo(HttpStatus.OK);
        assertThat(status("203.0.113.10, " + INTERNAL_HOP)).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
    }

    @Test
    void callerSuppliedEntriesNeitherChooseABucketNorDrainAnotherClients() {
        assertThat(status("192.0.2.1, 192.0.2.2, 203.0.113.20, " + INTERNAL_HOP)).isEqualTo(HttpStatus.OK);
        assertThat(status("192.0.2.3, 203.0.113.20, " + INTERNAL_HOP)).isEqualTo(HttpStatus.OK);
        assertThat(status("203.0.113.20, " + INTERNAL_HOP)).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);

        assertThat(status("203.0.113.21, 203.0.113.22, " + INTERNAL_HOP)).isEqualTo(HttpStatus.OK);
        assertThat(status("203.0.113.21, 203.0.113.22, " + INTERNAL_HOP)).isEqualTo(HttpStatus.OK);
        assertThat(status("203.0.113.21, 203.0.113.22, " + INTERNAL_HOP)).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(status("203.0.113.21, " + INTERNAL_HOP)).isEqualTo(HttpStatus.OK);
    }

    @Test
    void withoutAChainTheSocketPeerIsTheKeyAndTheRefusalIsTheConstantContract() {
        assertThat(status(null)).isEqualTo(HttpStatus.OK);
        assertThat(status(null)).isEqualTo(HttpStatus.OK);

        ResponseEntity<String> refused = resolve(null);
        assertThat(refused.getStatusCode().value()).isEqualTo(429);
        assertThat(refused.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).matches("[1-9][0-9]*");
        assertThat(refused.getBody()).isEqualTo(ResolveAbuseFilter.RATE_LIMITED_BODY);
    }
}
