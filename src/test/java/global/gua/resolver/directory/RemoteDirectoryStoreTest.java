package global.gua.resolver.directory;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import global.gua.resolver.config.ResolverProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RemoteDirectoryStoreTest {

    @Test
    void mirrorDirectoryLookupFailsClosedByDefault() {
        ResolverProperties props = props(false);
        RemoteDirectoryStore store = new RemoteDirectoryStore(props, new PhoneHasher(props), WebClient.builder());

        assertThatThrownBy(() -> store.homeserverIdForUsername("alice"))
                .isInstanceOf(DirectoryUnavailableException.class);
    }

    @Test
    void mirrorDirectoryLookupCanFailOpenForLegacyDeployments() {
        ResolverProperties props = props(true);
        RemoteDirectoryStore store = new RemoteDirectoryStore(props, new PhoneHasher(props), WebClient.builder());

        assertThat(store.homeserverIdForUsername("alice")).isEmpty();
    }

    @Test
    void servesAStaleVerifiedMappingDuringAnAuthorityOutageWithinBudget() throws Exception {
        HttpServer server = directoryStub("carrier");
        server.start();
        try {
            ResolverProperties props = props(false);
            props.getMirror().setUpstreamUrl("http://127.0.0.1:" + server.getAddress().getPort());
            props.getMirror().setDirectoryCacheTtl(Duration.ofMinutes(10));
            RemoteDirectoryStore store = new RemoteDirectoryStore(props, new PhoneHasher(props), WebClient.builder());

            assertThat(store.homeserverIdForUsername("alice")).contains("carrier");   // warms the cache
            server.stop(0);                                                           // authority goes down
            assertThat(store.homeserverIdForUsername("alice")).contains("carrier");   // served from stale cache
        } finally {
            server.stop(0);
        }
    }

    @Test
    void doesNotServeStaleWhenTheBudgetIsZero() throws Exception {
        HttpServer server = directoryStub("carrier");
        server.start();
        ResolverProperties props = props(false);
        props.getMirror().setUpstreamUrl("http://127.0.0.1:" + server.getAddress().getPort());
        props.getMirror().setDirectoryCacheTtl(Duration.ZERO);   // strict fail-closed
        RemoteDirectoryStore store = new RemoteDirectoryStore(props, new PhoneHasher(props), WebClient.builder());

        assertThat(store.homeserverIdForUsername("alice")).contains("carrier");
        server.stop(0);
        assertThatThrownBy(() -> store.homeserverIdForUsername("alice"))
                .isInstanceOf(DirectoryUnavailableException.class);
    }

    private static HttpServer directoryStub(String homeserverId) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        byte[] body = ("{\"homeserverId\":\"" + homeserverId + "\"}").getBytes(StandardCharsets.UTF_8);
        server.createContext("/directory/lookup", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        return server;
    }

    private static ResolverProperties props(boolean failOpen) {
        ResolverProperties props = new ResolverProperties();
        props.getDirectory().setPepper("test-pepper");
        props.getDirectory().setFailOpenOnLookupError(failOpen);
        props.getMirror().setUpstreamUrl("http://127.0.0.1:9");
        return props;
    }
}
