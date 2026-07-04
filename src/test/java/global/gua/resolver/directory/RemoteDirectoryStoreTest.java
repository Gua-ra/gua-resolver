package global.gua.resolver.directory;

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

    private static ResolverProperties props(boolean failOpen) {
        ResolverProperties props = new ResolverProperties();
        props.getDirectory().setPepper("test-pepper");
        props.getDirectory().setFailOpenOnLookupError(failOpen);
        props.getMirror().setUpstreamUrl("http://127.0.0.1:9");
        return props;
    }
}
