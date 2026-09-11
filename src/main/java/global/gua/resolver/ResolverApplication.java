package global.gua.resolver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

import global.gua.resolver.config.ResolverProperties;

/**
 * gua-resolver: the federation routing front door.
 *
 * <p>The service a client asks before login to find which homeserver an identifier leads to, and the
 * service that serves the signed, transparency-logged set of federated homeservers. It serves and verifies
 * routing information; it does not authenticate anyone. What the code on {@code main} does today:
 * <ul>
 *   <li><b>Resolution</b>: {@code POST /resolve}, called by the iOS and Android clients before login. An
 *       existing account is looked up in the directory first; otherwise the placement rule pipeline picks
 *       a homeserver to register at, per request, from the roster and the routing policy. The target is an
 *       answer backed by a committed placement record (ADM-001 L6).</li>
 *   <li><b>Roster</b>: the signed, transparency-logged set of federated homeservers.</li>
 *   <li><b>Routing policy</b>: signed policy bundles with delegated zones, split from roster membership.</li>
 * </ul>
 *
 * <p>Both deployed environments run a single node in AUTHORITY mode with one operator holding every key;
 * MIRROR mode exists and is covered by tests. Running a resolver grants no authority over the federation
 * (ADM-001 O12). identity-service is today the single credential store for every homeserver; under
 * ADM-001 L2 authentication moves to each homeserver, and the resolver never holds a credential. See
 * docs/architecture/gua-identity-and-federation.md and
 * docs/decisions/ADM-001-identifier-binding-placement-trust.md.
 */
@SpringBootApplication
@EnableConfigurationProperties(ResolverProperties.class)
@EnableScheduling
public class ResolverApplication {
    public static void main(String[] args) {
        SpringApplication.run(ResolverApplication.class, args);
    }
}
