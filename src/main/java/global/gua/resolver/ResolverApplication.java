package global.gua.resolver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * gua-resolver — the federation routing front door.
 *
 * <p>Owns three concerns (see docs/FEDERATION_ROUTING_DESIGN.md):
 * <ul>
 *   <li><b>Resolution</b> — phone/username → which homeserver (read-mostly, cacheable, mirrorable).</li>
 *   <li><b>Roster</b> — the signed, transparency-logged set of federated homeservers.</li>
 *   <li><b>Placement engine</b> — a pluggable rule pipeline that decides where a new account lives;
 *       the decision is invoked by identity-service at provisioning time.</li>
 * </ul>
 *
 * <p>Deliberately separate from identity-service (the credential-holding IdP): this is the public,
 * horizontally-scalable, anyone-can-mirror front door.
 */
@SpringBootApplication
public class ResolverApplication {
    public static void main(String[] args) {
        SpringApplication.run(ResolverApplication.class, args);
    }
}
