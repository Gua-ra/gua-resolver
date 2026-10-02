package global.gua.resolver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.scheduling.annotation.EnableScheduling;

import global.gua.resolver.config.ResolverProperties;

/**
 * gua-resolver: the federation routing front door. A client asks it before login which homeserver an
 * identifier leads to, and it serves the signed, transparency-logged roster of federated homeservers and
 * the signed routing policy. It serves and verifies routing information; it does not authenticate anyone
 * and never holds a credential.
 */
@SpringBootApplication
@EnableConfigurationProperties(ResolverProperties.class)
@EnableScheduling
public class ResolverApplication {
    public static void main(String[] args) {
        SpringApplication.run(ResolverApplication.class, args);
    }
}
