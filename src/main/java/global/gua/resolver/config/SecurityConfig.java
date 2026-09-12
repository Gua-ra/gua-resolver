package global.gua.resolver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Explicit public allowlist plus deny-by-default. The resolver front door is public by design:
 * {@code /resolve}, {@code /roster*}, {@code /policy/routing*}, health + docs are unauthenticated.
 * {@code /resolve} is rate-limited per client and globally by {@code ResolveAbuseFilter}, registered for
 * that path only and ordered ahead of this chain; it still answers {@code exists} for any raw E.164, so it
 * remains an existence oracle, only no longer a free one (ADM-001 L16 requires layered controls that do not
 * assume an account session). {@code /directory/lookup} is the mirror-facing, rate-limited, peppered-HMAC
 * read; the directory has no write endpoint (ADM-001 L1b). {@code /.well-known/gua-federation} publishes the
 * pinned federation genesis and {@code /registry/**} the governance-signed registry epochs; both are public
 * by design, because a trust root nobody can fetch and compare out of band is not a trust root (ADM-001
 * L10). The {@code /authority/**} admin surface (admission, status changes, member attestation, epoch
 * submission) requires the {@code ADMIN} role via HTTP Basic, and fails closed: with no admin password hash
 * configured there are no admin users, so those endpoints stay denied. Everything else is denied.
 *
 * <p>{@code /error} is permitted because Spring Security filters the ERROR dispatch too, not only the
 * original request. Without it, the container's error render is itself denied, so a public endpoint that
 * answers 404 reaches the caller as a 401 with an empty body: "no genesis yet" and "no such epoch" both read
 * as "authenticate first", which is a misleading answer on endpoints that are public by design. Permitting
 * it does not open anything, because the status being rendered was already decided by the rules above: a
 * denied request still renders as its own 401 or 403.
 */
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/resolve", "/roster", "/roster/log", "/roster/log/consistency",
                                "/policy/routing", "/policy/routing/status", "/policy/log",
                                "/directory/lookup", "/directory/checkpoint",
                                "/.well-known/gua-federation", "/registry/**",
                                "/actuator/**", "/error",
                                "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers("/authority/**").hasRole("ADMIN")
                        .anyRequest().denyAll())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    /**
     * Admin identity for {@code /authority/**}. Defining this bean also disables Spring Boot's default
     * generated user. When no BCrypt password hash is configured there are simply no users, so authority
     * endpoints cannot be authenticated into (fail closed).
     */
    @Bean
    UserDetailsService adminUsers(ResolverProperties props, PasswordEncoder encoder) {
        String hash = props.getAdmin().getPasswordHash();
        if (hash == null || hash.isBlank()) {
            return new InMemoryUserDetailsManager();
        }
        return new InMemoryUserDetailsManager(
                User.withUsername(props.getAdmin().getUsername()).password(hash).roles("ADMIN").build());
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
