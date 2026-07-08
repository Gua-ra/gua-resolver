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
 * {@code /resolve}, {@code /roster*}, {@code /policy/routing*}, health + docs are unauthenticated (rate
 * limited at the edge / by resilience4j). {@code /directory/entries} is unauthenticated at the transport
 * layer but authorised in the controller by a homeserver membership signature; {@code /directory/lookup} is
 * the mirror-facing, rate-limited, peppered-HMAC read. The {@code /authority/**} admin surface (admission,
 * status changes) requires the {@code ADMIN} role via HTTP Basic, and fails closed: with no admin password
 * hash configured there are no admin users, so those endpoints stay denied. Everything else is denied.
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
                                "/directory/entries", "/directory/lookup", "/actuator/**",
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
