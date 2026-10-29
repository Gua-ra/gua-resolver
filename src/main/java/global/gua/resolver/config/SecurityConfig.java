package global.gua.resolver.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

/**
 * Explicit public allowlist plus deny by default.
 * <ul>
 *   <li>Public by design: {@code /resolve}, {@code /roster*}, {@code /policy/routing*}, {@code /policy/log},
 *       the directory lookup and checkpoint, {@code /.well-known/gua-federation}, {@code /registry/**},
 *       health and API docs. {@code /resolve} is rate limited by {@code ResolveAbuseFilter}, which runs
 *       ahead of this chain.</li>
 *   <li>{@code /placement/records} is public only while {@code gua.resolver.placement.enabled} is on. Its
 *       ingest is self-authenticating: a record is accepted only when it verifies under the roster signing
 *       key of the ACTIVE homeserver it names.</li>
 *   <li>{@code /authority/**} requires the {@code ADMIN} role via HTTP Basic and fails closed: with no
 *       admin password hash configured there are no admin users.</li>
 * </ul>
 *
 * <p>{@code /error} is permitted because Spring Security filters the ERROR dispatch too. Without it a public
 * endpoint that answers 404 reaches the caller as a 401 with an empty body. Permitting it opens nothing: a
 * denied request still renders as its own 401 or 403.
 */
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, ResolverProperties props) throws Exception {
        List<String> publicPaths = new ArrayList<>(List.of(
                "/resolve", "/roster", "/roster/log", "/roster/log/consistency",
                "/policy/routing", "/policy/routing/status", "/policy/log",
                "/directory/lookup", "/directory/checkpoint",
                "/.well-known/gua-federation", "/registry/**",
                "/actuator/**", "/error",
                "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html"));
        // Permitted under exactly the condition that maps the placement controller.
        if (props.getMode() == ResolverProperties.Mode.AUTHORITY && props.getPlacement().isEnabled()) {
            publicPaths.add("/placement/records");
            publicPaths.add("/placement/records/**");
        }
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(publicPaths.toArray(String[]::new)).permitAll()
                        .requestMatchers("/authority/**").hasRole("ADMIN")
                        .anyRequest().denyAll())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    /**
     * Cross-origin access for the web app: the public read endpoints and {@code POST /resolve}, only from
     * {@code gua.resolver.cors.allowed-origins}. With no origin configured every preflight is refused.
     * {@code /authority/**} and the placement ingest are never exposed.
     */
    @Bean
    FilterRegistrationBean<CorsFilter> resolverCorsFilter(ResolverProperties props) {
        List<String> origins = props.getCors().getAllowedOrigins().stream()
                .filter(o -> o != null && !o.isBlank()).map(String::trim).toList();
        FilterRegistrationBean<CorsFilter> registration =
                new FilterRegistrationBean<>(new CorsFilter(corsSource(origins)));
        registration.setName("resolverCorsFilter");
        registration.setEnabled(!origins.isEmpty());
        // Ahead of the /resolve rate limiter, so a preflight spends no token and a 429 still carries the header.
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER - 2);
        return registration;
    }

    private static UrlBasedCorsConfigurationSource corsSource(List<String> origins) {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration read = new CorsConfiguration();
        read.setAllowedOrigins(origins);
        read.setAllowedMethods(List.of("GET"));
        read.setAllowedHeaders(List.of("Accept", "Content-Type"));
        read.setMaxAge(3600L);
        for (String path : List.of("/roster", "/roster/log", "/roster/log/consistency", "/policy/routing",
                "/policy/log", "/directory/checkpoint", "/.well-known/gua-federation")) {
            source.registerCorsConfiguration(path, read);
        }
        CorsConfiguration resolve = new CorsConfiguration(read);
        resolve.setAllowedMethods(List.of("POST"));
        resolve.setExposedHeaders(List.of("Retry-After"));
        source.registerCorsConfiguration("/resolve", resolve);
        return source;
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
