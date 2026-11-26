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
 * Placement ingest is public because each record must verify under the key of the ACTIVE homeserver it names.
 * {@code /error} is permitted so a public 404 is not rewritten to an empty 401; denials still render as 401 or 403.
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
        // Must match the condition that maps the placement controller.
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

    /** {@code /authority/**} and placement ingest must never be exposed cross-origin. */
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

    /** Also disables Spring Boot's generated default user; with no password hash there are no users at all. */
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
