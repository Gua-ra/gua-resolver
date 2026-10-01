package global.gua.resolver.config;

import java.util.ArrayList;
import java.util.List;

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

/** Deny by default; {@code /authority/**} needs ADMIN. /error is permitted so a public 404 is not a 401. */
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

    /** Defining this bean disables Spring Boot's generated user. */
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
