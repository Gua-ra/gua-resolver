package global.gua.resolver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The resolver front door is public by design: {@code /resolve} and {@code /roster} are unauthenticated
 * (rate-limited at the edge / by resilience4j), and so are health + docs. Authority/admin write endpoints
 * (roster mutations) land under {@code /authority/**} and are locked down when they arrive.
 */
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/resolve", "/roster", "/actuator/**",
                                "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers("/authority/**").authenticated()
                        .anyRequest().permitAll());
        return http.build();
    }
}
