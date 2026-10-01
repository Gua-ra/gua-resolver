package global.gua.resolver.abuse;

import jakarta.servlet.DispatcherType;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.github.benmanes.caffeine.cache.Ticker;

import global.gua.resolver.config.ResolverProperties;
import io.micrometer.core.instrument.MeterRegistry;

@Configuration
public class AbuseControlsConfig {

    @Bean
    public ResolveRateLimiter resolveRateLimiter(ResolverProperties props, MeterRegistry metrics) {
        return new ResolveRateLimiter(props.getAbuse(), metrics, Ticker.systemTicker());
    }

    @Bean
    public FilterRegistrationBean<ResolveAbuseFilter> resolveAbuseFilter(ResolveRateLimiter limiter) {
        FilterRegistrationBean<ResolveAbuseFilter> registration =
                new FilterRegistrationBean<>(new ResolveAbuseFilter(limiter));
        registration.setName("resolveAbuseFilter");
        registration.addUrlPatterns("/resolve");
        registration.setDispatcherTypes(DispatcherType.REQUEST);
        registration.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER - 1);
        return registration;
    }
}
