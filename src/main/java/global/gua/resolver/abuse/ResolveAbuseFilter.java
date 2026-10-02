package global.gua.resolver.abuse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Applies {@link ResolveRateLimiter} to {@code /resolve} (registered for that path only, see
 * {@link AbuseControlsConfig}). It runs ahead of the security chain and never reads the request body, so a
 * refused request costs one cache lookup and reveals nothing: the 429 body is a constant, and no phone is
 * parsed, echoed or logged. The WARN on the first refusal per key per window carries a truncated hash of the
 * client key, never the address itself.
 */
public class ResolveAbuseFilter extends OncePerRequestFilter {

    static final String RATE_LIMITED_BODY =
            "{\"code\":\"rate_limited\",\"message\":\"too many requests, retry after the Retry-After interval\"}";

    private static final Logger log = LoggerFactory.getLogger(ResolveAbuseFilter.class);

    private final ResolveRateLimiter limiter;

    public ResolveAbuseFilter(ResolveRateLimiter limiter) {
        this.limiter = limiter;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String key = ClientKey.of(request);
        ResolveRateLimiter.Decision decision = limiter.check(key);
        if (decision.allowed()) {
            chain.doFilter(request, response);
            return;
        }
        if (decision.firstHitInWindow()) {
            log.warn("resolve rate limit reached scope={} client={} retryAfterSeconds={}",
                    decision.scope().name().toLowerCase(Locale.ROOT), ClientKey.logHandle(key),
                    decision.retryAfterSeconds());
        }
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(decision.retryAfterSeconds()));
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(RATE_LIMITED_BODY);
        response.flushBuffer();
    }
}
