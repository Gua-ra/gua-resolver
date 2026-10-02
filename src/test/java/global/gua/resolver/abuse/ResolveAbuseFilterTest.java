package global.gua.resolver.abuse;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import global.gua.resolver.config.ResolverProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import static org.assertj.core.api.Assertions.assertThat;

/** The servlet edge of the limiter: the 429 contract and what the WARN log does and does not contain. */
class ResolveAbuseFilterTest {

    private static final String PHONE = "+5511987654321";
    private static final String CLIENT = "client-a";

    private final FakeTicker ticker = new FakeTicker();
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private ResolveAbuseFilter filter;

    @BeforeEach
    void setUp() {
        ResolverProperties.Abuse p = new ResolverProperties.Abuse();
        p.setClientLimitForPeriod(2);
        p.setClientBurst(2);
        p.setClientRefreshPeriod(Duration.ofMinutes(1));
        filter = new ResolveAbuseFilter(new ResolveRateLimiter(p, new SimpleMeterRegistry(), ticker));
        logs.start();
        logger().addAppender(logs);
    }

    @AfterEach
    void tearDown() {
        logger().detachAppender(logs);
    }

    private static Logger logger() {
        return (Logger) LoggerFactory.getLogger(ResolveAbuseFilter.class);
    }

    private MockHttpServletRequest resolveRequest(String client) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/resolve");
        request.setRemoteAddr(client);
        request.setContentType("application/json");
        request.setContent(("{\"phone\":\"" + PHONE + "\"}").getBytes());
        return request;
    }

    private MockHttpServletResponse run(MockHttpServletRequest request, MockFilterChain chain) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        return response;
    }

    @Test
    void underTheLimitTheChainRunsAndOverItA429IsWrittenWithoutTouchingTheBody() throws Exception {
        MockFilterChain chain = new MockFilterChain();
        assertThat(run(resolveRequest(CLIENT), chain).getStatus()).isEqualTo(200);
        assertThat(chain.getRequest()).isNotNull();

        run(resolveRequest(CLIENT), new MockFilterChain());

        MockFilterChain blocked = new MockFilterChain();
        MockHttpServletResponse refused = run(resolveRequest(CLIENT), blocked);
        assertThat(blocked.getRequest()).as("the controller must never see a refused request").isNull();
        assertThat(refused.getStatus()).isEqualTo(429);
        assertThat(refused.getHeader(HttpHeaders.RETRY_AFTER)).matches("[1-9][0-9]*");
        assertThat(refused.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
        assertThat(refused.getContentType()).startsWith("application/json");
        assertThat(refused.getContentAsString())
                .isEqualTo(ResolveAbuseFilter.RATE_LIMITED_BODY)
                .contains("\"code\":\"rate_limited\"")
                .doesNotContain(PHONE)
                .doesNotContain("exists");
    }

    @Test
    void firstRefusalPerWindowLogsAWarnWithAHashedClientAndNeverThePhone() throws Exception {
        run(resolveRequest(CLIENT), new MockFilterChain());
        run(resolveRequest(CLIENT), new MockFilterChain());
        run(resolveRequest(CLIENT), new MockFilterChain());   // refused: WARN
        run(resolveRequest(CLIENT), new MockFilterChain());   // refused again in the same window: silent

        List<ILoggingEvent> warns = logs.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
        assertThat(warns).hasSize(1);
        String line = warns.get(0).getFormattedMessage();
        assertThat(line).contains("scope=client")
                .contains("client=" + ClientKey.logHandle(CLIENT))
                .doesNotContain(PHONE)
                .doesNotContain(CLIENT);

        ticker.advance(Duration.ofMinutes(1));                // a full period: the burst of 2 is back
        run(resolveRequest(CLIENT), new MockFilterChain());   // allowed
        run(resolveRequest(CLIENT), new MockFilterChain());   // allowed
        run(resolveRequest(CLIENT), new MockFilterChain());   // refused in a new window: WARN again
        assertThat(logs.list.stream().filter(e -> e.getLevel() == Level.WARN)).hasSize(2);
    }

    @Test
    void clientsAreKeyedByTheRemoteAddressSoAnotherClientIsNotAffected() throws Exception {
        run(resolveRequest(CLIENT), new MockFilterChain());
        run(resolveRequest(CLIENT), new MockFilterChain());
        assertThat(run(resolveRequest(CLIENT), new MockFilterChain()).getStatus()).isEqualTo(429);
        assertThat(run(resolveRequest("client-b"), new MockFilterChain()).getStatus()).isEqualTo(200);
    }
}
