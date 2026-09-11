package global.gua.resolver.abuse;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Key derivation from the remote address. Every address below is from the documentation ranges reserved by
 * RFC 5737 (192.0.2/24, 198.51.100/24, 203.0.113/24) and RFC 3849 (2001:db8::/32); none of them routes
 * anywhere. The forwarded chain is resolved by Tomcat's RemoteIpValve before this class runs;
 * {@link ClientKeyThroughTomcatTest} covers that against a real listener.
 */
class ClientKeyTest {

    @Test
    void theRemoteAddressIsTheKey() {
        assertThat(ClientKey.of("198.51.100.7")).isEqualTo("198.51.100.7");
        assertThat(ClientKey.of(" 198.51.100.7 ")).isEqualTo("198.51.100.7");

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("198.51.100.7");
        assertThat(ClientKey.of(request)).isEqualTo("198.51.100.7");
    }

    @Test
    void forwardedHeadersAreNeverReadEvenWhenPresent() {
        // Regression for the removed header rule. After the valve, whatever is left in X-Forwarded-For is the
        // caller-supplied part of the chain, so an address named there must neither pick a different bucket
        // nor reach a victim's.
        MockHttpServletRequest chain = new MockHttpServletRequest();
        chain.setRemoteAddr("198.51.100.7");
        chain.addHeader("X-Forwarded-For", "192.0.2.1, 203.0.113.9");
        assertThat(ClientKey.of(chain)).isEqualTo("198.51.100.7");

        MockHttpServletRequest victim = new MockHttpServletRequest();
        victim.setRemoteAddr("198.51.100.7");
        victim.addHeader("X-Forwarded-For", "203.0.113.9");
        assertThat(ClientKey.of(victim)).isEqualTo(ClientKey.of(chain)).isNotEqualTo("203.0.113.9");

        MockHttpServletRequest rfc7239 = new MockHttpServletRequest();
        rfc7239.setRemoteAddr("198.51.100.7");
        rfc7239.addHeader("Forwarded", "for=203.0.113.9");
        rfc7239.addHeader("X-Real-IP", "203.0.113.9");
        assertThat(ClientKey.of(rfc7239)).isEqualTo("198.51.100.7");
    }

    @Test
    void portSuffixesAreStripped() {
        assertThat(ClientKey.normalize("203.0.113.9:51234")).isEqualTo("203.0.113.9");
        assertThat(ClientKey.normalize("[2001:db8:1:2::9]:51234")).isEqualTo("2001:db8:1:2::/64");
        assertThat(ClientKey.normalize("[2001:db8:1:2::9]")).isEqualTo("2001:db8:1:2::/64");
    }

    @Test
    void ipv6IsKeyedByItsSlash64() {
        assertThat(ClientKey.normalize("2001:db8:1:2::9")).isEqualTo("2001:db8:1:2::/64");
        assertThat(ClientKey.normalize("2001:0db8:0001:0002:aaaa:bbbb:cccc:dddd")).isEqualTo("2001:db8:1:2::/64");
        assertThat(ClientKey.normalize("2001:DB8:1:2:ffff::1")).isEqualTo("2001:db8:1:2::/64");
        assertThat(ClientKey.normalize("2001:db8:1:2::9%eth0")).isEqualTo("2001:db8:1:2::/64");
        // a neighbouring /64 is a different client
        assertThat(ClientKey.normalize("2001:db8:1:3::9")).isEqualTo("2001:db8:1:3::/64");
        assertThat(ClientKey.normalize("::1")).isEqualTo("0:0:0:0::/64");
        // the form Tomcat reports the IPv6 loopback peer in
        assertThat(ClientKey.of("0:0:0:0:0:0:0:1")).isEqualTo("0:0:0:0::/64");
    }

    @Test
    void ipv4MappedIpv6KeysByTheEmbeddedIpv4() {
        // A dual-stack listener reports IPv4 peers this way; folding them all into 0:0:0:0::/64 would put
        // every IPv4 client in one bucket.
        assertThat(ClientKey.normalize("::ffff:203.0.113.9")).isEqualTo("203.0.113.9");
        assertThat(ClientKey.normalize("::ffff:cb00:7109")).isEqualTo("203.0.113.9");
        assertThat(ClientKey.normalize("0:0:0:0:0:ffff:203.0.113.9")).isEqualTo("203.0.113.9");
    }

    @Test
    void unparseableIpv6LookingTokensAreUsedVerbatimNotDroppedOrCollapsed() {
        assertThat(ClientKey.normalize("2001:db8::1::2")).isEqualTo("2001:db8::1::2");       // two "::"
        assertThat(ClientKey.normalize("2001:db8:zz::1")).isEqualTo("2001:db8:zz::1");       // non-hex
        assertThat(ClientKey.normalize("1:2:3:4:5:6:7:8:9")).isEqualTo("1:2:3:4:5:6:7:8:9"); // nine groups
        assertThat(ClientKey.normalize("::ffff:203.0.113.999")).isEqualTo("::ffff:203.0.113.999");
    }

    @Test
    void noAddressAtAllYieldsTheUnknownKey() {
        assertThat(ClientKey.of((String) null)).isEqualTo(ClientKey.UNKNOWN);
        assertThat(ClientKey.of("  ")).isEqualTo(ClientKey.UNKNOWN);
    }

    @Test
    void logHandleIsAShortStableHashThatNeverContainsTheKey() {
        String handle = ClientKey.logHandle("203.0.113.9");
        assertThat(handle).hasSize(12).matches("[0-9a-f]{12}");
        assertThat(handle).isEqualTo(ClientKey.logHandle("203.0.113.9"));
        assertThat(handle).isNotEqualTo(ClientKey.logHandle("203.0.113.10"));
        assertThat(handle).doesNotContain("203.0.113");
    }
}
