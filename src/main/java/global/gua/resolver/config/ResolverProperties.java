package global.gua.resolver.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * All {@code gua.resolver.*} configuration. A resolver runs in one of two modes:
 * <ul>
 *   <li><b>AUTHORITY</b> — owns the roster: admits homeservers, appends to the transparency log, and
 *       threshold-signs the published roster with its authority signing key.</li>
 *   <li><b>MIRROR</b> — pulls the signed roster from an upstream authority, verifies threshold signatures
 *       + log consistency, and serves a read-only copy (an institution running its own resolver).</li>
 * </ul>
 * Both modes verify against the same published {@code authority.trusted-keys} + {@code threshold}.
 */
@ConfigurationProperties(prefix = "gua.resolver")
public class ResolverProperties {

    public enum Mode { AUTHORITY, MIRROR }

    private Mode mode = Mode.AUTHORITY;
    private final Authority authority = new Authority();
    private final Mirror mirror = new Mirror();
    private final Directory directory = new Directory();
    private final DevHomeserver devHomeserver = new DevHomeserver();

    public Mode getMode() { return mode; }
    public void setMode(Mode mode) { this.mode = mode; }
    public Authority getAuthority() { return authority; }
    public Mirror getMirror() { return mirror; }
    public Directory getDirectory() { return directory; }
    public DevHomeserver getDevHomeserver() { return devHomeserver; }

    /** Authority trust root: the published key set (verify) + this node's signing key (authority mode). */
    public static class Authority {
        /** Minimum number of valid authority signatures required for a roster to be trusted (k of n). */
        private int threshold = 1;
        /** The published authority public keys (n). Every verifier checks against these. */
        private List<TrustedKey> trustedKeys = new ArrayList<>();
        /** This node's authority signing key id (must be one of trustedKeys); AUTHORITY mode only. */
        private String signingKeyId;
        /** This node's authority Ed25519 private key, base64 PKCS#8; AUTHORITY mode only. */
        private String signingPrivateKey;

        public int getThreshold() { return threshold; }
        public void setThreshold(int threshold) { this.threshold = threshold; }
        public List<TrustedKey> getTrustedKeys() { return trustedKeys; }
        public void setTrustedKeys(List<TrustedKey> trustedKeys) { this.trustedKeys = trustedKeys; }
        public String getSigningKeyId() { return signingKeyId; }
        public void setSigningKeyId(String signingKeyId) { this.signingKeyId = signingKeyId; }
        public String getSigningPrivateKey() { return signingPrivateKey; }
        public void setSigningPrivateKey(String k) { this.signingPrivateKey = k; }
    }

    public static class TrustedKey {
        /** Authority key id (stable label). */
        private String id;
        /** Ed25519 public key, base64 X.509. */
        private String publicKey;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getPublicKey() { return publicKey; }
        public void setPublicKey(String publicKey) { this.publicKey = publicKey; }
    }

    public static class Mirror {
        /** Upstream authority base URL whose /roster + /roster/log this mirror pulls. */
        private String upstreamUrl;
        /** How often the mirror re-pulls + re-verifies. */
        private Duration refreshInterval = Duration.ofMinutes(5);

        public String getUpstreamUrl() { return upstreamUrl; }
        public void setUpstreamUrl(String upstreamUrl) { this.upstreamUrl = upstreamUrl; }
        public Duration getRefreshInterval() { return refreshInterval; }
        public void setRefreshInterval(Duration refreshInterval) { this.refreshInterval = refreshInterval; }
    }

    public static class Directory {
        /** Shared secret pepper for the phone HMAC. MUST be set + identical across the fleet + identity-service. */
        private String pepper;

        public String getPepper() { return pepper; }
        public void setPepper(String pepper) { this.pepper = pepper; }
    }

    /** The single homeserver the authority seeds its roster with on first boot (Phase 1 / fresh DB). */
    public static class DevHomeserver {
        private String id = "dev";
        private String serverName = "gua.local";
        private String baseUrl = "https://matrix.gua.local";
        private String masIssuer = "https://account.gua.local";
        private String region = "dev";
        private String signingKey = "";  // the homeserver's Ed25519 public key (membership credential)

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getServerName() { return serverName; }
        public void setServerName(String serverName) { this.serverName = serverName; }
        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
        public String getMasIssuer() { return masIssuer; }
        public void setMasIssuer(String masIssuer) { this.masIssuer = masIssuer; }
        public String getRegion() { return region; }
        public void setRegion(String region) { this.region = region; }
        public String getSigningKey() { return signingKey; }
        public void setSigningKey(String signingKey) { this.signingKey = signingKey; }
    }
}
