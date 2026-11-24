package global.gua.resolver.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "gua.resolver")
public class ResolverProperties {

    /** MIRROR serves an upstream authority's roster read-only, verified against the same keys and threshold. */
    public enum Mode { AUTHORITY, MIRROR }

    private Mode mode = Mode.AUTHORITY;
    private final Authority authority = new Authority();
    private final Mirror mirror = new Mirror();
    private final Directory directory = new Directory();
    private final Policy policy = new Policy();
    private final Claims claims = new Claims();
    private final Admin admin = new Admin();
    private final Abuse abuse = new Abuse();
    private final Roster roster = new Roster();
    private final Genesis genesis = new Genesis();
    private final Governance governance = new Governance();
    private final Placement placement = new Placement();
    private final DevHomeserver devHomeserver = new DevHomeserver();
    private final Cors cors = new Cors();

    public Mode getMode() { return mode; }
    public void setMode(Mode mode) { this.mode = mode; }
    public Authority getAuthority() { return authority; }
    public Mirror getMirror() { return mirror; }
    public Directory getDirectory() { return directory; }
    public Policy getPolicy() { return policy; }
    public Claims getClaims() { return claims; }
    public Admin getAdmin() { return admin; }
    public Abuse getAbuse() { return abuse; }
    public Roster getRoster() { return roster; }
    public Genesis getGenesis() { return genesis; }
    public Governance getGovernance() { return governance; }
    public Placement getPlacement() { return placement; }
    public DevHomeserver getDevHomeserver() { return devHomeserver; }
    public Cors getCors() { return cors; }

    public static class Authority {
        private int threshold = 1;
        private List<TrustedKey> trustedKeys = new ArrayList<>();
        /** Must be one of trustedKeys; AUTHORITY mode only. */
        private String signingKeyId;
        /** Ed25519, base64 PKCS#8; AUTHORITY mode only. */
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
        private String id;
        /** Ed25519 public key, base64 X.509. */
        private String publicKey;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getPublicKey() { return publicKey; }
        public void setPublicKey(String publicKey) { this.publicKey = publicKey; }
    }

    public static class Mirror {
        private String upstreamUrl;
        private Duration refreshInterval = Duration.ofMinutes(5);
        private String cacheFile;
        /** Bounds each upstream lookup so a stalled authority cannot exhaust the mirror's request threads. */
        private Duration lookupTimeout = Duration.ofSeconds(3);
        /**
         * How long a verified positive lookup may be served while the authority is unreachable. Negative
         * results are never served stale; zero disables stale serving.
         */
        private Duration directoryCacheTtl = Duration.ofMinutes(10);

        public String getUpstreamUrl() { return upstreamUrl; }
        public void setUpstreamUrl(String upstreamUrl) { this.upstreamUrl = upstreamUrl; }
        public Duration getRefreshInterval() { return refreshInterval; }
        public void setRefreshInterval(Duration refreshInterval) { this.refreshInterval = refreshInterval; }
        public String getCacheFile() { return cacheFile; }
        public void setCacheFile(String cacheFile) { this.cacheFile = cacheFile; }
        public Duration getLookupTimeout() { return lookupTimeout; }
        public void setLookupTimeout(Duration lookupTimeout) { this.lookupTimeout = lookupTimeout; }
        public Duration getDirectoryCacheTtl() { return directoryCacheTtl; }
        public void setDirectoryCacheTtl(Duration directoryCacheTtl) { this.directoryCacheTtl = directoryCacheTtl; }
    }

    public static class Admin {
        private String username = "admin";
        /** BCrypt hash; empty means no admin user exists, so {@code /authority/**} stays denied. */
        private String passwordHash = "";

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPasswordHash() { return passwordHash; }
        public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    }

    public static class Directory {
        /** Required on every node, identical across the fleet and identity-service, and not rotatable. */
        private String pepper;
        private boolean failOpenOnLookupError = false;

        public String getPepper() { return pepper; }
        public void setPepper(String pepper) { this.pepper = pepper; }
        public boolean isFailOpenOnLookupError() { return failOpenOnLookupError; }
        public void setFailOpenOnLookupError(boolean failOpenOnLookupError) {
            this.failOpenOnLookupError = failOpenOnLookupError;
        }
    }

    public static class Policy {
        /** When false, placement uses roster claims and deterministic fallback only. */
        private boolean enabled = false;
        private String file;
        private boolean requireSignatures = true;
        private int signatureThreshold = 1;
        /**
         * Ignored while {@code governance.required} is on, when only genesis governance keys verify bundles.
         * Empty falls back to authority.trusted-keys.
         */
        private List<TrustedKey> trustedKeys = new ArrayList<>();
        private String signingKeyId;
        /** Ed25519, base64 PKCS#8. */
        private String signingPrivateKey;
        private Duration refreshInterval = Duration.ofMinutes(1);

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getFile() { return file; }
        public void setFile(String file) { this.file = file; }
        public boolean isRequireSignatures() { return requireSignatures; }
        public void setRequireSignatures(boolean requireSignatures) { this.requireSignatures = requireSignatures; }
        public int getSignatureThreshold() { return signatureThreshold; }
        public void setSignatureThreshold(int signatureThreshold) { this.signatureThreshold = signatureThreshold; }
        public List<TrustedKey> getTrustedKeys() { return trustedKeys; }
        public void setTrustedKeys(List<TrustedKey> trustedKeys) { this.trustedKeys = trustedKeys; }
        public String getSigningKeyId() { return signingKeyId; }
        public void setSigningKeyId(String signingKeyId) { this.signingKeyId = signingKeyId; }
        public String getSigningPrivateKey() { return signingPrivateKey; }
        public void setSigningPrivateKey(String signingPrivateKey) { this.signingPrivateKey = signingPrivateKey; }
        public Duration getRefreshInterval() { return refreshInterval; }
        public void setRefreshInterval(Duration refreshInterval) { this.refreshInterval = refreshInterval; }
    }

    public static class Claims {
        private String audience = "gua-resolver";
        private Duration maxClockSkew = Duration.ofMinutes(2);
        private Duration maxLifetime = Duration.ofMinutes(5);
        /** Persists nonces so routing claims cannot be replayed across resolver nodes. */
        private boolean replayProtectionEnabled = true;
        /** Subject must equal the request phone, so a captured envelope cannot be replayed for another number. */
        private boolean requireSubjectBinding = true;
        private Duration replayCleanupInterval = Duration.ofMinutes(10);
        /**
         * Empty rejects every envelope while {@code governance.required} is on; otherwise empty falls back to
         * the policy keys, then the authority keys.
         */
        private List<TrustedKey> trustedKeys = new ArrayList<>();

        public String getAudience() { return audience; }
        public void setAudience(String audience) { this.audience = audience; }
        public Duration getMaxClockSkew() { return maxClockSkew; }
        public void setMaxClockSkew(Duration maxClockSkew) { this.maxClockSkew = maxClockSkew; }
        public Duration getMaxLifetime() { return maxLifetime; }
        public void setMaxLifetime(Duration maxLifetime) { this.maxLifetime = maxLifetime; }
        public boolean isReplayProtectionEnabled() { return replayProtectionEnabled; }
        public void setReplayProtectionEnabled(boolean replayProtectionEnabled) {
            this.replayProtectionEnabled = replayProtectionEnabled;
        }
        public boolean isRequireSubjectBinding() { return requireSubjectBinding; }
        public void setRequireSubjectBinding(boolean requireSubjectBinding) {
            this.requireSubjectBinding = requireSubjectBinding;
        }
        public Duration getReplayCleanupInterval() { return replayCleanupInterval; }
        public void setReplayCleanupInterval(Duration replayCleanupInterval) {
            this.replayCleanupInterval = replayCleanupInterval;
        }
        public List<TrustedKey> getTrustedKeys() { return trustedKeys; }
        public void setTrustedKeys(List<TrustedKey> trustedKeys) { this.trustedKeys = trustedKeys; }
    }

    public static class Abuse {
        /** Rate limits only; does not affect traceEnabled. */
        private boolean enabled = true;
        private int clientLimitForPeriod = 20;
        private Duration clientRefreshPeriod = Duration.ofMinutes(1);
        private int clientBurst = 20;
        private int globalLimitForPeriod = 200;
        private Duration globalRefreshPeriod = Duration.ofSeconds(1);
        private int globalBurst = 200;
        private long maxTrackedClients = 10_000;
        private Duration clientExpiry = Duration.ofMinutes(5);
        private boolean traceEnabled = false;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getClientLimitForPeriod() { return clientLimitForPeriod; }
        public void setClientLimitForPeriod(int v) { this.clientLimitForPeriod = v; }
        public Duration getClientRefreshPeriod() { return clientRefreshPeriod; }
        public void setClientRefreshPeriod(Duration v) { this.clientRefreshPeriod = v; }
        public int getClientBurst() { return clientBurst; }
        public void setClientBurst(int v) { this.clientBurst = v; }
        public int getGlobalLimitForPeriod() { return globalLimitForPeriod; }
        public void setGlobalLimitForPeriod(int v) { this.globalLimitForPeriod = v; }
        public Duration getGlobalRefreshPeriod() { return globalRefreshPeriod; }
        public void setGlobalRefreshPeriod(Duration v) { this.globalRefreshPeriod = v; }
        public int getGlobalBurst() { return globalBurst; }
        public void setGlobalBurst(int v) { this.globalBurst = v; }
        public long getMaxTrackedClients() { return maxTrackedClients; }
        public void setMaxTrackedClients(long v) { this.maxTrackedClients = v; }
        public Duration getClientExpiry() { return clientExpiry; }
        public void setClientExpiry(Duration v) { this.clientExpiry = v; }
        public boolean isTraceEnabled() { return traceEnabled; }
        public void setTraceEnabled(boolean v) { this.traceEnabled = v; }
    }

    public static class Roster {
        /**
         * Excludes ACTIVE entries without a valid member self-signature from the roster, placement and
         * resolution, so every ACTIVE member must be attested before this is turned on.
         */
        private boolean requireMemberSignature = false;
        private Duration memberMaxLifetime = Duration.ofDays(400);

        public boolean isRequireMemberSignature() { return requireMemberSignature; }
        public void setRequireMemberSignature(boolean v) { this.requireMemberSignature = v; }
        public Duration getMemberMaxLifetime() { return memberMaxLifetime; }
        public void setMemberMaxLifetime(Duration v) { this.memberMaxLifetime = v; }
    }

    public static class Genesis {
        /** Unset runs without governance. */
        private String file;
        /** JSON array in chain order. */
        private String transitionsFile;
        /** Validated at startup so another validly signed genesis cannot replace the trust root. */
        private String expectedId;
        /**
         * The genesis id, or the hash of the last applied transition. Validated at startup to prevent key
         * rotation rollback, which the chain checks alone allow through a truncated transitions file.
         */
        private String expectedChainHead;

        public String getFile() { return file; }
        public void setFile(String file) { this.file = file; }
        public String getTransitionsFile() { return transitionsFile; }
        public void setTransitionsFile(String transitionsFile) { this.transitionsFile = transitionsFile; }
        public String getExpectedId() { return expectedId; }
        public void setExpectedId(String expectedId) { this.expectedId = expectedId; }
        public String getExpectedChainHead() { return expectedChainHead; }
        public void setExpectedChainHead(String head) { this.expectedChainHead = head; }
    }

    public static class Governance {
        /** When true, admissions land PENDING and served status changes only through a governance-signed epoch. */
        private boolean required = false;

        public boolean isRequired() { return required; }
        public void setRequired(boolean required) { this.required = required; }
    }

    public static class Placement {
        /** When false, no placement bean, endpoint or scheduled job exists and the table is never touched. */
        private boolean enabled = false;
        private boolean ingestEnabled = false;
        /** Kept long because each logged checkpoint leaf moves new-account fallback placement. */
        private Duration checkpointInterval = Duration.ofHours(1);
        private Duration auditInterval = Duration.ofMinutes(5);
        private Duration metricsInterval = Duration.ofMinutes(1);
        private Duration maxValidity = Duration.ofDays(400);
        private int defaultPageSize = 100;
        private int maxPageSize = 500;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public boolean isIngestEnabled() { return ingestEnabled; }
        public void setIngestEnabled(boolean ingestEnabled) { this.ingestEnabled = ingestEnabled; }
        public Duration getCheckpointInterval() { return checkpointInterval; }
        public void setCheckpointInterval(Duration v) { this.checkpointInterval = v; }
        public Duration getAuditInterval() { return auditInterval; }
        public void setAuditInterval(Duration v) { this.auditInterval = v; }
        public Duration getMetricsInterval() { return metricsInterval; }
        public void setMetricsInterval(Duration v) { this.metricsInterval = v; }
        public Duration getMaxValidity() { return maxValidity; }
        public void setMaxValidity(Duration v) { this.maxValidity = v; }
        public int getDefaultPageSize() { return defaultPageSize; }
        public void setDefaultPageSize(int v) { this.defaultPageSize = v; }
        public int getMaxPageSize() { return maxPageSize; }
        public void setMaxPageSize(int v) { this.maxPageSize = v; }
    }

    /** Seeded into the roster on first boot of an empty database. */
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

    /** Empty refuses every cross-origin call to the public endpoints. */
    public static class Cors {
        private List<String> allowedOrigins = new ArrayList<>();

        public List<String> getAllowedOrigins() { return allowedOrigins; }
        public void setAllowedOrigins(List<String> allowedOrigins) {
            this.allowedOrigins = allowedOrigins == null ? new ArrayList<>() : allowedOrigins;
        }
    }
}
