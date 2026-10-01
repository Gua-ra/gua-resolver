package global.gua.resolver.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "gua.resolver")
public class ResolverProperties {

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

    public static class Authority {
        private int threshold = 1;
        private List<TrustedKey> trustedKeys = new ArrayList<>();
        private String signingKeyId;
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
        private Duration lookupTimeout = Duration.ofSeconds(3);
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

    /** HTTP Basic credentials for {@code /authority/**}. */
    public static class Admin {
        private String username = "admin";
        private String passwordHash = "";

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPasswordHash() { return passwordHash; }
        public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    }

    public static class Directory {
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
        private boolean enabled = false;
        private String file;
        private boolean requireSignatures = true;
        private int signatureThreshold = 1;
        private List<TrustedKey> trustedKeys = new ArrayList<>();
        private String signingKeyId;
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
        private boolean replayProtectionEnabled = true;
        private boolean requireSubjectBinding = true;
        private Duration replayCleanupInterval = Duration.ofMinutes(10);
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
        private boolean requireMemberSignature = false;
        private Duration memberMaxLifetime = Duration.ofDays(400);

        public boolean isRequireMemberSignature() { return requireMemberSignature; }
        public void setRequireMemberSignature(boolean v) { this.requireMemberSignature = v; }
        public Duration getMemberMaxLifetime() { return memberMaxLifetime; }
        public void setMemberMaxLifetime(Duration v) { this.memberMaxLifetime = v; }
    }

    public static class Genesis {
        private String file;
        private String transitionsFile;
        private String expectedId;
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
        private boolean required = false;

        public boolean isRequired() { return required; }
        public void setRequired(boolean required) { this.required = required; }
    }

    public static class Placement {
        private boolean enabled = false;
        private boolean ingestEnabled = false;
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

    public static class DevHomeserver {
        private String id = "dev";
        private String serverName = "gua.local";
        private String baseUrl = "https://matrix.gua.local";
        private String masIssuer = "https://account.gua.local";
        private String region = "dev";
        private String signingKey = "";

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
