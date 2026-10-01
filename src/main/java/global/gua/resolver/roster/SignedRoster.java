package global.gua.resolver.roster;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SignedRoster(
        long version,
        Instant issuedAt,
        List<RosterEntry> entries,
        LogCheckpoint logCheckpoint,
        List<AuthoritySignature> authoritySignatures) {

    public record LogCheckpoint(String merkleRoot, long size) {}

    public record AuthoritySignature(String authorityKeyId, String signatureB64) {}

    public List<RosterEntry> activeEntries() {
        return entries.stream().filter(RosterEntry::isActive).toList();
    }
}
