package global.gua.resolver.roster;

import java.time.Instant;
import java.util.List;

/**
 * The federation roster as published: a versioned, threshold-signed snapshot anchored to the transparency
 * log. Resolvers (including third-party mirrors) verify {@code authoritySignatures} (k-of-n) AND
 * {@code logCheckpoint} inclusion before trusting any entry. See docs/FEDERATION_ROUTING_DESIGN.md §5.
 *
 * @param version             monotonically increasing roster version
 * @param issuedAt            issuance timestamp
 * @param entries             the admitted homeservers
 * @param logCheckpoint       transparency-log checkpoint (Merkle root + tree size) this roster commits to
 * @param authoritySignatures detached Ed25519 signatures over (version,issuedAt,entries,logCheckpoint);
 *                            valid only if at least the configured threshold k are present and verify
 */
public record SignedRoster(
        long version,
        Instant issuedAt,
        List<RosterEntry> entries,
        LogCheckpoint logCheckpoint,
        List<AuthoritySignature> authoritySignatures) {

    /** A Merkle transparency-log checkpoint: the root hash over a tree of {@code size} membership events. */
    public record LogCheckpoint(String merkleRoot, long size) {}

    /** One directory-authority's detached signature. */
    public record AuthoritySignature(String authorityKeyId, String signatureB64) {}

    public List<RosterEntry> activeEntries() {
        return entries.stream().filter(RosterEntry::isActive).toList();
    }
}
