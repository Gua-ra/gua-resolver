package global.gua.resolver.federationlog;

import java.util.List;

import global.gua.resolver.crypto.CanonicalEncoder;
import global.gua.resolver.governance.CanonicalOrder;

/**
 * The state after replaying a log prefix. A homeserver can update its own entry without a new membership
 * epoch, so the state names each homeserver's latest accepted entry next to the epochs.
 */
public record FederationState(
        String schema,
        String genesisId,
        String governanceChainHead,
        String homeserverEpochHash,
        List<MemberEntry> memberEntries,
        String witnessEpochHash) {

    public static final String SCHEMA = "gua-federation-state.v1";

    public record MemberEntry(String homeserverId, String entryHash) {}

    public FederationState {
        memberEntries = memberEntries == null ? List.of() : List.copyOf(memberEntries);
    }

    public void validateShape() {
        if (!SCHEMA.equals(schema)) {
            throw new FederationLogException("unsupported state schema: " + schema);
        }
        Checks.sha256Hex(genesisId, "genesisId");
        Checks.sha256Hex(governanceChainHead, "governanceChainHead");
        if (homeserverEpochHash != null) {
            Checks.sha256Hex(homeserverEpochHash, "homeserverEpochHash");
        }
        for (MemberEntry entry : memberEntries) {
            if (entry == null || entry.homeserverId() == null || entry.homeserverId().isBlank()) {
                throw new FederationLogException("a member entry needs a homeserverId");
            }
            Checks.sha256Hex(entry.entryHash(), "entryHash");
        }
        if (witnessEpochHash != null) {
            Checks.sha256Hex(witnessEpochHash, "witnessEpochHash");
        }
    }

    public byte[] canonicalBytes() {
        List<MemberEntry> sorted =
                CanonicalOrder.sortedUnique(memberEntries, MemberEntry::homeserverId, "member entry");
        CanonicalEncoder e = CanonicalEncoder.begin(SCHEMA)
                .string(genesisId)
                .string(governanceChainHead)
                .optionalString(homeserverEpochHash)
                .listCount(sorted.size());
        for (MemberEntry entry : sorted) {
            e.string(entry.homeserverId()).string(entry.entryHash());
        }
        return e.optionalString(witnessEpochHash).toByteArray();
    }

    public String hash() {
        return CanonicalEncoder.sha256Hex(canonicalBytes());
    }
}
