package global.gua.resolver.placement.record;

import java.time.Instant;

/**
 * A decoded generation-1 placement record: one accountId, one roster homeserver id, and a validity window
 * (ADM-008 decision 7).
 *
 * <p>It binds nothing to an identifier. There is no phone, no phone hash, no Matrix user id and no
 * identifier of any kind in the object, which is what separates this per-account state from the directory
 * write ADM-001 L1b deleted, and what keeps replicated federation state clear of routing keys (L15).
 *
 * <p>This is the decoded view. The authoritative form is always the received bytes, which the resolver
 * stores verbatim and re-verifies from; these fields exist so the row can be indexed and compared.
 */
public record PlacementRecord(
        int version,
        int generation,
        String accountId,
        Origin origin,
        String homeserverId,
        Instant issuedAt,
        Instant notBefore,
        Instant notAfter) {

    /** Where the account's identifier came from; it must equal the root class inside the accountId. */
    public enum Origin {

        /** An account that predates account authority, carrying a bootstrap id (ADM-001 L5 path B1). */
        BOOTSTRAP(AccountId.CLASS_BOOTSTRAP),

        /** An account rooted in an on-device AccountGenesis (ADM-001 L4). */
        GENESIS(AccountId.CLASS_GENESIS);

        private final byte code;

        Origin(byte code) {
            this.code = code;
        }

        public byte code() {
            return code;
        }

        /** The origin for a wire byte, or null when the byte names none. */
        public static Origin of(byte code) {
            for (Origin origin : values()) {
                if (origin.code == code) {
                    return origin;
                }
            }
            return null;
        }
    }
}
