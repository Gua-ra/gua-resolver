/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.time.Instant;

/** Carries no phone, phone hash or Matrix user id. The received bytes, not this view, are authoritative. */
public record PlacementRecord(
        int version,
        int generation,
        String accountId,
        Origin origin,
        String homeserverId,
        Instant issuedAt,
        Instant notBefore,
        Instant notAfter) {

    /** Must equal the root class inside the accountId. */
    public enum Origin {

        BOOTSTRAP(AccountId.CLASS_BOOTSTRAP),

        GENESIS(AccountId.CLASS_GENESIS);

        private final byte code;

        Origin(byte code) {
            this.code = code;
        }

        public byte code() {
            return code;
        }

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
