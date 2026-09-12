/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterStore;
import global.gua.resolver.roster.SignedRoster;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

/**
 * The one refusal reason admission normally keeps out of reach, asserted anyway.
 *
 * <p>A roster entry reaches the verifier only after admission validated its key, so an entry whose signing
 * key will not decode should not exist. "Should not exist" is the reason to pin it rather than to skip it:
 * the rejection enum promises one reason per defect, and this reason is the one that catches a roster row
 * written by some future path that does not go through admission. The verifier is pure enough to test
 * directly, with a roster that holds exactly the broken entry.
 */
class PlacementRecordVerifierKeyTest {

    @Test
    void anEntryWhoseRosterKeyIsNotAUsableEd25519KeyRefusesTheRecord() {
        byte[] canonical = PlacementFixtures.canonical(
                PlacementFixtures.genesisAccountId("verifier-unusable-key"), "hs-broken", Instant.now());
        PlacementRecordEnvelope envelope =
                new PlacementRecordEnvelope(PlacementFixtures.recordB64(canonical), "AAAA");
        PlacementRecordVerifier verifier = new PlacementRecordVerifier(
                rosterHolding("hs-broken", "not-a-usable-key"), new ResolverProperties());

        PlacementRecordException refused = catchThrowableOfType(
                () -> verifier.verify(envelope, Instant.now()), PlacementRecordException.class);

        // Its own reason, not a bad_signature: an unusable key is this node's defect to fix, not the
        // caller's, and the two are answered differently on purpose.
        assertThat(refused).isNotNull();
        assertThat(refused.rejection()).isEqualTo(PlacementRecordRejection.SIGNER_KEY_UNUSABLE);
        assertThat(refused.reason()).isEqualTo("signer_key_unusable");
    }

    private static RosterStore rosterHolding(String homeserverId, String signingKey) {
        Homeserver homeserver = new Homeserver(homeserverId, homeserverId + ".gua.test",
                "https://" + homeserverId + ".gua.test",
                "https://account." + homeserverId + ".gua.test", "BR", 1, true, signingKey);
        SignedRoster roster = new SignedRoster(1L, Instant.now(),
                List.of(new RosterEntry(homeserver, List.of(), Instant.now(), RosterEntry.Status.ACTIVE)),
                new SignedRoster.LogCheckpoint("test-root", 1), List.of());
        return new RosterStore() {
            @Override
            public SignedRoster current() {
                return roster;
            }

            @Override
            public SignedRoster refresh() {
                return roster;
            }
        };
    }
}
