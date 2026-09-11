package global.gua.resolver.roster;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.domain.Homeserver;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * gua-roster.v1 must stay byte-identical across the member-attestation change: mirrors and clients that
 * verify the authority signature today keep verifying (ADM-007). The member block is additive JSON and is
 * outside CanonicalRoster, so attaching one must not move a single byte.
 */
class CanonicalRosterUnchangedTest {

    private static final Instant ADMITTED = Instant.ofEpochMilli(1_789_084_800_000L);

    private static Homeserver homeserver() {
        return new Homeserver("dev", "example.test", "https://example.test", "https://mas.example.test",
                "br", 5, true, "MCowBQYDK2VwAyEA", Homeserver.SearchVisibility.GROUP, List.of("b", "a"));
    }

    private static MemberAttestation member() {
        return new MemberAttestation(CanonicalMemberEntry.SCHEMA, CanonicalMemberEntry.ALG, "k1", 7,
                ADMITTED, ADMITTED.plusMillis(1000),
                List.of(new MemberSignature("k1", "c2lnbmF0dXJl")));
    }

    @Test
    void attachingAMemberAttestationDoesNotChangeTheSignedRosterBytes() {
        RosterEntry unattested = new RosterEntry(homeserver(), List.of(), ADMITTED, RosterEntry.Status.ACTIVE);
        RosterEntry attested = unattested.withMember(member());
        SignedRoster.LogCheckpoint checkpoint = new SignedRoster.LogCheckpoint("deadbeef", 3);

        byte[] without = CanonicalRoster.bytes(3, 1_789_084_800_000L, checkpoint, List.of(unattested));
        byte[] with = CanonicalRoster.bytes(3, 1_789_084_800_000L, checkpoint, List.of(attested));

        assertThat(with).isEqualTo(without);
    }

    /**
     * The exact bytes main produced for this roster, pinned as a literal so any future edit to
     * CanonicalRoster, RosterEntry or Homeserver that moves them fails here rather than in a client.
     */
    @Test
    void theCanonicalRosterFormIsPinnedByteForByte() {
        RosterEntry entry = new RosterEntry(homeserver(), List.of(), ADMITTED, RosterEntry.Status.ACTIVE)
                .withMember(member());
        byte[] bytes = CanonicalRoster.bytes(3, 1_789_084_800_000L,
                new SignedRoster.LogCheckpoint("deadbeef", 3), List.of(entry));

        String unit = Character.toString(0x1F);
        String expected = "gua-roster.v1\n"
                + "version=3\n"
                + "issuedAt=1789084800000\n"
                + "log=deadbeef:3\n"
                + String.join(unit, "dev", "example.test", "https://example.test",
                        "https://mas.example.test", "br", "5", "true", "MCowBQYDK2VwAyEA", "GROUP", "a|b",
                        "1789084800000", "ACTIVE", "[]")
                + "\n";

        assertThat(new String(bytes, StandardCharsets.UTF_8)).isEqualTo(expected);
    }
}
