package global.gua.resolver.roster;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.domain.Homeserver;

import static org.assertj.core.api.Assertions.assertThat;

/** The member self-signature rules (ADM-007), each exercised against keys generated in memory. */
class MemberEntryVerifierTest {

    private static final Ed25519.KeyPairB64 KEY = Ed25519.generate();
    private static final Ed25519.KeyPairB64 NEXT = Ed25519.generate();
    private static final Instant NOT_BEFORE = Instant.parse("2026-09-01T00:00:00Z");
    private static final Instant NOT_AFTER = NOT_BEFORE.plus(Duration.ofDays(400));
    private static final Instant AT = Instant.parse("2026-09-11T12:00:00Z");

    private final MemberEntryVerifier verifier = new MemberEntryVerifier(MemberEntryVerifier.DEFAULT_MAX_LIFETIME);

    private static Homeserver homeserver(String signingKey, String baseUrl) {
        return new Homeserver("hs1", "hs1.gua.test", baseUrl, "https://account.hs1.gua.test/", "BR",
                1, true, signingKey, Homeserver.SearchVisibility.GLOBAL, List.of());
    }

    private static Homeserver homeserver() {
        return homeserver(KEY.publicKeyB64(), "https://matrix.hs1.gua.test");
    }

    private static MemberAttestation unsigned(String keyId, long sequence, Instant notBefore, Instant notAfter) {
        return new MemberAttestation(CanonicalMemberEntry.SCHEMA, CanonicalMemberEntry.ALG, keyId, sequence,
                notBefore, notAfter, List.of());
    }

    private static MemberAttestation signed(Homeserver hs, MemberAttestation m, Ed25519.KeyPairB64 key,
                                            String keyId) {
        return MemberEntrySigner.sign(hs, m, keyId, key.privateKeyB64());
    }

    private static MemberAttestation valid() {
        return signed(homeserver(), unsigned("k1", 1, NOT_BEFORE, NOT_AFTER), KEY, "k1");
    }

    @Test
    void aCorrectlySelfSignedEntryVerifies() {
        MemberEntryVerifier.Result r = verifier.verify(homeserver(), valid(), AT);

        assertThat(r.valid()).isTrue();
        assertThat(r.entryHash()).isEqualTo(CanonicalMemberEntry.hash(homeserver(), valid()));
    }

    @Test
    void noMemberBlockIsUnattestedNotInvalid() {
        assertThat(verifier.verify(homeserver(), null, AT).outcome())
                .isEqualTo(MemberEntryVerifier.Outcome.UNATTESTED);
    }

    @Test
    void aSignatureByADifferentKeyFails() {
        MemberAttestation byOther = signed(homeserver(), unsigned("k1", 1, NOT_BEFORE, NOT_AFTER),
                Ed25519.generate(), "k1");

        MemberEntryVerifier.Result r = verifier.verify(homeserver(), byOther, AT);

        assertThat(r.outcome()).isEqualTo(MemberEntryVerifier.Outcome.INVALID);
        assertThat(r.reason()).contains("does not verify");
    }

    @Test
    void aSignatureUnderAnotherKeyIdDoesNotCount() {
        MemberAttestation m = signed(homeserver(), unsigned("k1", 1, NOT_BEFORE, NOT_AFTER), KEY, "k-other");

        assertThat(verifier.verify(homeserver(), m, AT).reason()).contains("no signature by keyId k1");
    }

    @Test
    void aSubstitutedBaseUrlInvalidatesTheMemberSignature() {
        Homeserver substituted = homeserver(KEY.publicKeyB64(), "https://attacker.gua.test");

        MemberEntryVerifier.Result r = verifier.verify(substituted, valid(), AT);

        assertThat(r.valid()).isFalse();
        assertThat(r.reason()).contains("does not verify");
    }

    @Test
    void everySignedHomeserverFieldIsCovered() {
        MemberAttestation m = valid();
        Homeserver h = homeserver();
        List<Homeserver> tampered = List.of(
                new Homeserver("hs2", h.serverName(), h.baseUrl(), h.masIssuer(), h.region(), 1, true,
                        h.signingKey(), h.searchVisibility(), h.searchGroups()),
                new Homeserver(h.id(), "other.gua.test", h.baseUrl(), h.masIssuer(), h.region(), 1, true,
                        h.signingKey(), h.searchVisibility(), h.searchGroups()),
                new Homeserver(h.id(), h.serverName(), h.baseUrl(), "https://evil/", h.region(), 1, true,
                        h.signingKey(), h.searchVisibility(), h.searchGroups()),
                new Homeserver(h.id(), h.serverName(), h.baseUrl(), h.masIssuer(), null, 1, true,
                        h.signingKey(), h.searchVisibility(), h.searchGroups()),
                new Homeserver(h.id(), h.serverName(), h.baseUrl(), h.masIssuer(), "", 1, true,
                        h.signingKey(), h.searchVisibility(), h.searchGroups()),
                new Homeserver(h.id(), h.serverName(), h.baseUrl(), h.masIssuer(), h.region(), 1, true,
                        h.signingKey(), Homeserver.SearchVisibility.GROUP, List.of("g")));
        for (Homeserver t : tampered) {
            assertThat(verifier.verify(t, m, AT).valid()).as("tampered %s", t).isFalse();
        }
        // weight and acceptsNew are authority attributes, deliberately not member-signed.
        Homeserver reweighted = new Homeserver(h.id(), h.serverName(), h.baseUrl(), h.masIssuer(), h.region(),
                0, false, h.signingKey(), h.searchVisibility(), h.searchGroups());
        assertThat(verifier.verify(reweighted, m, AT).valid()).isTrue();
    }

    @Test
    void theValidityWindowIsEnforcedAtTheAcceptanceTime() {
        assertThat(verifier.verify(homeserver(), valid(), NOT_BEFORE.minusMillis(1)).reason())
                .contains("not valid before");
        assertThat(verifier.verify(homeserver(), valid(), NOT_AFTER.plusMillis(1)).reason())
                .contains("expired");
        assertThat(verifier.verify(homeserver(), valid(), NOT_BEFORE).valid()).isTrue();
        assertThat(verifier.verify(homeserver(), valid(), NOT_AFTER).valid()).isTrue();
    }

    @Test
    void aWindowLongerThanTheMaximumLifetimeOrBackwardsOrSubMillisecondIsRefused() {
        MemberAttestation tooLong = signed(homeserver(),
                unsigned("k1", 1, NOT_BEFORE, NOT_BEFORE.plus(Duration.ofDays(401))), KEY, "k1");
        assertThat(verifier.verify(homeserver(), tooLong, AT).reason()).contains("maximum lifetime");

        MemberAttestation backwards = signed(homeserver(), unsigned("k1", 1, NOT_AFTER, NOT_BEFORE), KEY, "k1");
        assertThat(verifier.verify(homeserver(), backwards, AT).reason()).contains("after notBefore");

        MemberAttestation micros = signed(homeserver(),
                unsigned("k1", 1, NOT_BEFORE.plusNanos(1_000), NOT_AFTER), KEY, "k1");
        assertThat(verifier.verify(homeserver(), micros, AT).reason()).contains("millisecond");

        MemberEntryVerifier shortLived = new MemberEntryVerifier(Duration.ofDays(30));
        assertThat(shortLived.verify(homeserver(), valid(), AT).reason()).contains("maximum lifetime");
    }

    @Test
    void schemaAlgSequenceAndSignatureShapeAreChecked() {
        MemberAttestation m = valid();
        assertThat(verifier.verify(homeserver(), new MemberAttestation("gua-member-entry.v2", m.alg(),
                m.keyId(), 1, NOT_BEFORE, NOT_AFTER, m.signatures()), AT).reason()).contains("schema");
        assertThat(verifier.verify(homeserver(), new MemberAttestation(m.schema(), "Ed448",
                m.keyId(), 1, NOT_BEFORE, NOT_AFTER, m.signatures()), AT).reason()).contains("alg");
        MemberAttestation zero = signed(homeserver(), unsigned("k1", 0, NOT_BEFORE, NOT_AFTER), KEY, "k1");
        assertThat(verifier.verify(homeserver(), zero, AT).reason()).contains("sequence");
        MemberAttestation dup = m.withSignatures(List.of(m.signatures().get(0), m.signatures().get(0)));
        assertThat(verifier.verify(homeserver(), dup, AT).reason()).contains("duplicate signature keyId");
    }

    @Test
    void aDuplicateSearchGroupHasNoEncodingAndIsRefused() {
        Homeserver grouped = new Homeserver("hs1", "hs1.gua.test", "https://matrix.hs1.gua.test",
                "https://account.hs1.gua.test/", "BR", 1, true, KEY.publicKeyB64(),
                Homeserver.SearchVisibility.GROUP, List.of("edu", "edu"));
        MemberAttestation m = new MemberAttestation(CanonicalMemberEntry.SCHEMA, CanonicalMemberEntry.ALG, "k1",
                1, NOT_BEFORE, NOT_AFTER, List.of(new MemberSignature("k1", "AAAA")));

        assertThat(verifier.verify(grouped, m, AT).reason()).contains("duplicate set element");
    }

    @Test
    void aRotationSignedByBothKeysIsAccepted() {
        MemberEntryVerifier.Prior prior = new MemberEntryVerifier.Prior("k1", KEY.publicKeyB64(), 1,
                CanonicalMemberEntry.hash(homeserver(), valid()));
        Homeserver rotated = homeserver(NEXT.publicKeyB64(), "https://matrix.hs1.gua.test");
        MemberAttestation m = signed(rotated, unsigned("k2", 2, NOT_BEFORE, NOT_AFTER), NEXT, "k2");
        m = signed(rotated, m, KEY, "k1");

        assertThat(verifier.verify(rotated, m, AT, prior).valid()).isTrue();
    }

    @Test
    void aRotationWithoutThePreviousKeysSignatureIsRefused() {
        MemberEntryVerifier.Prior prior = new MemberEntryVerifier.Prior("k1", KEY.publicKeyB64(), 1, null);
        Homeserver rotated = homeserver(NEXT.publicKeyB64(), "https://matrix.hs1.gua.test");
        MemberAttestation onlyNew = signed(rotated, unsigned("k2", 2, NOT_BEFORE, NOT_AFTER), NEXT, "k2");

        assertThat(verifier.verify(rotated, onlyNew, AT, prior).reason())
                .contains("not signed by the previous key");
        // Without prior state the same entry is self-consistent: continuity needs history (brief rule 5).
        assertThat(verifier.verify(rotated, onlyNew, AT).valid()).isTrue();

        // A signature labelled k1 but made by some other key does not stand in for the previous key.
        MemberAttestation forged = signed(rotated, onlyNew, Ed25519.generate(), "k1");
        assertThat(verifier.verify(rotated, forged, AT, prior).valid()).isFalse();
    }

    @Test
    void aRotationFromAnUnattestedEntryAcceptsAnyLabelForTheGenesisKey() {
        MemberEntryVerifier.Prior legacy = new MemberEntryVerifier.Prior(null, KEY.publicKeyB64(), 0, null);
        Homeserver rotated = homeserver(NEXT.publicKeyB64(), "https://matrix.hs1.gua.test");
        MemberAttestation m = signed(rotated, unsigned("k2", 1, NOT_BEFORE, NOT_AFTER), NEXT, "k2");
        m = signed(rotated, m, KEY, "genesis");

        assertThat(verifier.verify(rotated, m, AT, legacy).valid()).isTrue();
    }

    @Test
    void aRotatedKeyMustNotReuseThePreviousKeyId() {
        MemberEntryVerifier.Prior prior = new MemberEntryVerifier.Prior("k1", KEY.publicKeyB64(), 1, null);
        Homeserver rotated = homeserver(NEXT.publicKeyB64(), "https://matrix.hs1.gua.test");
        MemberAttestation m = signed(rotated, unsigned("k1", 2, NOT_BEFORE, NOT_AFTER), NEXT, "k1");

        assertThat(verifier.verify(rotated, m, AT, prior).reason()).contains("new keyId");
    }

    @Test
    void sequenceRegressionAndEquivocationAreRefused() {
        MemberAttestation m = valid();
        String hash = CanonicalMemberEntry.hash(homeserver(), m);

        MemberEntryVerifier.Prior ahead = new MemberEntryVerifier.Prior("k1", KEY.publicKeyB64(), 3, null);
        assertThat(verifier.verify(homeserver(), m, AT, ahead).reason()).contains("sequence regression");

        MemberEntryVerifier.Prior same = new MemberEntryVerifier.Prior("k1", KEY.publicKeyB64(), 1, hash);
        assertThat(verifier.verify(homeserver(), m, AT, same).valid()).isTrue();

        Homeserver moved = homeserver(KEY.publicKeyB64(), "https://matrix2.hs1.gua.test");
        MemberAttestation other = signed(moved, unsigned("k1", 1, NOT_BEFORE, NOT_AFTER), KEY, "k1");
        assertThat(verifier.verify(moved, other, AT, same).reason()).contains("already names a different entry");

        Homeserver rekeyed = homeserver(NEXT.publicKeyB64(), "https://matrix.hs1.gua.test");
        MemberAttestation sameSeqNewKey = signed(rekeyed, unsigned("k2", 1, NOT_BEFORE, NOT_AFTER), NEXT, "k2");
        sameSeqNewKey = signed(rekeyed, sameSeqNewKey, KEY, "k1");
        assertThat(verifier.verify(rekeyed, sameSeqNewKey, AT, same).reason()).contains("higher sequence");
    }

    @Test
    void anUnusableSigningKeyIsRefused() {
        Homeserver noKey = homeserver("", "https://matrix.hs1.gua.test");
        MemberAttestation m = new MemberAttestation(CanonicalMemberEntry.SCHEMA, CanonicalMemberEntry.ALG, "k1",
                1, NOT_BEFORE, NOT_AFTER, List.of(new MemberSignature("k1", "AAAA")));

        assertThat(verifier.verify(noKey, m, AT).reason()).contains("not an Ed25519 public key");
    }
}
