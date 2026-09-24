/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.verify;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import global.gua.resolver.account.authority.AccountAuthorityHeadEnvelope;
import global.gua.resolver.account.authority.AccountAuthorityHeadException;
import global.gua.resolver.account.authority.AccountAuthorityHeadProof;
import global.gua.resolver.account.authority.AccountAuthorityHeadRejection;
import global.gua.resolver.account.authority.AuthorityHeadFixtures;
import global.gua.resolver.config.ResolverProperties;
import global.gua.resolver.crypto.Ed25519;
import global.gua.resolver.crypto.MerkleTree;
import global.gua.resolver.domain.Homeserver;
import global.gua.resolver.roster.RosterEntry;
import global.gua.resolver.roster.RosterSigner;
import global.gua.resolver.roster.SignedRoster;
import global.gua.resolver.roster.TransparencyLeaf;
import global.gua.resolver.roster.TransparencyLog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The verifier ADM-009 decision 12 was waiting for: given a head an account's own homeserver served, check that
 * the same head was published, signed and logged.
 *
 * <p>Every test below is an attack rather than a happy path variation, because the only thing that makes the
 * leaf worth appending is what the check refuses. The three the sub-phase names explicitly:
 * <ul>
 *   <li>a head the log does not carry ({@code leaf_not_included});</li>
 *   <li>a head under another account ({@code account_mismatch});</li>
 *   <li>a forged head or a replayed leaf ({@code bad_signature}, {@code payload_hash_mismatch},
 *       {@code leaf_hash_mismatch}, {@code leaf_type_mismatch}, {@code head_seq_mismatch}).</li>
 * </ul>
 *
 * <p>The log here is an in-memory tree built through the same {@code TransparencyLeaf} and {@code MerkleTree}
 * functions the server appends with, so a test can hold both a log that carries a leaf and one that does not.
 */
class AccountAuthorityHeadCheckTest {

    /** The resolver authority key: the trust root a client pins out of band. */
    private static final Ed25519.KeyPairB64 AUTHORITY = Ed25519.generate();

    /** Roster membership keys: what a homeserver signs a published head with. */
    private static final Ed25519.KeyPairB64 HS_ONE = Ed25519.generate();
    private static final Ed25519.KeyPairB64 HS_TWO = Ed25519.generate();

    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.MILLIS);
    private static final String ACCOUNT = AuthorityHeadFixtures.bootstrapAccountId("check-a");
    private static final String OTHER_ACCOUNT = AuthorityHeadFixtures.bootstrapAccountId("check-b");

    private final AuthorityHeadFixtures.FakeLog log = new AuthorityHeadFixtures.FakeLog();

    // --- the check itself ---

    @Test
    void aPublishedAndLoggedHeadVerifies() {
        Published head = publish(ACCOUNT, "head-1", 4, "hs-one", HS_ONE);

        AccountAuthorityHeadCheck.Result result = verifier().verifyAccountAuthorityHead(
                expected(ACCOUNT, "head-1", 4), proofFor(head),
                AccountAuthorityHeadCheck.Consistency.none(), signedRoster(), NOW);

        assertThat(result.head().accountId()).isEqualTo(ACCOUNT);
        assertThat(result.head().headSeq()).isEqualTo(4);
        assertThat(result.head().homeserverId()).isEqualTo("hs-one");
        assertThat(result.leafIndex()).isEqualTo(head.leafIndex);
        assertThat(result.checkpoint()).isEqualTo(log.checkpoint());
    }

    @Test
    void aHeadTheLogDoesNotCarryIsRefused() {
        // The log is busy with other leaves and the head was never appended. The proof is built as favourably as
        // a dishonest server could make it: a leaf whose hash really is the hash of its own fields, and a real
        // audit path taken from the tree. The only thing missing is the leaf being in that tree.
        log.append(TransparencyLog.MEMBER_ATTEST, "hs-one", "aa", NOW.toEpochMilli());
        log.append("POLICY_PUBLISH", null, "bb", NOW.toEpochMilli());
        log.append(TransparencyLog.MEMBERSHIP_EPOCH, null, "cc", NOW.toEpochMilli());

        byte[] canonical = AuthorityHeadFixtures.canonical(ACCOUNT,
                AuthorityHeadFixtures.headHash("unlogged"), 2, "hs-one", NOW);
        AccountAuthorityHeadEnvelope envelope = AuthorityHeadFixtures.envelope(canonical, HS_ONE);
        AccountAuthorityHeadProof.Leaf invented = leaf(1, TransparencyLog.ACCOUNT_AUTHORITY, "hs-one",
                MerkleTree.sha256Hex(canonical), NOW.toEpochMilli());
        AccountAuthorityHeadProof proof = new AccountAuthorityHeadProof(envelope, invented,
                log.auditPath(1), log.checkpoint(), 1);

        refused(proof, expected(ACCOUNT, "unlogged", 2),
                AccountAuthorityHeadRejection.LEAF_NOT_INCLUDED);
    }

    @Test
    void aHeadUnderAnotherAccountIsRefused() {
        // Genuinely published, genuinely logged, genuinely signed by an active member: everything except being
        // this account's head. Without the final comparison a homeserver could answer every account with one
        // real proof.
        Published other = publish(OTHER_ACCOUNT, "head-b", 1, "hs-one", HS_ONE);

        refused(proofFor(other), expected(ACCOUNT, "head-b", 1),
                AccountAuthorityHeadRejection.ACCOUNT_MISMATCH);
    }

    @Test
    void aForgedHeadIsRefused() {
        Published head = publish(ACCOUNT, "head-1", 4, "hs-one", HS_ONE);

        // The bytes are edited after signing: the head hash now names a different chain record.
        byte[] tampered = AuthorityHeadFixtures.canonical(ACCOUNT,
                AuthorityHeadFixtures.headHash("forged"), 4, "hs-one", NOW);
        AccountAuthorityHeadProof forged = new AccountAuthorityHeadProof(
                new AccountAuthorityHeadEnvelope(AuthorityHeadFixtures.recordB64(tampered),
                        head.envelope.signature()),
                log.leaf(head.leafIndex), log.auditPath(head.leafIndex), log.checkpoint(), 1);
        refused(forged, expected(ACCOUNT, "forged", 4), AccountAuthorityHeadRejection.BAD_SIGNATURE);
    }

    @Test
    void aHeadSignedByAMemberOtherThanTheOneItNamesIsRefused() {
        // hs-two is an ACTIVE member with a valid roster key. It simply is not the key hs-one's heads verify
        // under, which is what stops one member publishing for another member's accounts.
        byte[] canonical = AuthorityHeadFixtures.canonical(ACCOUNT,
                AuthorityHeadFixtures.headHash("head-1"), 4, "hs-one", NOW);
        long index = log.appendHead(canonical, "hs-one", NOW);
        AccountAuthorityHeadProof proof = new AccountAuthorityHeadProof(
                AuthorityHeadFixtures.envelope(canonical, HS_TWO),
                log.leaf(index), log.auditPath(index), log.checkpoint(), 1);

        refused(proof, expected(ACCOUNT, "head-1", 4), AccountAuthorityHeadRejection.BAD_SIGNATURE);
    }

    @Test
    void aReplayedEarlierHeadIsRefused() {
        // Both heads are real and both are in the log. The homeserver serves seq 5 to the device and hands the
        // resolver's proof for seq 4, which is the revocation-hiding move this check has to catch.
        Published old = publish(ACCOUNT, "head-4", 4, "hs-one", HS_ONE);
        publish(ACCOUNT, "head-5", 5, "hs-one", HS_ONE);

        refused(proofFor(old), expected(ACCOUNT, "head-5", 5),
                AccountAuthorityHeadRejection.HEAD_HASH_MISMATCH);
        refused(proofFor(old), expected(ACCOUNT, "head-4", 5),
                AccountAuthorityHeadRejection.HEAD_SEQ_MISMATCH);
    }

    @Test
    void aLeafForSomeOtherObjectCannotStandInForAHeadLeaf() {
        Published head = publish(ACCOUNT, "head-1", 4, "hs-one", HS_ONE);
        long policyLeaf = log.append("POLICY_PUBLISH", null, "policy-root", NOW.toEpochMilli());

        AccountAuthorityHeadProof wrongType = new AccountAuthorityHeadProof(head.envelope,
                log.leaf(policyLeaf), log.auditPath(policyLeaf), log.checkpoint(), 1);
        refused(wrongType, expected(ACCOUNT, "head-1", 4),
                AccountAuthorityHeadRejection.LEAF_TYPE_MISMATCH);
    }

    @Test
    void aLeafThatCommitsOtherBytesIsRefused() {
        // A real ACCOUNT_AUTHORITY leaf, really in the tree, for another account's head, presented beside this
        // account's envelope. The payload hash is what ties a leaf to bytes, so this is where it fails.
        Published mine = publish(ACCOUNT, "head-1", 4, "hs-one", HS_ONE);
        Published theirs = publish(OTHER_ACCOUNT, "head-b", 1, "hs-one", HS_ONE);

        AccountAuthorityHeadProof mixed = new AccountAuthorityHeadProof(mine.envelope,
                log.leaf(theirs.leafIndex), log.auditPath(theirs.leafIndex), log.checkpoint(), 1);
        refused(mixed, expected(ACCOUNT, "head-1", 4),
                AccountAuthorityHeadRejection.PAYLOAD_HASH_MISMATCH);
    }

    @Test
    void aLeafHashTheServerMadeUpIsRefused() {
        // The leaf hash is recomputed from the leaf's own fields. A server that serves a hash which really is in
        // the tree, beside fields that do not produce it, is refused before inclusion is even considered.
        Published head = publish(ACCOUNT, "head-1", 4, "hs-one", HS_ONE);
        long decoy = log.append(TransparencyLog.MEMBER_ATTEST, "hs-one", "decoy", NOW.toEpochMilli());
        AccountAuthorityHeadProof.Leaf real = log.leaf(head.leafIndex);

        AccountAuthorityHeadProof lied = new AccountAuthorityHeadProof(head.envelope,
                new AccountAuthorityHeadProof.Leaf(real.index(), real.type(), real.publisherId(),
                        real.payloadHash(), real.recordedAtMillis(), log.leaf(decoy).leafHash()),
                log.auditPath(decoy), log.checkpoint(), 1);
        refused(lied, expected(ACCOUNT, "head-1", 4),
                AccountAuthorityHeadRejection.LEAF_HASH_MISMATCH);
    }

    @Test
    void aLeafAttributedToAnotherPublisherIsRefused() {
        byte[] canonical = AuthorityHeadFixtures.canonical(ACCOUNT,
                AuthorityHeadFixtures.headHash("head-1"), 4, "hs-one", NOW);
        // The leaf says hs-two published these bytes while the bytes say hs-one signed them. The leaf hash is
        // recomputed for the altered fields, so this cannot be caught by the hash check.
        long index = log.append(TransparencyLog.ACCOUNT_AUTHORITY, "hs-two",
                MerkleTree.sha256Hex(canonical), NOW.toEpochMilli());
        AccountAuthorityHeadProof proof = new AccountAuthorityHeadProof(
                AuthorityHeadFixtures.envelope(canonical, HS_ONE),
                log.leaf(index), log.auditPath(index), log.checkpoint(), 1);

        refused(proof, expected(ACCOUNT, "head-1", 4),
                AccountAuthorityHeadRejection.LEAF_PUBLISHER_MISMATCH);
    }

    // --- the trust root and the roster ---

    @Test
    void aRosterBelowTheThresholdVerifiesNothing() {
        Published head = publish(ACCOUNT, "head-1", 4, "hs-one", HS_ONE);
        SignedRoster unsigned = new SignedRoster(1, NOW, entries(RosterEntry.Status.ACTIVE),
                log.checkpoint(), List.of());

        assertThatThrownBy(() -> verifier().verifyAccountAuthorityHead(
                expected(ACCOUNT, "head-1", 4), proofFor(head),
                AccountAuthorityHeadCheck.Consistency.none(), unsigned, NOW))
                .isInstanceOf(AccountAuthorityHeadException.class)
                .extracting(e -> ((AccountAuthorityHeadException) e).rejection())
                .isEqualTo(AccountAuthorityHeadRejection.ROSTER_UNVERIFIED);
    }

    @Test
    void aHeadFromASuspendedPublisherIsRefused() {
        Published head = publish(ACCOUNT, "head-1", 4, "hs-one", HS_ONE);
        SignedRoster suspended = sign(entries(RosterEntry.Status.SUSPENDED), log.checkpoint());

        assertThatThrownBy(() -> verifier().verifyAccountAuthorityHead(
                expected(ACCOUNT, "head-1", 4), proofFor(head),
                AccountAuthorityHeadCheck.Consistency.none(), suspended, NOW))
                .isInstanceOf(AccountAuthorityHeadException.class)
                .extracting(e -> ((AccountAuthorityHeadException) e).rejection())
                .isEqualTo(AccountAuthorityHeadRejection.HOMESERVER_NOT_ACTIVE);
    }

    @Test
    void aHeadPastItsWindowReadsAsStaleRatherThanValid() {
        // This is the only signal a reader has that its homeserver stopped publishing. It cannot distinguish
        // silence from "nothing changed", but it can refuse to treat an old head as a current one.
        Published head = publish(ACCOUNT, "head-1", 4, "hs-one", HS_ONE);
        Instant wayLater = NOW.plus(AuthorityHeadFixtures.VALIDITY).plus(Duration.ofDays(1));

        assertThatThrownBy(() -> verifier().verifyAccountAuthorityHead(
                expected(ACCOUNT, "head-1", 4), proofFor(head),
                AccountAuthorityHeadCheck.Consistency.none(), signedRoster(), wayLater))
                .isInstanceOf(AccountAuthorityHeadException.class)
                .extracting(e -> ((AccountAuthorityHeadException) e).rejection())
                .isEqualTo(AccountAuthorityHeadRejection.EXPIRED);
    }

    // --- checkpoints ---

    @Test
    void aProofBuiltAtAnOlderCheckpointNeedsAConsistencyProof() {
        Published head = publish(ACCOUNT, "head-1", 4, "hs-one", HS_ONE);
        SignedRoster.LogCheckpoint atProofTime = log.checkpoint();
        // The log moves on between the two requests, which is the ordinary case.
        log.append(TransparencyLog.MEMBERSHIP_EPOCH, null, "later-epoch", NOW.toEpochMilli());
        log.append(TransparencyLog.MEMBER_ATTEST, "hs-one", "later-attest", NOW.toEpochMilli());
        SignedRoster roster = sign(entries(RosterEntry.Status.ACTIVE), log.checkpoint());

        AccountAuthorityHeadProof proof = new AccountAuthorityHeadProof(head.envelope,
                log.leaf(head.leafIndex), log.auditPath(head.leafIndex, (int) atProofTime.size()),
                atProofTime, 1);

        // Without the step, the checkpoint the path was built at is not one the reader can authenticate.
        refused(proof, expected(ACCOUNT, "head-1", 4), roster,
                AccountAuthorityHeadRejection.CHECKPOINT_NOT_EXTENDED);

        // With it, the reader can see that the signed root extends the one the proof was built at.
        AccountAuthorityHeadCheck.Consistency step = new AccountAuthorityHeadCheck.Consistency(
                log.consistencyProof((int) atProofTime.size(), log.size()), null, null);
        assertThat(verifier().verifyAccountAuthorityHead(expected(ACCOUNT, "head-1", 4), proof, step,
                roster, NOW).leafIndex()).isEqualTo(head.leafIndex);
    }

    @Test
    void aSignedCheckpointThatDoesNotExtendTheReadersOwnHistoryIsRefused() {
        Published head = publish(ACCOUNT, "head-1", 4, "hs-one", HS_ONE);

        // A checkpoint from a log this one is not an extension of: the reader saw a history that has since been
        // rewritten, which is exactly what its own stored checkpoint exists to detect.
        AuthorityHeadFixtures.FakeLog fork = new AuthorityHeadFixtures.FakeLog();
        fork.append(TransparencyLog.MEMBER_ATTEST, "hs-one", "fork-a", NOW.toEpochMilli());

        AccountAuthorityHeadCheck.Consistency history = new AccountAuthorityHeadCheck.Consistency(
                null, fork.checkpoint(), fork.auditPath(0));
        assertThatThrownBy(() -> verifier().verifyAccountAuthorityHead(
                expected(ACCOUNT, "head-1", 4), proofFor(head), history, signedRoster(), NOW))
                .isInstanceOf(AccountAuthorityHeadException.class)
                .extracting(e -> ((AccountAuthorityHeadException) e).rejection())
                .isEqualTo(AccountAuthorityHeadRejection.CHECKPOINT_NOT_EXTENDED);
    }

    @Test
    void aReadersOwnEarlierCheckpointIsBridgedWithItsProof() {
        log.append(TransparencyLog.MEMBER_ATTEST, "hs-one", "first", NOW.toEpochMilli());
        SignedRoster.LogCheckpoint lastSeen = log.checkpoint();
        Published head = publish(ACCOUNT, "head-1", 4, "hs-one", HS_ONE);

        AccountAuthorityHeadCheck.Consistency history = new AccountAuthorityHeadCheck.Consistency(
                null, lastSeen, log.consistencyProof((int) lastSeen.size(), log.size()));
        assertThat(verifier().verifyAccountAuthorityHead(expected(ACCOUNT, "head-1", 4), proofFor(head),
                history, signedRoster(), NOW).head().headSeq()).isEqualTo(4);
    }

    // --- helpers ---

    private record Published(AccountAuthorityHeadEnvelope envelope, long leafIndex) {}

    private Published publish(String accountId, String headSeed, long seq, String homeserverId,
                              Ed25519.KeyPairB64 key) {
        byte[] canonical = AuthorityHeadFixtures.canonical(accountId,
                AuthorityHeadFixtures.headHash(headSeed), seq, homeserverId, NOW);
        long index = log.appendHead(canonical, homeserverId, NOW);
        return new Published(AuthorityHeadFixtures.envelope(canonical, key), index);
    }

    private AccountAuthorityHeadProof proofFor(Published published) {
        return new AccountAuthorityHeadProof(published.envelope, log.leaf(published.leafIndex),
                log.auditPath(published.leafIndex), log.checkpoint(), 1);
    }

    private static AccountAuthorityHeadProof.Leaf leaf(long index, String type, String publisherId,
                                                       String payloadHash, long millis) {
        return new AccountAuthorityHeadProof.Leaf(index, type, publisherId, payloadHash, millis,
                TransparencyLeaf.hash(index, type, publisherId, payloadHash, millis));
    }

    private static AccountAuthorityHeadCheck.Expected expected(String accountId, String headSeed,
                                                               long seq) {
        return new AccountAuthorityHeadCheck.Expected(accountId,
                AuthorityHeadFixtures.headHash(headSeed), seq);
    }

    private void refused(AccountAuthorityHeadProof proof, AccountAuthorityHeadCheck.Expected expected,
                         AccountAuthorityHeadRejection rejection) {
        refused(proof, expected, signedRoster(), rejection);
    }

    private void refused(AccountAuthorityHeadProof proof, AccountAuthorityHeadCheck.Expected expected,
                         SignedRoster roster, AccountAuthorityHeadRejection rejection) {
        assertThatThrownBy(() -> verifier().verifyAccountAuthorityHead(expected, proof,
                AccountAuthorityHeadCheck.Consistency.none(), roster, NOW))
                .isInstanceOf(AccountAuthorityHeadException.class)
                .extracting(e -> ((AccountAuthorityHeadException) e).rejection())
                .isEqualTo(rejection);
    }

    private static ResolverVerifier verifier() {
        ResolverProperties.TrustedKey key = new ResolverProperties.TrustedKey();
        key.setId("authority-a");
        key.setPublicKey(AUTHORITY.publicKeyB64());
        return new ResolverVerifier(List.of(key), 1, List.of(), 1);
    }

    private SignedRoster signedRoster() {
        return sign(entries(RosterEntry.Status.ACTIVE), log.checkpoint());
    }

    private static List<RosterEntry> entries(RosterEntry.Status oneStatus) {
        List<RosterEntry> entries = new ArrayList<>();
        entries.add(new RosterEntry(homeserver("hs-one", HS_ONE), List.of(), NOW, oneStatus));
        entries.add(new RosterEntry(homeserver("hs-two", HS_TWO), List.of(), NOW,
                RosterEntry.Status.ACTIVE));
        return entries;
    }

    private static Homeserver homeserver(String id, Ed25519.KeyPairB64 key) {
        return new Homeserver(id, id + ".gua.test", "https://" + id, "https://account." + id, "BR", 1,
                true, key.publicKeyB64());
    }

    private static SignedRoster sign(List<RosterEntry> entries, SignedRoster.LogCheckpoint checkpoint) {
        ResolverProperties props = new ResolverProperties();
        props.getAuthority().setSigningKeyId("authority-a");
        props.getAuthority().setSigningPrivateKey(AUTHORITY.privateKeyB64());
        return new RosterSigner(props).sign(checkpoint.size(), NOW, entries, checkpoint);
    }
}
