/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

/**
 * One row of {@code account_authority_head}: the decoded fields the resolver indexes on, the received bytes
 * and signature held verbatim, and the index of the log leaf that committed them.
 *
 * <p>The verbatim pair is the authoritative copy. Reads serve it unchanged and the leaf commits its SHA-256,
 * so nothing a reader checks depends on this node having decoded the head the same way twice.
 *
 * <p>{@code logLeafIndex} is null only in the window between a row being written and its leaf being appended.
 * A head in that state is stored but not yet anchored, and the proof read says so rather than inventing an
 * index; re-presenting the same head repairs it.
 */
public record StoredAccountAuthorityHead(
        String accountId,
        String homeserverId,
        String headHashHex,
        long headSeq,
        Instant issuedAt,
        Instant notBefore,
        Instant notAfter,
        String recordB64,
        String signatureB64,
        String payloadHashHex,
        Long logLeafIndex,
        Instant receivedAt) {

    /** The signed envelope exactly as it arrived. */
    public AccountAuthorityHeadEnvelope envelope() {
        return new AccountAuthorityHeadEnvelope(recordB64, signatureB64);
    }

    /** The canonical bytes this row holds, decoded from the spelling they were received in. */
    public byte[] recordBytes() {
        return decode(Base64.getUrlDecoder(), recordB64);
    }

    /** The detached signature this row holds, decoded from the spelling it was received in. */
    public byte[] signatureBytes() {
        return decode(Base64.getDecoder(), signatureB64);
    }

    /**
     * Whether two rows carry the same signed object, compared as bytes rather than as transport spellings.
     *
     * <p>This is what makes a retry idempotent for a well-behaved publisher. The record field has one
     * canonical spelling and the verifier refuses every other, but the detached signature is plain base64,
     * whose padding a decoder treats as optional, so one signature can still arrive spelled two ways.
     * Comparing the strings would read that as a re-publication of the same head and refuse the retry as
     * stale.
     */
    public boolean sameSignedBytesAs(StoredAccountAuthorityHead other) {
        byte[] mine = recordBytes();
        byte[] theirs = other.recordBytes();
        byte[] mySignature = signatureBytes();
        byte[] theirSignature = other.signatureBytes();
        if (mine == null || theirs == null || mySignature == null || theirSignature == null) {
            return recordB64.equals(other.recordB64) && signatureB64.equals(other.signatureB64);
        }
        return Arrays.equals(mine, theirs) && Arrays.equals(mySignature, theirSignature);
    }

    /** The row a verified head becomes, before its leaf exists. */
    public static StoredAccountAuthorityHead of(AccountAuthorityHeadVerification.Verified verified,
                                                String payloadHashHex, Instant receivedAt) {
        AccountAuthorityHead head = verified.head();
        return new StoredAccountAuthorityHead(head.accountId(), head.homeserverId(), head.headHashHex(),
                head.headSeq(), head.issuedAt(), head.notBefore(), head.notAfter(),
                verified.envelope().record(), verified.envelope().signature(), payloadHashHex, null,
                receivedAt);
    }

    private static byte[] decode(Base64.Decoder decoder, String value) {
        try {
            return value == null ? null : decoder.decode(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
