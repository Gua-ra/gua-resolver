/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.account.authority;

import java.time.Instant;

/**
 * A decoded {@code gua-account-authority-head.v1} object: one account's authority chain head as published by
 * the homeserver that stores that chain (ADM-009 decision 12).
 *
 * <p>It carries the accountId, the head record's hash, the head sequence number, the publishing homeserver's
 * roster id and a validity window. It carries no record bodies, no device keys and no identifier of any kind:
 * no phone, no phone hash, no Matrix user id. The chain records themselves stay on the homeserver, and this
 * object is only the commitment that says which head that homeserver was willing to publish and when.
 *
 * <p>What the object buys, and what it does not. A verifier that holds this object, its log leaf and the
 * signed root above it can tell that the head it was shown was published and logged, so a homeserver that
 * shows one device a chain and another device a different chain is now contradicting something it signed and
 * anchored. It cannot tell that this head is the account's <b>latest</b>: silence is indistinguishable from
 * no transition, because nothing compels publication and there is no non-membership proof (ADM-005
 * requirement 9). The window is what turns silence into a visible stale state rather than into proof.
 *
 * <p>This is the decoded view. The authoritative form is always the received bytes, which the resolver stores
 * verbatim and the leaf commits to.
 */
public record AccountAuthorityHead(
        int version,
        int suite,
        String accountId,
        String headHashHex,
        long headSeq,
        String homeserverId,
        Instant issuedAt,
        Instant notBefore,
        Instant notAfter) {
}
