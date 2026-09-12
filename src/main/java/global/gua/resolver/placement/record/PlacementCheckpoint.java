/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.time.Instant;
import java.util.List;

import global.gua.resolver.roster.SignedRoster;

/**
 * A signed commitment to the placement state: a Merkle root over every stored (accountId, homeserver,
 * origin) leaf, plus the record count and issuance time.
 *
 * <p>The root depends only on the records, not on the time, so the same state always produces the same root.
 * That is what lets the checkpoint be anchored once per changed root instead of once per record. It is an
 * assertion by the signer, not a proof that the state is correct, and no per-record inclusion proof is
 * served (ADM-001 L11).
 */
public record PlacementCheckpoint(String merkleRoot, long size, Instant issuedAt) {

    /** The checkpoint plus the authority's k-of-n signatures over its canonical bytes. */
    public record Signed(PlacementCheckpoint checkpoint, List<SignedRoster.AuthoritySignature> signatures) {}
}
