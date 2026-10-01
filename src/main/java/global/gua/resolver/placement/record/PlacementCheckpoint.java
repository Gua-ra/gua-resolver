/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

import java.time.Instant;
import java.util.List;

import global.gua.resolver.roster.SignedRoster;

public record PlacementCheckpoint(String merkleRoot, long size, Instant issuedAt) {

    public record Signed(PlacementCheckpoint checkpoint, List<SignedRoster.AuthoritySignature> signatures) {}
}
