package global.gua.resolver.directory;

import java.time.Instant;
import java.util.List;

import global.gua.resolver.roster.SignedRoster;

/**
 * A signed commitment to the directory state: a Merkle root over all (peppered-phone-hash -> homeserver) and
 * (username -> homeserver) mappings, plus the entry count and issuance time. Anchored in the transparency log
 * so a client can detect a change against the checkpoint it stored earlier. The raw phone graph is never
 * exported: only the root travels.
 */
public record DirectoryCheckpoint(String merkleRoot, long size, Instant issuedAt) {

    /** The directory checkpoint plus the authority's k-of-n signatures over its canonical bytes. */
    public record Signed(DirectoryCheckpoint checkpoint, List<SignedRoster.AuthoritySignature> signatures) {}
}
