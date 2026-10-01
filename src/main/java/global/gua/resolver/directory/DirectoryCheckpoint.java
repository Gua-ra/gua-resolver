package global.gua.resolver.directory;

import java.time.Instant;
import java.util.List;

import global.gua.resolver.roster.SignedRoster;

public record DirectoryCheckpoint(String merkleRoot, long size, Instant issuedAt) {

    public record Signed(DirectoryCheckpoint checkpoint, List<SignedRoster.AuthoritySignature> signatures) {}
}
