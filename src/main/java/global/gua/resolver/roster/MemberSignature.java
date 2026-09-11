package global.gua.resolver.roster;

/**
 * One detached Ed25519 signature over a member entry's {@code gua-member-entry.v1} bytes.
 *
 * @param keyId        the member key id that produced it
 * @param signatureB64 base64 Ed25519 signature
 */
public record MemberSignature(String keyId, String signatureB64) {}
