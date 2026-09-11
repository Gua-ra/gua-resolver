package global.gua.resolver.governance;

/**
 * One detached Ed25519 signature by a governance key over a governance object's canonical bytes.
 * Signatures sit outside those bytes, so adding one never changes what the others cover.
 *
 * @param keyId        the governance key id that produced it
 * @param signatureB64 base64 Ed25519 signature
 */
public record GovernanceSignature(String keyId, String signatureB64) {}
