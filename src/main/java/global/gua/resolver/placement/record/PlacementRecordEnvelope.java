/*
 * Copyright 2026 Gua
 */
package global.gua.resolver.placement.record;

/** record is unpadded base64url, the only accepted spelling. Both fields are served verbatim. */
public record PlacementRecordEnvelope(String record, String signature) {}
