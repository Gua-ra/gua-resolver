-- Migration plan Phase 4 (ADM-001 L6, ADM-008 decision 7): generation-1 placement records, in shadow mode.
-- One accountId, one homeserver, signed by that homeserver's roster membership key. Additive: nothing reads
-- this table on the resolution path, and the whole feature is off unless gua.resolver.placement.enabled is
-- on, so applying this migration changes no behaviour by itself.

-- The account_id is the primary key, which is what makes "one accountId has one home" a property of the
-- schema rather than of the code above it: a second homeserver's claim collides instead of overwriting.
-- record_b64 and signature_b64 hold the bytes exactly as they were received, because the signature covers
-- those bytes and a re-encoding would not be the object that was signed (ADM-001 L4). The decoded columns
-- beside them exist only so the row can be indexed and compared.
-- No identifier appears here: no phone, no phone hash, no Matrix user id (ADM-001 L4, L15).
-- Plain types and a plain index only, so the H2 unit profile, the hand-mirrored test schema and Postgres
-- all agree.
CREATE TABLE placement_record (
    account_id     VARCHAR(64)  PRIMARY KEY,        -- canonical "ga1" + base32 id, re-derived from the bytes
    homeserver_id  VARCHAR(64)  NOT NULL,           -- roster_entry.id, never the Matrix domain
    generation     INTEGER      NOT NULL,           -- 1 in this phase
    origin         VARCHAR(16)  NOT NULL,           -- GENESIS | BOOTSTRAP, equal to the id's class byte
    issued_at      TIMESTAMP    NOT NULL,           -- from the signed bytes; the re-issue ordering key
    not_before     TIMESTAMP    NOT NULL,
    not_after      TIMESTAMP    NOT NULL,
    record_b64     TEXT         NOT NULL,           -- canonical bytes as received, base64url
    signature_b64  TEXT         NOT NULL,           -- detached Ed25519 signature over exactly those bytes
    received_at    TIMESTAMP    NOT NULL
);

-- The reconciliation read path: one homeserver's records, paged by account_id.
CREATE INDEX ix_placement_record_hs ON placement_record (homeserver_id);
