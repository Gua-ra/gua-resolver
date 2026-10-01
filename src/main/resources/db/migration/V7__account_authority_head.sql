-- Copyright 2026 Gua
-- ADM-009 decision 12: the published head of an account's authority chain, signed by the roster membership key
-- of the homeserver that stores that chain and anchored as one ACCOUNT_AUTHORITY transparency-log leaf.
-- Additive: nothing reads this table on the resolution path, and the whole feature is off unless
-- gua.resolver.account-authority.enabled is on, so applying this migration changes no behaviour by itself.

-- The account_id is the primary key, which makes "one account has one published head" a property of the schema
-- rather than of the code above it: a second homeserver's claim collides instead of overwriting.
-- record_b64 and signature_b64 hold the bytes exactly as they were received, because the signature covers those
-- bytes and a re-encoding would not be the object that was signed (ADM-001 L4). payload_hash is the SHA-256 of
-- those bytes, which is the transparency-log leaf's payload, so the row names the leaf's content as well as its
-- index. The decoded columns beside them exist only so the row can be compared and ordered.
-- log_leaf_index is nullable on purpose: the row is written before its leaf is appended, so a crash in between
-- leaves a head that is stored and not yet anchored, which the proof read reports as such and re-presenting the
-- same head repairs. The other order would append a leaf, which cannot be retracted, for a head this node does
-- not serve.
-- No identifier appears here: no phone, no phone hash, no Matrix user id (ADM-001 L4, L15). The accountId is a
-- 256-bit hash and the head hash commits to a chain record this node does not hold.
-- Plain types and a plain index only, so the H2 unit profile, the hand-mirrored test schema and Postgres all
-- agree.
CREATE TABLE account_authority_head (
    account_id      VARCHAR(64)  PRIMARY KEY,       -- canonical "ga1" + base32 id, re-derived from the bytes
    homeserver_id   VARCHAR(64)  NOT NULL,          -- roster_entry.id of the publisher, never the Matrix domain
    head_hash       VARCHAR(64)  NOT NULL,          -- SHA-256 of the head chain record's canonical bytes, hex
    head_seq        BIGINT       NOT NULL,          -- chain sequence number of that record; forward only
    issued_at       TIMESTAMP    NOT NULL,          -- from the signed bytes; the tiebreak within one head_seq
    not_before      TIMESTAMP    NOT NULL,
    not_after       TIMESTAMP    NOT NULL,
    record_b64      TEXT         NOT NULL,          -- canonical bytes as received, base64url unpadded
    signature_b64   TEXT         NOT NULL,          -- detached Ed25519 signature over exactly those bytes
    payload_hash    VARCHAR(128) NOT NULL,          -- SHA-256 of record bytes, hex: the log leaf's payload
    log_leaf_index  BIGINT,                         -- the ACCOUNT_AUTHORITY leaf that committed them, or null
    received_at     TIMESTAMP    NOT NULL
);

-- Which accounts a homeserver publishes for: the operator's own reconciliation read, never a public listing.
CREATE INDEX ix_account_authority_head_hs ON account_authority_head (homeserver_id);
