-- Test schema (H2/PostgreSQL mode), mirrors db/migration/V1 to V6 by hand. Flyway is disabled
-- in tests; Spring SQL init runs this. DROP-first so each test context starts clean.
-- SchemaParityTest applies the real migrations to one database and this script to another and compares the
-- resulting columns, so a drift between the two fails the build rather than a deployment.
DROP TABLE IF EXISTS roster_entry;
DROP TABLE IF EXISTS roster_member_history;
DROP TABLE IF EXISTS registry_epoch;
DROP TABLE IF EXISTS transparency_log;
DROP TABLE IF EXISTS directory_entry;
DROP TABLE IF EXISTS username_index;
DROP TABLE IF EXISTS routing_claim_nonce;
DROP TABLE IF EXISTS placement_record;

CREATE TABLE roster_entry (
    id             VARCHAR(64)  PRIMARY KEY,
    server_name    VARCHAR(255) NOT NULL,
    base_url       VARCHAR(512) NOT NULL,
    mas_issuer     VARCHAR(512) NOT NULL,
    region         VARCHAR(64),
    weight         INTEGER      NOT NULL DEFAULT 1,
    accepts_new    BOOLEAN      NOT NULL DEFAULT TRUE,
    signing_key    VARCHAR(255) NOT NULL,
    search_visibility VARCHAR(16) NOT NULL DEFAULT 'GLOBAL',
    search_groups_json TEXT      NOT NULL DEFAULT '[]',
    claims_json    TEXT         NOT NULL DEFAULT '[]',
    admitted_at    TIMESTAMP    NOT NULL,
    status         VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    member_key_id  VARCHAR(128),
    member_sequence BIGINT,
    member_not_before TIMESTAMP,
    member_not_after  TIMESTAMP,
    member_signatures_json TEXT,
    member_entry_hash VARCHAR(64),
    genesis_signing_key VARCHAR(255),
    genesis_key_proof TEXT,
    registry_epoch BIGINT,
    pending_status VARCHAR(16)
);
CREATE UNIQUE INDEX ux_roster_entry_server_name ON roster_entry (server_name);

CREATE TABLE registry_epoch (
    registry        VARCHAR(32)  NOT NULL,
    epoch           BIGINT       NOT NULL,
    genesis_id      VARCHAR(64)  NOT NULL,
    previous_hash   VARCHAR(64)  NOT NULL,
    epoch_hash      VARCHAR(64)  NOT NULL,
    issued_at       TIMESTAMP    NOT NULL,
    content_json    TEXT         NOT NULL,
    signatures_json TEXT         NOT NULL,
    accepted_at     TIMESTAMP    NOT NULL,
    log_leaf_index  BIGINT,
    PRIMARY KEY (registry, epoch)
);

CREATE TABLE roster_member_history (
    homeserver_id   VARCHAR(64)  NOT NULL,
    sequence        BIGINT       NOT NULL,
    key_id          VARCHAR(128) NOT NULL,
    signing_key     VARCHAR(255) NOT NULL,
    entry_json      TEXT         NOT NULL,
    entry_hash      VARCHAR(64)  NOT NULL,
    signatures_json TEXT         NOT NULL,
    accepted_at     TIMESTAMP    NOT NULL,
    log_leaf_index  BIGINT,
    PRIMARY KEY (homeserver_id, sequence)
);

CREATE TABLE transparency_log (
    leaf_index    BIGINT       PRIMARY KEY,
    event_type    VARCHAR(32)  NOT NULL,
    homeserver_id VARCHAR(64),
    payload_hash  VARCHAR(128) NOT NULL,
    leaf_hash     VARCHAR(128) NOT NULL,
    recorded_at   TIMESTAMP    NOT NULL
);

CREATE TABLE directory_entry (
    phone_hash    VARCHAR(64)  PRIMARY KEY,
    homeserver_id VARCHAR(64)  NOT NULL,
    updated_at    TIMESTAMP    NOT NULL
);
CREATE INDEX ix_directory_entry_hs ON directory_entry (homeserver_id);

CREATE TABLE username_index (
    username      VARCHAR(255) PRIMARY KEY,
    homeserver_id VARCHAR(64)  NOT NULL,
    updated_at    TIMESTAMP    NOT NULL
);

CREATE TABLE routing_claim_nonce (
    issuer        VARCHAR(512) NOT NULL,
    nonce         VARCHAR(128) NOT NULL,
    expires_at    TIMESTAMP    NOT NULL,
    first_seen_at TIMESTAMP    NOT NULL,
    PRIMARY KEY (issuer, nonce)
);
CREATE INDEX ix_routing_claim_nonce_expires ON routing_claim_nonce (expires_at);

CREATE TABLE placement_record (
    account_id     VARCHAR(64)  PRIMARY KEY,
    homeserver_id  VARCHAR(64)  NOT NULL,
    generation     INTEGER      NOT NULL,
    origin         VARCHAR(16)  NOT NULL,
    issued_at      TIMESTAMP    NOT NULL,
    not_before     TIMESTAMP    NOT NULL,
    not_after      TIMESTAMP    NOT NULL,
    record_b64     TEXT         NOT NULL,
    signature_b64  TEXT         NOT NULL,
    received_at    TIMESTAMP    NOT NULL
);
CREATE INDEX ix_placement_record_hs ON placement_record (homeserver_id);
