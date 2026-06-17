-- Test schema (H2/PostgreSQL mode), mirrors db/migration/V1__roster_log_directory.sql. Flyway is disabled
-- in tests; Spring SQL init runs this. DROP-first so each test context starts clean.
DROP TABLE IF EXISTS roster_entry;
DROP TABLE IF EXISTS transparency_log;
DROP TABLE IF EXISTS directory_entry;
DROP TABLE IF EXISTS username_index;

CREATE TABLE roster_entry (
    id             VARCHAR(64)  PRIMARY KEY,
    server_name    VARCHAR(255) NOT NULL,
    base_url       VARCHAR(512) NOT NULL,
    mas_issuer     VARCHAR(512) NOT NULL,
    region         VARCHAR(64),
    weight         INTEGER      NOT NULL DEFAULT 1,
    accepts_new    BOOLEAN      NOT NULL DEFAULT TRUE,
    signing_key    VARCHAR(255) NOT NULL,
    claims_json    TEXT         NOT NULL DEFAULT '[]',
    admitted_at    TIMESTAMP    NOT NULL,
    status         VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE'
);
CREATE UNIQUE INDEX ux_roster_entry_server_name ON roster_entry (server_name);

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
