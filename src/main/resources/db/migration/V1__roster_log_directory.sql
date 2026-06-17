-- gua-resolver persistence: the authority-owned roster, the append-only transparency log, and the shared
-- phone->homeserver directory. Portable SQL (Postgres in prod, H2/PostgreSQL-mode in tests).
-- See docs/FEDERATION_ROUTING_DESIGN.md §4 (directory) and §5 (roster + transparency log).

-- The set of admitted homeservers. Authority mode is the source of truth here; mirrors never write it
-- (they pull the signed snapshot). claims_json is the homeserver's authorised ClaimPredicate list.
CREATE TABLE roster_entry (
    id             VARCHAR(64)  PRIMARY KEY,         -- stable federation id (NOT the Matrix domain)
    server_name    VARCHAR(255) NOT NULL,            -- Matrix server_name
    base_url       VARCHAR(512) NOT NULL,
    mas_issuer     VARCHAR(512) NOT NULL,
    region         VARCHAR(64),
    weight         INTEGER      NOT NULL DEFAULT 1,
    accepts_new    BOOLEAN      NOT NULL DEFAULT TRUE,
    signing_key    VARCHAR(255) NOT NULL,            -- Ed25519 public key (base64), the membership credential
    claims_json    TEXT         NOT NULL DEFAULT '[]',
    admitted_at    TIMESTAMP    NOT NULL,
    status         VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE'  -- ACTIVE | SUSPENDED | REVOKED
);

CREATE UNIQUE INDEX ux_roster_entry_server_name ON roster_entry (server_name);

-- The transparency log: one append-only, hash-chained row per membership event. leaf_hash is the RFC6962
-- leaf hash; the Merkle root over all leaves (ordered by leaf_index) is the published checkpoint root.
CREATE TABLE transparency_log (
    leaf_index    BIGINT       PRIMARY KEY,          -- 0-based, gap-free, append-only
    event_type    VARCHAR(32)  NOT NULL,             -- ADMIT | UPDATE | SUSPEND | REVOKE | AUTHORITY_CHANGE
    homeserver_id VARCHAR(64),
    payload_hash  VARCHAR(128) NOT NULL,             -- SHA-256 (hex) of the event's canonical payload
    leaf_hash     VARCHAR(128) NOT NULL,             -- RFC6962 leaf hash (hex)
    recorded_at   TIMESTAMP    NOT NULL
);

-- The shared phone->homeserver directory. The phone is stored ONLY as a peppered HMAC (never raw); each
-- homeserver writes only rows for accounts it hosts (authenticated by its roster signing key). Never bulk
-- exported — mirrors query it (rate-limited), they do not replicate it.
CREATE TABLE directory_entry (
    phone_hash    VARCHAR(64)  PRIMARY KEY,          -- peppered HMAC-SHA256 (hex) of the E.164 phone
    homeserver_id VARCHAR(64)  NOT NULL,
    updated_at    TIMESTAMP    NOT NULL
);

CREATE INDEX ix_directory_entry_hs ON directory_entry (homeserver_id);

-- Locate-by-handle: global username -> homeserver. Same write rules as the phone directory.
CREATE TABLE username_index (
    username      VARCHAR(255) PRIMARY KEY,          -- lowercased global username
    homeserver_id VARCHAR(64)  NOT NULL,
    updated_at    TIMESTAMP    NOT NULL
);
