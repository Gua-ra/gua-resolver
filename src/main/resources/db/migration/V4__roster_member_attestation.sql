-- Migration plan Phase 1 (ADM-007): a roster entry can carry the member's own signature over the fields it
-- controls, so the authority alone can no longer rewrite a member's address or key. Every column here is
-- nullable and every table is new, so rows admitted before this migration stay legal as unattested entries.

-- The accepted attestation for the current entry. member_entry_hash is SHA-256 of the gua-member-entry.v1
-- canonical bytes and is the payload of the MEMBER_ATTEST log leaf that accepted it.
ALTER TABLE roster_entry ADD COLUMN member_key_id VARCHAR(128);
ALTER TABLE roster_entry ADD COLUMN member_sequence BIGINT;
ALTER TABLE roster_entry ADD COLUMN member_not_before TIMESTAMP;
ALTER TABLE roster_entry ADD COLUMN member_not_after TIMESTAMP;
ALTER TABLE roster_entry ADD COLUMN member_signatures_json TEXT;
ALTER TABLE roster_entry ADD COLUMN member_entry_hash VARCHAR(64);

-- The key the operator was admitted with, retained as the anchor of its attestation chain instead of being
-- proved once and never used again. genesis_key_proof is the legacy possession signature over server_name;
-- it is null for an entry admitted with a member block (whose self-signature is in roster_member_history)
-- and for the seeded first entry, which proves nothing.
ALTER TABLE roster_entry ADD COLUMN genesis_signing_key VARCHAR(255);
ALTER TABLE roster_entry ADD COLUMN genesis_key_proof TEXT;

-- Every accepted attestation, so the sequence chain and each key rotation stay auditable after the columns
-- above move on. entry_json is the signed field set as accepted; log_leaf_index is its MEMBER_ATTEST leaf.
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
