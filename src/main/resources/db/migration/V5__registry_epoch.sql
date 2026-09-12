-- Migration plan Phase 2 (ADM-001 L10): registry roots under a pinned federation genesis. A governance-signed
-- epoch, not the operational key, is what gives a roster entry its status once
-- gua.resolver.governance.required is on. Everything here is additive and nullable, so rows written before
-- this migration stay legal and the pre-governance path keeps working with the flag off.

-- One accepted epoch per registry. content_json is the registry content the epoch's content_hash commits to,
-- kept so the served epoch can be re-verified and so an auditor can see what was signed, not just its hash.
-- epoch_hash is the SHA-256 of the gua-registry-epoch.v1 canonical bytes: the next epoch's previous_hash and
-- the payload of the MEMBERSHIP_EPOCH log leaf that accepted it.
CREATE TABLE registry_epoch (
    registry        VARCHAR(32)  NOT NULL,           -- HomeserverRegistry | VerifierRegistry | PolicyRegistry | WitnessRegistry
    epoch           BIGINT       NOT NULL,           -- 1-based, gap-free per registry
    genesis_id      VARCHAR(64)  NOT NULL,
    previous_hash   VARCHAR(64)  NOT NULL,           -- empty string at epoch 1
    epoch_hash      VARCHAR(64)  NOT NULL,
    issued_at       TIMESTAMP    NOT NULL,
    content_json    TEXT         NOT NULL,
    signatures_json TEXT         NOT NULL,
    accepted_at     TIMESTAMP    NOT NULL,
    log_leaf_index  BIGINT,
    PRIMARY KEY (registry, epoch)
);

-- The epoch that set this entry's current status. NULL means the status predates governance, or was set by
-- the operational key while the flag was off.
ALTER TABLE roster_entry ADD COLUMN registry_epoch BIGINT;

-- A requested status that governance has not ratified yet. With governance.required on, a suspend or revoke
-- through the admin API lands here and the entry keeps serving until an epoch carries the change: recording
-- intent must not itself be the act, or the operational key would still be able to take a member out of
-- service on its own, which is the power ADM-001 L10 moves to the governance keys.
ALTER TABLE roster_entry ADD COLUMN pending_status VARCHAR(16);
