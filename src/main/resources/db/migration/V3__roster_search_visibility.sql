-- Per-homeserver user-search discoverability policy, carried in the signed roster.
-- GLOBAL: users discoverable by federated search from any member (default).
-- SERVER: users discoverable only by searchers on the same homeserver.
-- GROUP : users discoverable from homeservers sharing at least one search group.
ALTER TABLE roster_entry ADD COLUMN search_visibility VARCHAR(16) NOT NULL DEFAULT 'GLOBAL';
ALTER TABLE roster_entry ADD COLUMN search_groups_json TEXT NOT NULL DEFAULT '[]';
