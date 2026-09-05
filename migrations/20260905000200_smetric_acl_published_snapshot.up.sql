-- Preserve immutable published ACL policy state separately from the mutable draft tables.
-- Location recompiles must use this snapshot so editing a published policy cannot silently remove
-- or alter the live gateway policy before the next explicit publish.

ALTER TABLE smetric_acl_revision
    ADD COLUMN policy_snapshot JSONB;

-- Existing rows predate snapshots. They remain valid history but are not safe live snapshots until
-- the corresponding policy is published again.
CREATE INDEX smetric_acl_revision_latest_snapshot_idx
    ON smetric_acl_revision(policy_id, revision DESC)
    WHERE policy_snapshot IS NOT NULL;
