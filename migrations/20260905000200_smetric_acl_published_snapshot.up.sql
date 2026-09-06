-- Preserve immutable published ACL policy state separately from the mutable draft tables.
-- Location recompiles must use this snapshot so editing a published policy cannot silently remove
-- or alter the live gateway policy before the next explicit publish.

ALTER TABLE smetric_acl_revision
    ADD COLUMN policy_snapshot JSONB;

-- Pre-snapshot revision rows cannot reconstruct the live rules. Remove them rather than treating a
-- checksum-only row as deployable state. Administrators must republish those policies once after
-- this migration, after which every deployable revision has an immutable snapshot.
DELETE FROM smetric_acl_revision WHERE policy_snapshot IS NULL;

CREATE INDEX smetric_acl_revision_latest_snapshot_idx
    ON smetric_acl_revision(policy_id, revision DESC)
    WHERE policy_snapshot IS NOT NULL;
