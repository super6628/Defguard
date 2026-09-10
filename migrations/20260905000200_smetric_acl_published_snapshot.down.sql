DROP INDEX IF EXISTS smetric_acl_revision_latest_snapshot_idx;
ALTER TABLE smetric_acl_revision DROP COLUMN IF EXISTS policy_snapshot;
