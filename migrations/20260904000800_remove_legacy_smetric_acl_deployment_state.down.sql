-- Restore the retired policy/location deployment state for migration rollback.
CREATE SEQUENCE IF NOT EXISTS smetric_acl_deployment_generation_seq AS BIGINT;

CREATE TABLE IF NOT EXISTS smetric_acl_deployment_state (
    policy_id BIGINT NOT NULL REFERENCES smetric_acl_policy(id) ON DELETE CASCADE,
    location_id BIGINT NOT NULL,
    desired_generation BIGINT NOT NULL,
    desired_policy_revision BIGINT NOT NULL,
    desired_checksum TEXT NOT NULL,
    desired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_generation BIGINT,
    applied_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (policy_id, location_id)
);
