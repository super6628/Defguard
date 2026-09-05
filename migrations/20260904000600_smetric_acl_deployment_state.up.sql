-- Track desired and acknowledged S-Metric ACL gateway state independently from policy revisions.
-- Policy revision changes describe policy definition edits; generation changes describe effective deployment changes.

CREATE SEQUENCE smetric_acl_deployment_generation_seq AS BIGINT START WITH 1;

CREATE TABLE smetric_acl_deployment_state (
    policy_id BIGINT NOT NULL REFERENCES smetric_acl_policy(id) ON DELETE CASCADE,
    location_id BIGINT NOT NULL,
    desired_generation BIGINT NOT NULL CHECK (desired_generation > 0),
    desired_policy_revision BIGINT NOT NULL CHECK (desired_policy_revision > 0),
    desired_checksum TEXT NOT NULL,
    desired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_generation BIGINT,
    applied_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (policy_id, location_id),
    CONSTRAINT smetric_acl_deployment_applied_generation_positive
        CHECK (applied_generation IS NULL OR applied_generation > 0),
    CONSTRAINT smetric_acl_deployment_applied_not_ahead
        CHECK (applied_generation IS NULL OR applied_generation <= desired_generation)
);

CREATE INDEX smetric_acl_deployment_location_idx
    ON smetric_acl_deployment_state(location_id);

CREATE INDEX smetric_acl_deployment_pending_idx
    ON smetric_acl_deployment_state(location_id, desired_generation)
    WHERE applied_generation IS NULL OR applied_generation < desired_generation;
