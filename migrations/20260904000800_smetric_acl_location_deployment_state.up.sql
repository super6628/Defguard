-- Track the gateway's authoritative effective firewall state per VPN location.
-- This is separate from policy revision state because one gateway update contains the complete
-- aggregated FirewallConfig for the location.

CREATE SEQUENCE smetric_acl_location_deployment_generation_seq AS BIGINT START WITH 1;

CREATE TABLE smetric_acl_location_deployment_state (
    location_id BIGINT PRIMARY KEY,
    desired_generation BIGINT NOT NULL CHECK (desired_generation > 0),
    desired_checksum TEXT NOT NULL,
    desired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_generation BIGINT,
    applied_checksum TEXT,
    applied_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT smetric_acl_location_deployment_applied_generation_positive
        CHECK (applied_generation IS NULL OR applied_generation > 0),
    CONSTRAINT smetric_acl_location_deployment_applied_not_ahead
        CHECK (applied_generation IS NULL OR applied_generation <= desired_generation)
);

CREATE INDEX smetric_acl_location_deployment_pending_idx
    ON smetric_acl_location_deployment_state(desired_generation)
    WHERE applied_generation IS NULL OR applied_generation < desired_generation;
