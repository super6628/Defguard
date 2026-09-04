CREATE TABLE smetric_acl_device_group (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE smetric_acl_device_group_member (
    group_id BIGINT NOT NULL REFERENCES smetric_acl_device_group(id) ON DELETE CASCADE,
    device_id BIGINT NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, device_id)
);

CREATE INDEX smetric_acl_device_group_member_device_idx
    ON smetric_acl_device_group_member(device_id);
