-- Independent S-Metric client traffic policy storage.
-- Server-side policy resolution is intentionally separate from firewall ACL policy storage.

CREATE TABLE smetric_traffic_policy (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    mode TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 100 CHECK (priority >= 0),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT smetric_traffic_policy_mode CHECK (mode IN ('full_tunnel', 'split_tunnel', 'bypass'))
);

CREATE TABLE smetric_traffic_policy_target (
    id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL REFERENCES smetric_traffic_policy(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL,
    target_value TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT smetric_traffic_policy_target_kind CHECK (target_kind IN ('global', 'location', 'group', 'user', 'device')),
    CONSTRAINT smetric_traffic_policy_target_value CHECK (
        (target_kind = 'global' AND target_value IS NULL) OR
        (target_kind <> 'global' AND target_value IS NOT NULL)
    ),
    UNIQUE(policy_id, target_kind, target_value)
);

CREATE TABLE smetric_traffic_policy_destination (
    id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL REFERENCES smetric_traffic_policy(id) ON DELETE CASCADE,
    destination_kind TEXT NOT NULL,
    destination_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT smetric_traffic_policy_destination_kind CHECK (destination_kind IN ('cidr', 'ip')),
    UNIQUE(policy_id, destination_kind, destination_value)
);

CREATE TABLE smetric_traffic_policy_revision (
    id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL REFERENCES smetric_traffic_policy(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL CHECK (revision > 0),
    checksum TEXT NOT NULL,
    compiled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(policy_id, revision)
);

CREATE INDEX smetric_traffic_policy_priority_idx ON smetric_traffic_policy(enabled, priority, id);
CREATE INDEX smetric_traffic_policy_target_lookup_idx ON smetric_traffic_policy_target(target_kind, target_value);
CREATE INDEX smetric_traffic_policy_destination_policy_idx ON smetric_traffic_policy_destination(policy_id);
