-- Independent S-Metric ACL policy storage.
-- Kept separate from inherited enterprise ACL tables so S-Metric policy semantics can evolve independently.

CREATE TABLE smetric_acl_policy (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    default_action TEXT NOT NULL DEFAULT 'allow',
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT smetric_acl_policy_default_action CHECK (default_action IN ('allow', 'deny'))
);

CREATE TABLE smetric_acl_rule (
    id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL REFERENCES smetric_acl_policy(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    priority INTEGER NOT NULL CHECK (priority >= 0),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    action TEXT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'any',
    ports INT8RANGE,
    source_kind TEXT NOT NULL,
    source_value TEXT,
    destination_kind TEXT NOT NULL,
    destination_value TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT smetric_acl_rule_action CHECK (action IN ('allow', 'deny', 'reject')),
    CONSTRAINT smetric_acl_rule_protocol CHECK (protocol IN ('any', 'tcp', 'udp', 'icmp')),
    CONSTRAINT smetric_acl_rule_source_kind CHECK (source_kind IN ('any', 'user', 'group', 'device', 'device_group', 'location', 'cidr')),
    CONSTRAINT smetric_acl_rule_destination_kind CHECK (destination_kind IN ('any', 'cidr', 'ip', 'ip_range', 'alias', 'service')),
    CONSTRAINT smetric_acl_rule_source_value CHECK ((source_kind = 'any' AND source_value IS NULL) OR (source_kind <> 'any' AND source_value IS NOT NULL)),
    CONSTRAINT smetric_acl_rule_destination_value CHECK ((destination_kind = 'any' AND destination_value IS NULL) OR (destination_kind <> 'any' AND destination_value IS NOT NULL)),
    CONSTRAINT smetric_acl_rule_ports CHECK (ports IS NULL OR (lower(ports) >= 1 AND upper(ports) <= 65536)),
    UNIQUE(policy_id, priority)
);

CREATE TABLE smetric_acl_policy_assignment (
    id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL REFERENCES smetric_acl_policy(id) ON DELETE CASCADE,
    location_id BIGINT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(policy_id, location_id)
);

CREATE TABLE smetric_acl_revision (
    id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL REFERENCES smetric_acl_policy(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL CHECK (revision > 0),
    checksum TEXT NOT NULL,
    compiled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(policy_id, revision)
);

CREATE INDEX smetric_acl_rule_policy_priority_idx ON smetric_acl_rule(policy_id, priority);
CREATE INDEX smetric_acl_assignment_location_idx ON smetric_acl_policy_assignment(location_id) WHERE enabled = TRUE;
