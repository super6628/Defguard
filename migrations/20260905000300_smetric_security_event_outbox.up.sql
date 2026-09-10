-- Durable queue for S-Metric security events destined for activity-log/SIEM delivery.
-- Events are inserted once, then dispatched asynchronously with retry/backoff.
CREATE TABLE smetric_security_event_outbox (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('firewall', 'client_traffic_policy', 'deployment', 'gateway', 'system')),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'error', 'critical')),
    actor_user_id BIGINT NULL,
    actor_username TEXT NULL,
    actor_ip INET NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NULL,
    description TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ NULL,
    last_error TEXT NULL
);

CREATE INDEX smetric_security_event_outbox_pending_idx
    ON smetric_security_event_outbox (next_attempt_at, id)
    WHERE delivered_at IS NULL;

CREATE INDEX smetric_security_event_outbox_created_idx
    ON smetric_security_event_outbox (created_at DESC);

CREATE INDEX smetric_security_event_outbox_type_idx
    ON smetric_security_event_outbox (event_type, created_at DESC);
