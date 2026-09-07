DROP INDEX IF EXISTS smetric_security_event_outbox_pending_idx;

ALTER TABLE smetric_security_event_outbox
    DROP COLUMN dead_lettered_at;

CREATE INDEX smetric_security_event_outbox_pending_idx
    ON smetric_security_event_outbox (next_attempt_at, id)
    WHERE delivered_at IS NULL;
