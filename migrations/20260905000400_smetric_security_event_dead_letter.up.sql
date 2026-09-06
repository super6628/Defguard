ALTER TABLE smetric_security_event_outbox
    ADD COLUMN dead_lettered_at TIMESTAMPTZ;

DROP INDEX IF EXISTS smetric_security_event_outbox_pending_idx;
CREATE INDEX smetric_security_event_outbox_pending_idx
    ON smetric_security_event_outbox (next_attempt_at, id)
    WHERE delivered_at IS NULL AND dead_lettered_at IS NULL;
