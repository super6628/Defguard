CREATE INDEX smetric_security_event_outbox_delivered_idx
    ON smetric_security_event_outbox (delivered_at, id)
    WHERE delivered_at IS NOT NULL AND dead_lettered_at IS NULL;
