CREATE INDEX smetric_security_event_outbox_dead_lettered_idx
    ON smetric_security_event_outbox (dead_lettered_at, id)
    WHERE dead_lettered_at IS NOT NULL;
