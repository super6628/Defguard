ALTER TABLE smetric_security_event_outbox
    ALTER COLUMN attempts TYPE INTEGER
    USING LEAST(attempts, 2147483647)::INTEGER;
