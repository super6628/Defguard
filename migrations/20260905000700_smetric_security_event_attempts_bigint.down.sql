ALTER TABLE smetric_security_event_outbox
    ALTER COLUMN attempts TYPE INTEGER
    USING attempts::INTEGER;
