-- New client traffic policies must start disabled until a published snapshot exists.
-- Activation is an explicit operational action performed after publish.
ALTER TABLE smetric_traffic_policy
    ALTER COLUMN enabled SET DEFAULT FALSE;
