-- Keep policy activation separate from draft mutation.
-- New policies are always created disabled, even if an older API client sends enabled=true.
-- Draft updates that increment revision cannot simultaneously transition a disabled policy to enabled;
-- activation must go through the dedicated enabled endpoint after a published snapshot exists.
CREATE OR REPLACE FUNCTION smetric_traffic_policy_guard_enable()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.enabled := FALSE;
        RETURN NEW;
    END IF;

    IF NEW.revision <> OLD.revision AND NOT OLD.enabled AND NEW.enabled THEN
        NEW.enabled := FALSE;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER smetric_traffic_policy_guard_enable_trigger
BEFORE INSERT OR UPDATE OF enabled, revision ON smetric_traffic_policy
FOR EACH ROW
EXECUTE FUNCTION smetric_traffic_policy_guard_enable();
