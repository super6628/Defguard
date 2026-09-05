-- Gateway firewall updates carry a complete FirewallConfig for a location.
-- Multiple simultaneously enabled S-Metric ACL policies for the same location would therefore
-- overwrite each other in last-writer-wins order. Keep one active policy per location until
-- multi-policy aggregation is explicitly implemented.

DO $$
BEGIN
    IF EXISTS (
        SELECT location_id
        FROM smetric_acl_policy_assignment
        WHERE enabled = TRUE
        GROUP BY location_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION
            'cannot enforce one active S-Metric ACL policy per location: duplicate enabled assignments exist';
    END IF;
END
$$;

CREATE UNIQUE INDEX smetric_acl_assignment_one_active_policy_per_location_idx
    ON smetric_acl_policy_assignment(location_id)
    WHERE enabled = TRUE;
