-- S-Metric ACL deployments are authoritative per VPN location. The older
-- policy/location deployment state is no longer read or written by Core.
DROP TABLE IF EXISTS smetric_acl_deployment_state;
DROP SEQUENCE IF EXISTS smetric_acl_deployment_generation_seq;
