# S-Metric security events

S-Metric security-sensitive runtime paths emit structured `tracing` events using a stable
`security_event` field. These records are intended to be consumed by the same observability/SIEM
pipeline that captures Core logs while activity-log-native S-Metric event mapping is completed.

## Client traffic policy events

| `security_event` | Meaning | Key fields |
| --- | --- | --- |
| `smetric_traffic_policy_created` | Policy draft created | `policy_id`, `policy_name`, `mode`, `priority`, `target_count`, `destination_count` |
| `smetric_traffic_policy_updated` | Policy draft updated | `policy_id`, `revision`, `policy_name`, `mode`, `priority`, `target_count`, `destination_count` |
| `smetric_traffic_policy_deleted` | Policy deleted | `policy_id`, `policy_name`, `revision` |
| `smetric_traffic_policy_enabled_changed` | Operational enable state changed | `policy_id`, `enabled`, `revision` |
| `smetric_traffic_policy_published` | Immutable policy revision published | `policy_id`, `revision`, `checksum` |

## Client configuration sync events

| `security_event` | Meaning | Key fields |
| --- | --- | --- |
| `smetric_config_version_changed` | Desired client configuration changed | `version`, `reason` |
| `smetric_config_applied` | Client acknowledged the current desired version | `version`, `desired` |
| `smetric_config_apply_failed` | Client failed to apply the current desired version | `version`, `desired`, `error` |
| `smetric_config_ack_stale` | Acknowledgement did not match current desired version | `version`, `desired`, `success` |

## Firewall deployment events

| `security_event` | Meaning | Key fields |
| --- | --- | --- |
| `smetric_acl_deployment_desired` | Effective firewall generation recorded/ensured for a location | `location_id`, `generation`, `checksum` |
| `smetric_acl_deployment_applied` | Gateway acknowledgement applied successfully | `location_id`, `generation`, `checksum` |
| `smetric_acl_deployment_failed` | Gateway reported an enforcement failure | `location_id`, `generation`, `checksum`, `error` |
| `smetric_acl_deployment_ack_stale` | Gateway acknowledgement did not match desired state | `location_id`, `generation`, `checksum`, `reason` |
| `smetric_acl_deployment_ack_rejected` | Malformed acknowledgement rejected | `location_id`, `generation`, `reason` |
| `smetric_acl_deployment_ack_not_applied` | Valid acknowledgement could not mutate current deployment state | `location_id`, `generation`, `checksum`, `success` |

## Activity-log integration

Defguard's existing activity-log stream manager already supports Vector HTTP and Logstash HTTP.
The next integration layer is to map S-Metric management events into Defguard's `ApiEvent` /
`ActivityLogEvent` pipeline so the same records are persisted in the activity log and exported by
configured activity-log streams without relying on external log collection.

The structured event names above are intentionally stable so the activity-log mapping can preserve
an equivalent SIEM taxonomy when that layer is enabled.
