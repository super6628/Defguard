# S-Metric SIEM / Activity Log Event Map

This map defines the first S-Metric security-event taxonomy before wiring event emission into the existing Defguard activity-log pipeline.

## Transport and storage

S-Metric events reuse the existing Defguard activity log. The event logger persists them to `activity_log_event`, and configured activity-log streams can forward them to Vector HTTP or Logstash HTTP. No parallel SIEM transport is introduced.

## Module mapping

| S-Metric area | Activity log module |
| --- | --- |
| Firewall policy management | `vpn` |
| Firewall deployment / gateway acknowledgement | `vpn` |
| Client traffic policy management | `client` |

## Firewall management events

| Source action | Event type | Minimum metadata |
| --- | --- | --- |
| Create firewall policy | `smetric_firewall_policy_created` | `policy_id`, `policy_name`, `revision` |
| Delete firewall policy | `smetric_firewall_policy_deleted` | `policy_id`, `policy_name` |
| Enable/disable firewall policy | `smetric_firewall_policy_state_changed` | `policy_id`, `policy_name`, `enabled` |
| Add firewall rule | `smetric_firewall_rule_created` | `policy_id`, `rule_id`, `rule_name`, `revision` |
| Update firewall rule | `smetric_firewall_rule_updated` | `policy_id`, `rule_id`, `rule_name`, `revision` |
| Delete firewall rule | `smetric_firewall_rule_deleted` | `policy_id`, `rule_id`, `revision` |
| Publish firewall policy | `smetric_firewall_policy_published` | `policy_id`, `revision`, `checksum` |
| Set location assignment | `smetric_firewall_assignment_changed` | `policy_id`, `location_id`, `enabled` |
| Remove location assignment | `smetric_firewall_assignment_removed` | `policy_id`, `location_id` |

## Firewall deployment events

| Source action | Event type | Minimum metadata |
| --- | --- | --- |
| Desired aggregate firewall sent | `smetric_firewall_deployment_requested` | `location_id`, `generation`, `checksum` |
| Gateway accepts deployment | `smetric_firewall_deployment_applied` | `location_id`, `generation`, `checksum` |
| Gateway reports deployment failure | `smetric_firewall_deployment_failed` | `location_id`, `generation`, `checksum`, `error` |
| Stale/mismatched acknowledgement ignored | `smetric_firewall_deployment_ack_ignored` | `location_id`, `generation`, `checksum`, `reason` |

Gateway-originated acknowledgement events are system events. Management actions retain the authenticated API request context.

## Client traffic policy events

| Source action | Event type | Minimum metadata |
| --- | --- | --- |
| Create policy | `smetric_client_traffic_policy_created` | `policy_id`, `policy_name`, `revision`, `mode` |
| Update draft | `smetric_client_traffic_policy_updated` | `policy_id`, `policy_name`, `revision`, `mode` |
| Delete policy | `smetric_client_traffic_policy_deleted` | `policy_id`, `policy_name` |
| Enable/disable policy | `smetric_client_traffic_policy_state_changed` | `policy_id`, `policy_name`, `enabled` |
| Publish policy | `smetric_client_traffic_policy_published` | `policy_id`, `revision`, `checksum`, `mode` |

Effective-policy reads are deliberately not audit events in the first version; they can occur frequently during client synchronization and would create high-volume low-value SIEM noise.

## Context rules

1. API mutations use the existing `ApiRequestContext`, preserving actor, source IP, device/user-agent context and timestamp.
2. Gateway deployment ACK/failure uses system/gateway context until gateway-authenticated request context is introduced.
3. Metadata contains stable numeric identifiers and revision/checksum values so SIEM consumers can correlate management events with deployment outcomes.
4. Policy/rule payloads are not copied wholesale into SIEM metadata. This keeps events bounded and avoids accidentally exporting sensitive selector data when identifiers are sufficient.
5. Failed API requests are not emitted as state-change events. Deployment failures are emitted because they represent a successfully requested state transition that failed during enforcement.

## Initial implementation order

1. Add S-Metric event variants and activity-log event types.
2. Add structured metadata models and descriptions.
3. Emit management events from firewall and client-traffic API mutation handlers.
4. Emit deployment requested/applied/failed/ignored events from location deployment and ACK paths.
5. Add event-logger tests and validate Vector/Logstash output uses the existing stream format.
