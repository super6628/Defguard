# S-Metric SIEM / activity-log event mapping

This document maps S-Metric firewall and Client Traffic Policy lifecycle operations into Defguard's existing activity-log pipeline. The activity-log stream manager already exports those records to Vector HTTP and Logstash HTTP, so S-Metric reuses that transport rather than introducing a parallel SIEM exporter.

## Event model

Two structured API event families are used:

- `SmetricFirewallEvent` -> activity-log module `vpn`
- `SmetricTrafficPolicyEvent` -> activity-log module `client`

Each event contains an `action` plus stable identifiers and operation-specific fields. This keeps the activity-log event taxonomy compact while still allowing SIEM filters on metadata such as `action`, `policy_id`, `rule_id`, `location_id`, `generation`, `revision`, `enabled`, `success`, and `error`.

## Firewall mapping

| Operation | Action | Metadata | Emission point |
| --- | --- | --- | --- |
| Create policy | `policy_created` | `policy_id`, `revision` | ACL `create` API after commit |
| Delete policy | `policy_deleted` | `policy_id` | ACL `remove` API after replacement deployment is queued |
| Enable/disable policy | `policy_enabled` / `policy_disabled` | `policy_id`, `enabled` | ACL `set_policy_enabled` API after state change and replacement deployment |
| Create rule | `rule_created` | `policy_id`, `rule_id` | ACL `create_rule` API after revision bump |
| Update rule | `rule_updated` | `policy_id`, `rule_id` | ACL `update_rule_handler` after revision bump |
| Delete rule | `rule_deleted` | `policy_id`, `rule_id` | ACL `delete_rule_handler` after revision bump |
| Publish policy | `policy_published` | `policy_id`, `revision`, `checksum` | ACL `publish` after immutable snapshot and desired deployments are created |
| Assign location | `location_assigned` | `policy_id`, `location_id`, `enabled` | ACL `set_assignment` after persistence/deployment |
| Remove assignment | `location_unassigned` | `policy_id`, `location_id` | ACL `remove_assignment` after persistence/deployment |
| Deployment accepted | `deployment_applied` | `location_id`, `generation`, `checksum`, `success=true` | deployment ACK endpoint after desired generation/checksum validation |
| Deployment failed | `deployment_failed` | `location_id`, `generation`, `checksum`, `success=false`, `error` | deployment ACK endpoint after desired generation/checksum validation |

Stale or mismatched deployment acknowledgements are intentionally not recorded as successful deployment events. A later hardening step can add a separate rejected-ACK security event if operational value justifies the volume.

## Client Traffic Policy mapping

| Operation | Action | Metadata | Emission point |
| --- | --- | --- | --- |
| Create policy | `policy_created` | `policy_id`, `revision` | traffic-policy `create` API |
| Update draft | `policy_updated` | `policy_id`, `revision` | traffic-policy `update` API |
| Delete policy | `policy_deleted` | `policy_id` | traffic-policy `remove` API |
| Enable/disable policy | `policy_enabled` / `policy_disabled` | `policy_id`, `enabled` | traffic-policy `set_policy_enabled` API |
| Publish policy | `policy_published` | `policy_id`, `revision`, `checksum` | traffic-policy `publish` API |

Effective-policy reads are not management/security mutations and are not written to the activity log by default. They can be added later as high-volume telemetry if required.

## Actor and request context

Management mutations use Defguard's existing `ApiRequestContext`, preserving the authenticated actor, request IP, timestamp, and device/user-agent context already used by the activity log. The current deployment acknowledgement endpoint is admin-authenticated and therefore can use the same context. When ACK authentication is moved to gateway machine identity, the event context should move with it rather than pretending the gateway is an administrator.

## SIEM transport

No new transport is required. Once these events enter the activity log, configured activity-log streams deliver them through the existing Vector HTTP or Logstash HTTP stream implementations. SIEM-side routing should filter on `event`, `module`, and the structured metadata fields described above.
