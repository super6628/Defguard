# S-Metric security event mapping

This document defines how S-Metric firewall and client traffic policy activity maps into Defguard's existing activity-log/SIEM pipeline before implementation.

The existing pipeline is reused end-to-end:

`S-Metric handler -> AppState::emit_event(ApiEvent) -> defguard_event_logger -> activity_log_event -> configured Vector/Logstash HTTP stream`

No separate SIEM transport is introduced.

## Mapping principles

- Administrative changes are API events and retain the authenticated `ApiRequestContext` so the activity log records the real administrator, source IP, timestamp, and device context.
- Firewall enforcement events use the existing `Vpn` activity-log module because they change gateway VPN enforcement state.
- Client traffic policy management uses the existing `Client` module because it controls endpoint routing behavior.
- Policy authoring events that do not directly deploy gateway state still use the same module as the policy they affect, allowing SIEM filters to select all firewall or all client-policy events consistently.
- Event names are stored as text in `activity_log_event.event`, so adding new `EventType` variants does not require a PostgreSQL enum migration.
- S-Metric metadata is structured JSON and should remain stable enough for SIEM correlation and alerting. Human-readable descriptions are secondary.
- Immutable published revision/checksum values are logged on publish/deploy events. Draft-only edits log the resulting draft revision when available.
- Gateway acknowledgement events must include location, desired generation, checksum, success/failure, and error text for failure events.

## Firewall / ACL events

| Core API event | Activity-log event type | Module | Required metadata | Emission point |
| --- | --- | --- | --- | --- |
| `SmetricAclPolicyCreated` | `smetric_acl_policy_created` | `Vpn` | `policy_id`, `name`, `enabled`, `revision` | successful policy create |
| `SmetricAclPolicyDeleted` | `smetric_acl_policy_deleted` | `Vpn` | `policy_id`, `name` | successful policy delete, after replacement configs are queued |
| `SmetricAclPolicyStateChanged` | `smetric_acl_policy_state_changed` | `Vpn` | `policy_id`, `enabled`, `affected_location_ids` | successful enable/disable |
| `SmetricAclRuleCreated` | `smetric_acl_rule_created` | `Vpn` | `policy_id`, `rule_id`, `name`, `priority` | successful rule create |
| `SmetricAclRuleUpdated` | `smetric_acl_rule_updated` | `Vpn` | `policy_id`, `rule_id`, `name`, `priority` | successful rule update |
| `SmetricAclRuleDeleted` | `smetric_acl_rule_deleted` | `Vpn` | `policy_id`, `rule_id` | successful rule delete |
| `SmetricAclAssignmentChanged` | `smetric_acl_assignment_changed` | `Vpn` | `policy_id`, `location_id`, `enabled`, `removed` | assignment create/update/delete |
| `SmetricAclPolicyPublished` | `smetric_acl_policy_published` | `Vpn` | `policy_id`, `revision`, `checksum`, `location_ids` | successful publish after affected locations are queued |
| `SmetricAclDeploymentQueued` | `smetric_acl_deployment_queued` | `Vpn` | `location_id`, `generation`, `checksum`, `reason`, optional `policy_id` | when desired location deployment state is advanced and a gateway command is sent |
| `SmetricAclDeploymentApplied` | `smetric_acl_deployment_applied` | `Vpn` | `location_id`, `generation`, `checksum` | accepted successful gateway ACK |
| `SmetricAclDeploymentFailed` | `smetric_acl_deployment_failed` | `Vpn` | `location_id`, `generation`, `checksum`, `error` | accepted failed gateway ACK |
| `SmetricAclDeploymentAckRejected` | `smetric_acl_deployment_ack_rejected` | `Vpn` | `location_id`, `generation`, `checksum`, `reason` | stale/mismatched ACK; useful for SIEM anomaly detection |

### Firewall event notes

`SmetricAclDeploymentQueued` should be emitted once per location-generation, not once per rule or once per assigned policy. The location-level desired generation is the authoritative deployment identity.

`SmetricAclDeploymentAckRejected` is intentionally logged even though it does not mutate desired deployment state. A stale or checksum-mismatched acknowledgement is operationally significant and can indicate delayed gateways, duplicate delivery, or a broken/malicious integration.

Policy create/update/rule events do **not** imply enforcement. Only publish/enable/assignment/deployment events indicate a potential live gateway change.

## Client Traffic Policy events

| Core API event | Activity-log event type | Module | Required metadata | Emission point |
| --- | --- | --- | --- | --- |
| `SmetricTrafficPolicyCreated` | `smetric_traffic_policy_created` | `Client` | `policy_id`, `name`, `mode`, `priority`, `enabled`, `revision` | successful create |
| `SmetricTrafficPolicyUpdated` | `smetric_traffic_policy_updated` | `Client` | `policy_id`, `name`, `mode`, `priority`, `revision` | successful draft update |
| `SmetricTrafficPolicyDeleted` | `smetric_traffic_policy_deleted` | `Client` | `policy_id`, `name` | successful delete |
| `SmetricTrafficPolicyStateChanged` | `smetric_traffic_policy_state_changed` | `Client` | `policy_id`, `enabled` | successful enable/disable |
| `SmetricTrafficPolicyPublished` | `smetric_traffic_policy_published` | `Client` | `policy_id`, `revision`, `checksum`, `mode`, `target_count`, `destination_count` | successful publish |

Effective-policy reads are **not** activity-log events by default. They are frequent configuration reads rather than administrative/security state changes and would create SIEM noise. Client-side application/failure telemetry can be added later as a dedicated runtime event source when the client repository is integrated.

## Metadata schema

All S-Metric event metadata should include a version discriminator so fields can evolve without silently breaking SIEM parsers:

```json
{
  "schema": "smetric.security.v1",
  "policy_id": 42,
  "revision": 7,
  "checksum": "..."
}
```

Common field meanings:

- `policy_id`: Core database identifier for the S-Metric policy.
- `rule_id`: Core database identifier for an ACL rule.
- `location_id`: Defguard VPN location identifier.
- `generation`: authoritative location deployment generation.
- `checksum`: checksum of the immutable published/effective configuration represented by the event.
- `reason`: stable machine-readable reason string such as `publish`, `enable`, `disable`, `assignment_enable`, `assignment_disable`, `policy_delete`, or `reconnect_reconcile`.
- `error`: gateway/deployment failure text; never used for success events.

## Description examples

Descriptions should be concise because the structured metadata is the SIEM contract. Examples:

- `Published S-Metric firewall policy 42 revision 7.`
- `Queued S-Metric firewall deployment generation 19 for VPN location 3.`
- `Gateway applied S-Metric firewall deployment generation 19 for VPN location 3.`
- `S-Metric firewall deployment generation 20 failed for VPN location 3: nftables validation failed.`
- `Published S-Metric client traffic policy 11 revision 4.`

## Implementation order

1. Add the new `ApiEventType` variants in Core.
2. Add matching `EventType` values and module mapping in `defguard_event_logger`.
3. Add stable JSON metadata builders and descriptions.
4. Emit management events from ACL and Client Traffic Policy API handlers using authenticated `ApiRequestContext`.
5. Emit deployment ACK success/failure/rejection events.
6. Add tests for event-to-activity-log translation and metadata.
7. Compile `defguard_core` and `defguard_event_logger`, then perform one runtime SIEM stream test through a configured Vector or Logstash HTTP endpoint.
