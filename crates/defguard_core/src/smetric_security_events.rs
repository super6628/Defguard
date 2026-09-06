//! S-Metric security event payloads used by activity-log/SIEM integration.
//!
//! The event names and metadata contract are documented in
//! `docs/smetric-security-event-mapping.md`. This module keeps S-Metric-specific event data
//! independent from the inherited Defguard models so the existing activity-log pipeline can
//! translate it without coupling firewall and client-traffic services to logger internals.

use serde::{Deserialize, Serialize};

pub const SMETRIC_SECURITY_SCHEMA: &str = "smetric.security.v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SmetricSecurityEvent {
    AclPolicyCreated {
        policy_id: i64,
        name: String,
        enabled: bool,
        revision: u64,
    },
    AclPolicyDeleted {
        policy_id: i64,
        name: String,
    },
    AclPolicyStateChanged {
        policy_id: i64,
        enabled: bool,
        affected_location_ids: Vec<i64>,
    },
    AclRuleCreated {
        policy_id: i64,
        rule_id: i64,
        name: String,
        priority: i32,
    },
    AclRuleUpdated {
        policy_id: i64,
        rule_id: i64,
        name: String,
        priority: i32,
    },
    AclRuleDeleted {
        policy_id: i64,
        rule_id: i64,
    },
    AclAssignmentChanged {
        policy_id: i64,
        location_id: i64,
        enabled: bool,
        removed: bool,
    },
    AclPolicyPublished {
        policy_id: i64,
        revision: u64,
        checksum: String,
        location_ids: Vec<i64>,
    },
    AclDeploymentQueued {
        location_id: i64,
        generation: i64,
        checksum: String,
        reason: String,
        policy_id: Option<i64>,
    },
    AclDeploymentApplied {
        location_id: i64,
        generation: i64,
        checksum: String,
    },
    AclDeploymentFailed {
        location_id: i64,
        generation: i64,
        checksum: String,
        error: String,
    },
    AclDeploymentAckRejected {
        location_id: i64,
        generation: i64,
        checksum: String,
        reason: String,
    },
    TrafficPolicyCreated {
        policy_id: i64,
        name: String,
        mode: String,
        priority: u32,
        enabled: bool,
        revision: u64,
    },
    TrafficPolicyUpdated {
        policy_id: i64,
        name: String,
        mode: String,
        priority: u32,
        revision: u64,
    },
    TrafficPolicyDeleted {
        policy_id: i64,
        name: String,
    },
    TrafficPolicyStateChanged {
        policy_id: i64,
        enabled: bool,
    },
    TrafficPolicyPublished {
        policy_id: i64,
        revision: u64,
        checksum: String,
        mode: String,
        target_count: usize,
        destination_count: usize,
    },
}

impl SmetricSecurityEvent {
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        match self {
            Self::AclPolicyCreated { .. } => "smetric_acl_policy_created",
            Self::AclPolicyDeleted { .. } => "smetric_acl_policy_deleted",
            Self::AclPolicyStateChanged { .. } => "smetric_acl_policy_state_changed",
            Self::AclRuleCreated { .. } => "smetric_acl_rule_created",
            Self::AclRuleUpdated { .. } => "smetric_acl_rule_updated",
            Self::AclRuleDeleted { .. } => "smetric_acl_rule_deleted",
            Self::AclAssignmentChanged { .. } => "smetric_acl_assignment_changed",
            Self::AclPolicyPublished { .. } => "smetric_acl_policy_published",
            Self::AclDeploymentQueued { .. } => "smetric_acl_deployment_queued",
            Self::AclDeploymentApplied { .. } => "smetric_acl_deployment_applied",
            Self::AclDeploymentFailed { .. } => "smetric_acl_deployment_failed",
            Self::AclDeploymentAckRejected { .. } => "smetric_acl_deployment_ack_rejected",
            Self::TrafficPolicyCreated { .. } => "smetric_traffic_policy_created",
            Self::TrafficPolicyUpdated { .. } => "smetric_traffic_policy_updated",
            Self::TrafficPolicyDeleted { .. } => "smetric_traffic_policy_deleted",
            Self::TrafficPolicyStateChanged { .. } => "smetric_traffic_policy_state_changed",
            Self::TrafficPolicyPublished { .. } => "smetric_traffic_policy_published",
        }
    }

    #[must_use]
    pub const fn module(&self) -> SmetricEventModule {
        match self {
            Self::TrafficPolicyCreated { .. }
            | Self::TrafficPolicyUpdated { .. }
            | Self::TrafficPolicyDeleted { .. }
            | Self::TrafficPolicyStateChanged { .. }
            | Self::TrafficPolicyPublished { .. } => SmetricEventModule::Client,
            _ => SmetricEventModule::Vpn,
        }
    }

    #[must_use]
    pub fn metadata(&self) -> serde_json::Value {
        let mut value = serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "schema".to_owned(),
                serde_json::Value::String(SMETRIC_SECURITY_SCHEMA.to_owned()),
            );
        }
        value
    }

    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::AclPolicyCreated { policy_id, name, .. } => {
                format!("Created S-Metric firewall policy {policy_id} ({name}).")
            }
            Self::AclPolicyDeleted { policy_id, name } => {
                format!("Deleted S-Metric firewall policy {policy_id} ({name}).")
            }
            Self::AclPolicyStateChanged { policy_id, enabled, .. } => format!(
                "{} S-Metric firewall policy {policy_id}.",
                if *enabled { "Enabled" } else { "Disabled" }
            ),
            Self::AclRuleCreated { policy_id, rule_id, .. } => {
                format!("Created rule {rule_id} in S-Metric firewall policy {policy_id}.")
            }
            Self::AclRuleUpdated { policy_id, rule_id, .. } => {
                format!("Updated rule {rule_id} in S-Metric firewall policy {policy_id}.")
            }
            Self::AclRuleDeleted { policy_id, rule_id } => {
                format!("Deleted rule {rule_id} from S-Metric firewall policy {policy_id}.")
            }
            Self::AclAssignmentChanged { policy_id, location_id, enabled, removed } => {
                if *removed {
                    format!("Removed S-Metric firewall policy {policy_id} assignment from VPN location {location_id}.")
                } else {
                    format!(
                        "{} S-Metric firewall policy {policy_id} assignment for VPN location {location_id}.",
                        if *enabled { "Enabled" } else { "Disabled" }
                    )
                }
            }
            Self::AclPolicyPublished { policy_id, revision, .. } => {
                format!("Published S-Metric firewall policy {policy_id} revision {revision}.")
            }
            Self::AclDeploymentQueued { location_id, generation, .. } => format!(
                "Queued S-Metric firewall deployment generation {generation} for VPN location {location_id}."
            ),
            Self::AclDeploymentApplied { location_id, generation, .. } => format!(
                "Gateway applied S-Metric firewall deployment generation {generation} for VPN location {location_id}."
            ),
            Self::AclDeploymentFailed { location_id, generation, error, .. } => format!(
                "S-Metric firewall deployment generation {generation} failed for VPN location {location_id}: {error}."
            ),
            Self::AclDeploymentAckRejected { location_id, generation, reason, .. } => format!(
                "Rejected S-Metric firewall deployment acknowledgement generation {generation} for VPN location {location_id}: {reason}."
            ),
            Self::TrafficPolicyCreated { policy_id, name, .. } => {
                format!("Created S-Metric client traffic policy {policy_id} ({name}).")
            }
            Self::TrafficPolicyUpdated { policy_id, .. } => {
                format!("Updated S-Metric client traffic policy {policy_id}.")
            }
            Self::TrafficPolicyDeleted { policy_id, name } => {
                format!("Deleted S-Metric client traffic policy {policy_id} ({name}).")
            }
            Self::TrafficPolicyStateChanged { policy_id, enabled } => format!(
                "{} S-Metric client traffic policy {policy_id}.",
                if *enabled { "Enabled" } else { "Disabled" }
            ),
            Self::TrafficPolicyPublished { policy_id, revision, .. } => {
                format!("Published S-Metric client traffic policy {policy_id} revision {revision}.")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmetricEventModule {
    Vpn,
    Client,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_versioned() {
        let event = SmetricSecurityEvent::AclRuleDeleted {
            policy_id: 10,
            rule_id: 11,
        };
        assert_eq!(event.metadata()["schema"], SMETRIC_SECURITY_SCHEMA);
        assert_eq!(event.metadata()["policy_id"], 10);
        assert_eq!(event.event_type(), "smetric_acl_rule_deleted");
        assert_eq!(event.module(), SmetricEventModule::Vpn);
    }

    #[test]
    fn client_events_map_to_client_module() {
        let event = SmetricSecurityEvent::TrafficPolicyStateChanged {
            policy_id: 7,
            enabled: false,
        };
        assert_eq!(event.module(), SmetricEventModule::Client);
    }
}
