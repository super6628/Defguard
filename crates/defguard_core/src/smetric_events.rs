//! Structured S-Metric security/audit event payloads.
//!
//! These payloads are designed for Defguard's existing activity-log/SIEM pipeline. They keep
//! firewall and client traffic policy event metadata stable even if the human-readable activity
//! log descriptions change over time.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmetricFirewallAction {
    PolicyCreated,
    PolicyDeleted,
    PolicyEnabled,
    PolicyDisabled,
    RuleCreated,
    RuleUpdated,
    RuleDeleted,
    PolicyPublished,
    LocationAssigned,
    LocationUnassigned,
    DeploymentApplied,
    DeploymentFailed,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SmetricFirewallEvent {
    pub action: SmetricFirewallAction,
    pub policy_id: Option<i64>,
    pub rule_id: Option<i64>,
    pub location_id: Option<i64>,
    pub revision: Option<u64>,
    pub generation: Option<i64>,
    pub checksum: Option<String>,
    pub enabled: Option<bool>,
    pub success: Option<bool>,
    pub error: Option<String>,
}

impl SmetricFirewallEvent {
    #[must_use]
    pub const fn policy(action: SmetricFirewallAction, policy_id: i64) -> Self {
        Self {
            action,
            policy_id: Some(policy_id),
            rule_id: None,
            location_id: None,
            revision: None,
            generation: None,
            checksum: None,
            enabled: None,
            success: None,
            error: None,
        }
    }

    #[must_use]
    pub const fn rule(action: SmetricFirewallAction, policy_id: i64, rule_id: i64) -> Self {
        Self {
            action,
            policy_id: Some(policy_id),
            rule_id: Some(rule_id),
            location_id: None,
            revision: None,
            generation: None,
            checksum: None,
            enabled: None,
            success: None,
            error: None,
        }
    }

    #[must_use]
    pub const fn location(
        action: SmetricFirewallAction,
        policy_id: i64,
        location_id: i64,
    ) -> Self {
        Self {
            action,
            policy_id: Some(policy_id),
            rule_id: None,
            location_id: Some(location_id),
            revision: None,
            generation: None,
            checksum: None,
            enabled: None,
            success: None,
            error: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SmetricTrafficPolicyAction {
    PolicyCreated,
    PolicyUpdated,
    PolicyDeleted,
    PolicyEnabled,
    PolicyDisabled,
    PolicyPublished,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SmetricTrafficPolicyEvent {
    pub action: SmetricTrafficPolicyAction,
    pub policy_id: i64,
    pub revision: Option<u64>,
    pub checksum: Option<String>,
    pub enabled: Option<bool>,
}

impl SmetricTrafficPolicyEvent {
    #[must_use]
    pub const fn policy(action: SmetricTrafficPolicyAction, policy_id: i64) -> Self {
        Self {
            action,
            policy_id,
            revision: None,
            checksum: None,
            enabled: None,
        }
    }
}
