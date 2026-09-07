//! Translation helpers for S-Metric security events.
//!
//! The event names are represented by `EventType` and remain text in PostgreSQL, so this mapping
//! does not require an activity-log database enum migration.

use defguard_core::{
    db::models::activity_log::{ActivityLogModule, EventType},
    smetric_security_events::{SmetricEventModule, SmetricSecurityEvent},
};

pub struct SmetricActivityLogMapping {
    pub event_type: EventType,
    pub module: ActivityLogModule,
    pub description: String,
    pub metadata: serde_json::Value,
}

#[must_use]
pub fn map_smetric_event(event: &SmetricSecurityEvent) -> SmetricActivityLogMapping {
    let event_type = match event {
        SmetricSecurityEvent::AclPolicyCreated { .. } => EventType::SmetricAclPolicyCreated,
        SmetricSecurityEvent::AclPolicyDeleted { .. } => EventType::SmetricAclPolicyDeleted,
        SmetricSecurityEvent::AclPolicyStateChanged { .. } => {
            EventType::SmetricAclPolicyStateChanged
        }
        SmetricSecurityEvent::AclRuleCreated { .. } => EventType::SmetricAclRuleCreated,
        SmetricSecurityEvent::AclRuleUpdated { .. } => EventType::SmetricAclRuleUpdated,
        SmetricSecurityEvent::AclRuleDeleted { .. } => EventType::SmetricAclRuleDeleted,
        SmetricSecurityEvent::AclAssignmentChanged { .. } => {
            EventType::SmetricAclAssignmentChanged
        }
        SmetricSecurityEvent::AclPolicyPublished { .. } => EventType::SmetricAclPolicyPublished,
        SmetricSecurityEvent::AclDeploymentQueued { .. } => {
            EventType::SmetricAclDeploymentQueued
        }
        SmetricSecurityEvent::AclDeploymentApplied { .. } => {
            EventType::SmetricAclDeploymentApplied
        }
        SmetricSecurityEvent::AclDeploymentFailed { .. } => {
            EventType::SmetricAclDeploymentFailed
        }
        SmetricSecurityEvent::AclDeploymentAckRejected { .. } => {
            EventType::SmetricAclDeploymentAckRejected
        }
        SmetricSecurityEvent::TrafficPolicyCreated { .. } => {
            EventType::SmetricTrafficPolicyCreated
        }
        SmetricSecurityEvent::TrafficPolicyUpdated { .. } => {
            EventType::SmetricTrafficPolicyUpdated
        }
        SmetricSecurityEvent::TrafficPolicyDeleted { .. } => {
            EventType::SmetricTrafficPolicyDeleted
        }
        SmetricSecurityEvent::TrafficPolicyStateChanged { .. } => {
            EventType::SmetricTrafficPolicyStateChanged
        }
        SmetricSecurityEvent::TrafficPolicyPublished { .. } => {
            EventType::SmetricTrafficPolicyPublished
        }
    };
    let module = match event.module() {
        SmetricEventModule::Vpn => ActivityLogModule::Vpn,
        SmetricEventModule::Client => ActivityLogModule::Client,
    };

    SmetricActivityLogMapping {
        event_type,
        module,
        description: event.description(),
        metadata: event.metadata(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use defguard_core::smetric_security_events::SMETRIC_SECURITY_SCHEMA;

    #[test]
    fn firewall_publish_maps_to_vpn_activity_log() {
        let event = SmetricSecurityEvent::AclPolicyPublished {
            policy_id: 42,
            revision: 7,
            checksum: "abc".into(),
            location_ids: vec![2, 3],
        };
        let mapped = map_smetric_event(&event);
        assert_eq!(mapped.event_type, EventType::SmetricAclPolicyPublished);
        assert_eq!(mapped.module, ActivityLogModule::Vpn);
        assert_eq!(mapped.metadata["schema"], SMETRIC_SECURITY_SCHEMA);
        assert_eq!(mapped.metadata["policy_id"], 42);
        assert_eq!(mapped.metadata["revision"], 7);
    }

    #[test]
    fn traffic_policy_publish_maps_to_client_activity_log() {
        let event = SmetricSecurityEvent::TrafficPolicyPublished {
            policy_id: 9,
            revision: 3,
            checksum: "def".into(),
            mode: "split_tunnel".into(),
            target_count: 2,
            destination_count: 4,
        };
        let mapped = map_smetric_event(&event);
        assert_eq!(mapped.event_type, EventType::SmetricTrafficPolicyPublished);
        assert_eq!(mapped.module, ActivityLogModule::Client);
        assert_eq!(mapped.metadata["target_count"], 2);
    }
}
