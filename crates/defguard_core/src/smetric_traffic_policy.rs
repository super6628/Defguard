//! Independent S-Metric client traffic policy domain model.
//!
//! This module defines the server/client contract without depending on inherited enterprise
//! traffic-policy code. Persistence and HTTP wiring are layered on top separately.

#[path = "smetric_traffic_policy/api.rs"]
pub mod api;
#[path = "smetric_traffic_policy/service.rs"]
pub mod service;

use std::net::IpAddr;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficMode {
    FullTunnel,
    SplitTunnel,
    Bypass,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TrafficTarget {
    Global,
    Location(i64),
    Group(i64),
    User(i64),
    Device(i64),
}

impl TrafficTarget {
    /// Higher specificity wins before policy priority is considered.
    pub const fn specificity(&self) -> u8 {
        match self {
            Self::Global => 0,
            Self::Location(_) => 1,
            Self::Group(_) => 2,
            Self::User(_) => 3,
            Self::Device(_) => 4,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TrafficDestination {
    Cidr(IpNetwork),
    Ip(IpAddr),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TrafficPolicy {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub mode: TrafficMode,
    pub priority: u32,
    pub revision: u64,
    pub targets: Vec<TrafficTarget>,
    pub destinations: Vec<TrafficDestination>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EffectiveTrafficPolicy {
    pub policy_id: i64,
    pub revision: u64,
    pub mode: TrafficMode,
    pub destinations: Vec<TrafficDestination>,
}

/// Select the deterministic effective policy from already-matched candidates.
///
/// Target specificity is Device > User > Group > Location > Global. Within the same specificity,
/// lower numeric policy priority wins, followed by policy id as a stable tie-breaker.
pub fn resolve_effective_policy<'a, I>(candidates: I) -> Option<&'a TrafficPolicy>
where
    I: IntoIterator<Item = (&'a TrafficPolicy, &'a TrafficTarget)>,
{
    candidates
        .into_iter()
        .filter(|(policy, _)| policy.enabled)
        .max_by(|(left_policy, left_target), (right_policy, right_target)| {
            left_target
                .specificity()
                .cmp(&right_target.specificity())
                .then_with(|| right_policy.priority.cmp(&left_policy.priority))
                .then_with(|| right_policy.id.cmp(&left_policy.id))
        })
        .map(|(policy, _)| policy)
}

impl From<&TrafficPolicy> for EffectiveTrafficPolicy {
    fn from(policy: &TrafficPolicy) -> Self {
        Self {
            policy_id: policy.id,
            revision: policy.revision,
            mode: policy.mode,
            destinations: policy.destinations.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(id: i64, priority: u32) -> TrafficPolicy {
        TrafficPolicy {
            id,
            name: format!("policy-{id}"),
            description: None,
            enabled: true,
            mode: TrafficMode::SplitTunnel,
            priority,
            revision: 1,
            targets: Vec::new(),
            destinations: Vec::new(),
        }
    }

    #[test]
    fn device_target_beats_lower_specificity() {
        let device = policy(1, 100);
        let user = policy(2, 1);
        let selected = resolve_effective_policy([
            (&user, &TrafficTarget::User(10)),
            (&device, &TrafficTarget::Device(20)),
        ]);
        assert_eq!(selected.map(|policy| policy.id), Some(1));
    }

    #[test]
    fn complete_specificity_order_is_stable() {
        let global = policy(1, 1);
        let location = policy(2, 1);
        let group = policy(3, 1);
        let user = policy(4, 1);
        let device = policy(5, 1);
        let selected = resolve_effective_policy([
            (&global, &TrafficTarget::Global),
            (&location, &TrafficTarget::Location(10)),
            (&group, &TrafficTarget::Group(20)),
            (&user, &TrafficTarget::User(30)),
            (&device, &TrafficTarget::Device(40)),
        ]);
        assert_eq!(selected.map(|policy| policy.id), Some(5));
    }

    #[test]
    fn lower_priority_number_wins_with_same_specificity() {
        let first = policy(1, 50);
        let second = policy(2, 10);
        let selected = resolve_effective_policy([
            (&first, &TrafficTarget::Group(1)),
            (&second, &TrafficTarget::Group(2)),
        ]);
        assert_eq!(selected.map(|policy| policy.id), Some(2));
    }

    #[test]
    fn lower_policy_id_breaks_equal_priority_ties() {
        let first = policy(10, 25);
        let second = policy(20, 25);
        let selected = resolve_effective_policy([
            (&second, &TrafficTarget::Location(1)),
            (&first, &TrafficTarget::Location(2)),
        ]);
        assert_eq!(selected.map(|policy| policy.id), Some(10));
    }

    #[test]
    fn disabled_policy_is_never_selected() {
        let mut device = policy(1, 1);
        device.enabled = false;
        let global = policy(2, 100);
        let selected = resolve_effective_policy([
            (&device, &TrafficTarget::Device(20)),
            (&global, &TrafficTarget::Global),
        ]);
        assert_eq!(selected.map(|policy| policy.id), Some(2));
    }

    #[test]
    fn no_enabled_candidates_returns_none() {
        let mut policy = policy(1, 1);
        policy.enabled = false;
        let selected = resolve_effective_policy([(&policy, &TrafficTarget::Global)]);
        assert!(selected.is_none());
    }
}
