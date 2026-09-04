pub mod api;
pub mod gateway;
pub mod service;

use std::{fmt, net::IpAddr, str::FromStr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sha256::digest;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    Reject,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Subject {
    Any,
    User(String),
    Group(String),
    Device(String),
    DeviceGroup(String),
    Location(String),
    Cidr(String),
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Destination {
    Any,
    Cidr(String),
    Ip(String),
    IpRange(String),
    Alias(String),
    Service(String),
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rule {
    pub id: i64,
    pub name: String,
    pub priority: u32,
    pub enabled: bool,
    pub action: Action,
    pub protocol: Protocol,
    pub ports: Option<PortRange>,
    pub source: Subject,
    pub destination: Destination,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Allow,
    Deny,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Policy {
    pub id: i64,
    pub name: String,
    pub revision: u64,
    pub default_action: DefaultAction,
    pub rules: Vec<Rule>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompiledPolicy {
    pub policy_id: i64,
    pub revision: u64,
    pub checksum: String,
    pub default_action: DefaultAction,
    pub rules: Vec<Rule>,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ValidationError {
    #[error("policy name cannot be empty")]
    EmptyPolicyName,
    #[error("policy revision must be greater than zero")]
    InvalidRevision,
    #[error("rule {0} has an empty name")]
    EmptyRuleName(i64),
    #[error("duplicate ACL priority {0}")]
    DuplicatePriority(u32),
    #[error("rule {0} has an invalid port range")]
    InvalidPortRange(i64),
    #[error("rule {0} uses ports with a protocol that does not support ports")]
    PortsWithUnsupportedProtocol(i64),
    #[error("rule {0} contains an invalid CIDR")]
    InvalidCidr(i64),
    #[error("rule {0} contains an invalid IP address")]
    InvalidIp(i64),
    #[error("rule {0} contains an invalid IP range")]
    InvalidIpRange(i64),
    #[error("rule {0} contains an empty selector value")]
    EmptySelector(i64),
}

impl Policy {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.name.trim().is_empty() {
            return Err(ValidationError::EmptyPolicyName);
        }
        if self.revision == 0 {
            return Err(ValidationError::InvalidRevision);
        }
        let mut priorities = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.name.trim().is_empty() {
                return Err(ValidationError::EmptyRuleName(rule.id));
            }
            if !priorities.insert(rule.priority) {
                return Err(ValidationError::DuplicatePriority(rule.priority));
            }
            if let Some(ports) = &rule.ports {
                if ports.start == 0 || ports.end == 0 || ports.start > ports.end {
                    return Err(ValidationError::InvalidPortRange(rule.id));
                }
                if !matches!(rule.protocol, Protocol::Tcp | Protocol::Udp) {
                    return Err(ValidationError::PortsWithUnsupportedProtocol(rule.id));
                }
            }
            validate_source(rule)?;
            validate_destination(rule)?;
        }
        Ok(())
    }
}
fn validate_source(rule: &Rule) -> Result<(), ValidationError> {
    match &rule.source {
        Subject::Any => Ok(()),
        Subject::Cidr(v) => IpNetwork::from_str(v)
            .map(|_| ())
            .map_err(|_| ValidationError::InvalidCidr(rule.id)),
        Subject::User(v)
        | Subject::Group(v)
        | Subject::Device(v)
        | Subject::DeviceGroup(v)
        | Subject::Location(v) => validate_nonempty(rule.id, v),
    }
}
fn validate_destination(rule: &Rule) -> Result<(), ValidationError> {
    match &rule.destination {
        Destination::Any => Ok(()),
        Destination::Cidr(v) => IpNetwork::from_str(v)
            .map(|_| ())
            .map_err(|_| ValidationError::InvalidCidr(rule.id)),
        Destination::Ip(v) => IpAddr::from_str(v)
            .map(|_| ())
            .map_err(|_| ValidationError::InvalidIp(rule.id)),
        Destination::IpRange(v) => {
            let Some((s, e)) = v.split_once('-') else {
                return Err(ValidationError::InvalidIpRange(rule.id));
            };
            let s =
                IpAddr::from_str(s.trim()).map_err(|_| ValidationError::InvalidIpRange(rule.id))?;
            let e =
                IpAddr::from_str(e.trim()).map_err(|_| ValidationError::InvalidIpRange(rule.id))?;
            if std::mem::discriminant(&s) != std::mem::discriminant(&e) {
                return Err(ValidationError::InvalidIpRange(rule.id));
            }
            Ok(())
        }
        Destination::Alias(v) | Destination::Service(v) => validate_nonempty(rule.id, v),
    }
}
fn validate_nonempty(id: i64, v: &str) -> Result<(), ValidationError> {
    if v.trim().is_empty() {
        Err(ValidationError::EmptySelector(id))
    } else {
        Ok(())
    }
}
pub fn compile(mut policy: Policy) -> Result<CompiledPolicy, ValidationError> {
    policy.validate()?;
    policy.rules.retain(|r| r.enabled);
    policy.rules.sort_by_key(|r| (r.priority, r.id));
    let canonical = serde_json::to_string(&(
        policy.id,
        policy.revision,
        policy.default_action,
        &policy.rules,
    ))
    .expect("S-Metric ACL policy serialization must succeed");
    let checksum = digest(canonical);
    Ok(CompiledPolicy {
        policy_id: policy.id,
        revision: policy.revision,
        checksum,
        default_action: policy.default_action,
        rules: policy.rules,
    })
}
impl fmt::Display for DefaultAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rule(id: i64, priority: u32) -> Rule {
        Rule {
            id,
            name: format!("rule-{id}"),
            priority,
            enabled: true,
            action: Action::Allow,
            protocol: Protocol::Tcp,
            ports: Some(PortRange {
                start: 443,
                end: 443,
            }),
            source: Subject::Group("accounting".into()),
            destination: Destination::Cidr("10.20.30.0/24".into()),
        }
    }
    #[test]
    fn compiler_orders_rules_deterministically() {
        let p = Policy {
            id: 1,
            name: "Corporate".into(),
            revision: 7,
            default_action: DefaultAction::Deny,
            rules: vec![rule(2, 200), rule(1, 100)],
        };
        let c = compile(p).unwrap();
        assert_eq!(c.rules[0].priority, 100);
        assert_eq!(c.rules[1].priority, 200);
        assert!(!c.checksum.is_empty());
    }
    #[test]
    fn duplicate_priorities_are_rejected() {
        let p = Policy {
            id: 1,
            name: "Corporate".into(),
            revision: 1,
            default_action: DefaultAction::Deny,
            rules: vec![rule(1, 100), rule(2, 100)],
        };
        assert_eq!(compile(p), Err(ValidationError::DuplicatePriority(100)));
    }
    #[test]
    fn ports_require_tcp_or_udp() {
        let mut r = rule(1, 100);
        r.protocol = Protocol::Icmp;
        let p = Policy {
            id: 1,
            name: "Corporate".into(),
            revision: 1,
            default_action: DefaultAction::Deny,
            rules: vec![r],
        };
        assert_eq!(
            compile(p),
            Err(ValidationError::PortsWithUnsupportedProtocol(1))
        );
    }
}
