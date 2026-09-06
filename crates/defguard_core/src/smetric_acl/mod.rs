pub mod api;
pub mod deployment;
pub mod deployment_ack;
pub mod device_groups;
pub mod gateway;
pub mod location_deployment;
pub mod location_effective;
pub mod security_event;
pub mod service;
#[path = "../smetric_traffic_policy.rs"]
pub mod traffic_policy;

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

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Reject => "reject",
        })
    }
}

impl FromStr for Action {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "reject" => Ok(Self::Reject),
            _ => Err(ValidationError::InvalidEnumValue {
                field: "action",
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Any => "any",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        })
    }
}

impl FromStr for Protocol {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "any" => Ok(Self::Any),
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "icmp" => Ok(Self::Icmp),
            _ => Err(ValidationError::InvalidEnumValue {
                field: "protocol",
                value: value.to_owned(),
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SourceSelector {
    #[serde(default)]
    pub users: Vec<i64>,
    #[serde(default)]
    pub groups: Vec<i64>,
    #[serde(default)]
    pub devices: Vec<i64>,
    #[serde(default)]
    pub device_groups: Vec<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DestinationSelector {
    #[serde(default)]
    pub networks: Vec<IpNetwork>,
    #[serde(default)]
    pub ranges: Vec<IpRange>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IpRange {
    pub start: IpAddr,
    pub end: IpAddr,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AclRuleDefinition {
    pub id: String,
    pub priority: i32,
    pub action: Action,
    pub protocol: Protocol,
    pub source: SourceSelector,
    pub destination: DestinationSelector,
    #[serde(default)]
    pub source_ports: Vec<PortRange>,
    #[serde(default)]
    pub destination_ports: Vec<PortRange>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AclPolicyDefinition {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub rules: Vec<AclRuleDefinition>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EffectiveAclPolicy {
    pub policy_id: String,
    pub revision: i64,
    pub checksum: String,
    pub policy: AclPolicyDefinition,
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("{field} cannot be empty")]
    EmptyField { field: &'static str },
    #[error("invalid value for {field}: {value}")]
    InvalidEnumValue { field: &'static str, value: String },
    #[error("invalid port range {start}-{end}")]
    InvalidPortRange { start: u16, end: u16 },
    #[error("invalid IP range {start}-{end}")]
    InvalidIpRange { start: IpAddr, end: IpAddr },
    #[error("ACL policy must contain at least one rule")]
    EmptyRules,
    #[error("duplicate rule id: {0}")]
    DuplicateRuleId(String),
}

pub fn validate_policy(policy: &AclPolicyDefinition) -> Result<(), ValidationError> {
    if policy.id.trim().is_empty() {
        return Err(ValidationError::EmptyField { field: "policy.id" });
    }
    if policy.name.trim().is_empty() {
        return Err(ValidationError::EmptyField { field: "policy.name" });
    }
    if policy.rules.is_empty() {
        return Err(ValidationError::EmptyRules);
    }

    let mut rule_ids = std::collections::HashSet::new();
    for rule in &policy.rules {
        if rule.id.trim().is_empty() {
            return Err(ValidationError::EmptyField { field: "rule.id" });
        }
        if !rule_ids.insert(rule.id.as_str()) {
            return Err(ValidationError::DuplicateRuleId(rule.id.clone()));
        }
        validate_rule(rule)?;
    }

    Ok(())
}

fn validate_rule(rule: &AclRuleDefinition) -> Result<(), ValidationError> {
    for range in rule.source_ports.iter().chain(&rule.destination_ports) {
        if range.start == 0 || range.end == 0 || range.start > range.end {
            return Err(ValidationError::InvalidPortRange {
                start: range.start,
                end: range.end,
            });
        }
    }

    for range in &rule.destination.ranges {
        let valid = match (range.start, range.end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => start.octets() <= end.octets(),
            (IpAddr::V6(start), IpAddr::V6(end)) => start.octets() <= end.octets(),
            _ => false,
        };
        if !valid {
            return Err(ValidationError::InvalidIpRange {
                start: range.start,
                end: range.end,
            });
        }
    }

    Ok(())
}

pub fn policy_checksum(policy: &AclPolicyDefinition) -> String {
    let json = serde_json::to_string(policy).expect("ACL policy serialization should not fail");
    digest(json)
}
