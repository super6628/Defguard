pub mod api;
pub mod deployment;
pub mod deployment_ack;
pub mod device_groups;
pub mod gateway;
pub mod location_effective;
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    Allow,
    Deny,
}

impl fmt::Display for DefaultAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        })
    }
}

impl FromStr for DefaultAction {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            _ => Err(ValidationError::InvalidEnumValue {
                field: "default_action",
                value: value.to_owned(),
            }),
        }
    }
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

impl Subject {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::User(_) => "user",
            Self::Group(_) => "group",
            Self::Device(_) => "device",
            Self::DeviceGroup(_) => "device_group",
            Self::Location(_) => "location",
            Self::Cidr(_) => "cidr",
        }
    }

    #[must_use]
    pub fn value(&self) -> Option<&str> {
        match self {
            Self::Any => None,
            Self::User(value)
            | Self::Group(value)
            | Self::Device(value)
            | Self::DeviceGroup(value)
            | Self::Location(value)
            | Self::Cidr(value) => Some(value),
        }
    }
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

impl Destination {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Cidr(_) => "cidr",
            Self::Ip(_) => "ip",
            Self::IpRange(_) => "ip_range",
            Self::Alias(_) => "alias",
            Self::Service(_) => "service",
        }
    }

    #[must_use]
    pub fn value(&self) -> Option<&str> {
        match self {
            Self::Any => None,
            Self::Cidr(value)
            | Self::Ip(value)
            | Self::IpRange(value)
            | Self::Alias(value)
            | Self::Service(value) => Some(value),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rule {
    pub id: i64,
    pub priority: i32,
    pub name: String,
    pub enabled: bool,
    pub source: Subject,
    pub destination: Destination,
    pub protocol: Protocol,
    pub ports: Option<PortRange>,
    pub action: Action,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Policy {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub default_action: DefaultAction,
    pub revision: u64,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompiledPolicy {
    pub policy_id: i64,
    pub revision: u64,
    pub default_action: DefaultAction,
    pub rules: Vec<Rule>,
    pub checksum: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("policy name cannot be empty")]
    EmptyPolicyName,
    #[error("rule {0} name cannot be empty")]
    EmptyRuleName(i64),
    #[error("rule {rule_id} has invalid priority {priority}")]
    InvalidPriority { rule_id: i64, priority: i32 },
    #[error("rule {rule_id} has invalid port range {start}-{end}")]
    InvalidPortRange { rule_id: i64, start: u16, end: u16 },
    #[error("rule {rule_id} protocol {protocol} cannot use ports")]
    PortsNotAllowed { rule_id: i64, protocol: Protocol },
    #[error("rule {rule_id} source selector is empty")]
    EmptySource { rule_id: i64 },
    #[error("rule {rule_id} destination selector is empty")]
    EmptyDestination { rule_id: i64 },
    #[error("rule {rule_id} has invalid CIDR '{value}'")]
    InvalidCidr { rule_id: i64, value: String },
    #[error("rule {rule_id} has invalid IP '{value}'")]
    InvalidIp { rule_id: i64, value: String },
    #[error("rule {rule_id} has invalid IP range '{value}'")]
    InvalidIpRange { rule_id: i64, value: String },
    #[error("invalid {field} value '{value}'")]
    InvalidEnumValue { field: &'static str, value: String },
}

fn validate_nonempty(rule_id: i64, value: &str, source: bool) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        if source {
            Err(ValidationError::EmptySource { rule_id })
        } else {
            Err(ValidationError::EmptyDestination { rule_id })
        }
    } else {
        Ok(())
    }
}

pub fn validate(policy: &Policy) -> Result<(), ValidationError> {
    if policy.name.trim().is_empty() {
        return Err(ValidationError::EmptyPolicyName);
    }

    for rule in &policy.rules {
        if rule.name.trim().is_empty() {
            return Err(ValidationError::EmptyRuleName(rule.id));
        }
        if rule.priority < 0 {
            return Err(ValidationError::InvalidPriority {
                rule_id: rule.id,
                priority: rule.priority,
            });
        }
        if let Some(ports) = &rule.ports {
            if ports.start == 0 || ports.end == 0 || ports.start > ports.end {
                return Err(ValidationError::InvalidPortRange {
                    rule_id: rule.id,
                    start: ports.start,
                    end: ports.end,
                });
            }
            if matches!(rule.protocol, Protocol::Any | Protocol::Icmp) {
                return Err(ValidationError::PortsNotAllowed {
                    rule_id: rule.id,
                    protocol: rule.protocol,
                });
            }
        }

        match &rule.source {
            Subject::Any => {}
            Subject::Cidr(value) => {
                validate_nonempty(rule.id, value, true)?;
                IpNetwork::from_str(value).map_err(|_| ValidationError::InvalidCidr {
                    rule_id: rule.id,
                    value: value.clone(),
                })?;
            }
            Subject::User(value)
            | Subject::Group(value)
            | Subject::Device(value)
            | Subject::DeviceGroup(value)
            | Subject::Location(value) => validate_nonempty(rule.id, value, true)?,
        }

        match &rule.destination {
            Destination::Any => {}
            Destination::Cidr(value) => {
                validate_nonempty(rule.id, value, false)?;
                IpNetwork::from_str(value).map_err(|_| ValidationError::InvalidCidr {
                    rule_id: rule.id,
                    value: value.clone(),
                })?;
            }
            Destination::Ip(value) => {
                validate_nonempty(rule.id, value, false)?;
                IpAddr::from_str(value).map_err(|_| ValidationError::InvalidIp {
                    rule_id: rule.id,
                    value: value.clone(),
                })?;
            }
            Destination::IpRange(value) => {
                validate_nonempty(rule.id, value, false)?;
                let (start, end) = value
                    .split_once('-')
                    .ok_or_else(|| ValidationError::InvalidIpRange {
                        rule_id: rule.id,
                        value: value.clone(),
                    })?;
                let start = IpAddr::from_str(start.trim()).map_err(|_| {
                    ValidationError::InvalidIpRange {
                        rule_id: rule.id,
                        value: value.clone(),
                    }
                })?;
                let end = IpAddr::from_str(end.trim()).map_err(|_| {
                    ValidationError::InvalidIpRange {
                        rule_id: rule.id,
                        value: value.clone(),
                    }
                })?;
                if start.is_ipv4() != end.is_ipv4() {
                    return Err(ValidationError::InvalidIpRange {
                        rule_id: rule.id,
                        value: value.clone(),
                    });
                }
            }
            Destination::Alias(value) | Destination::Service(value) => {
                validate_nonempty(rule.id, value, false)?;
            }
        }
    }
    Ok(())
}

pub fn compile(policy: Policy) -> Result<CompiledPolicy, ValidationError> {
    validate(&policy)?;
    let mut rules: Vec<Rule> = policy.rules.into_iter().filter(|rule| rule.enabled).collect();
    rules.sort_by_key(|rule| (rule.priority, rule.id));
    let canonical = serde_json::to_string(&(
        policy.id,
        policy.revision,
        policy.default_action,
        &rules,
    ))
    .expect("S-Metric ACL policy serialization cannot fail");
    Ok(CompiledPolicy {
        policy_id: policy.id,
        revision: policy.revision,
        default_action: policy.default_action,
        rules,
        checksum: digest(canonical),
    })
}
