use std::{net::IpAddr, str::FromStr};

use defguard_common::{
    gateway_event::GatewayCommand,
    gateway_types::{
        FirewallConfig, FirewallPolicy, FirewallRule, IpAddress, IpRange, IpVersion, Port,
        PortRange as GatewayPortRange, Protocol as GatewayProtocol,
    },
};
use ipnetwork::IpNetwork;
use sqlx::PgPool;

use super::service::{ServiceError, load_policy};
use super::{Action, CompiledPolicy, DefaultAction, Destination, Protocol, Rule, Subject, compile};

#[derive(Debug, thiserror::Error)]
pub enum GatewayEnforcementError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error("S-Metric ACL policy {0} is not assigned to any enabled VPN location")]
    NoAssignments(i64),
    #[error(
        "rule {rule_id} uses source selector '{selector}', which is not yet supported by gateway enforcement"
    )]
    UnsupportedSourceSelector {
        rule_id: i64,
        selector: &'static str,
    },
    #[error(
        "rule {rule_id} uses destination selector '{selector}', which is not yet supported by gateway enforcement"
    )]
    UnsupportedDestinationSelector {
        rule_id: i64,
        selector: &'static str,
    },
    #[error("rule {0} uses REJECT, but the current gateway protocol supports ALLOW/DENY only")]
    RejectUnsupported(i64),
    #[error("rule {0} mixes IPv4 and IPv6 selectors")]
    AddressFamilyMismatch(i64),
    #[error("rule {0} contains an invalid IP selector")]
    InvalidAddress(i64),
}

#[derive(Clone, Debug)]
pub struct GatewayDeployment {
    pub location_id: i64,
    pub command: GatewayCommand,
}

pub async fn prepare_deployments(
    pool: &PgPool,
    policy_id: i64,
) -> Result<Vec<GatewayDeployment>, GatewayEnforcementError> {
    let policy = compile(load_policy(pool, policy_id).await?).map_err(ServiceError::Validation)?;
    let config = translate_policy(&policy)?;
    let location_ids = sqlx::query_scalar::<_, i64>(
        "SELECT location_id FROM smetric_acl_policy_assignment WHERE policy_id = $1 AND enabled = TRUE ORDER BY location_id",
    )
    .bind(policy_id)
    .fetch_all(pool)
    .await?;

    if location_ids.is_empty() {
        return Err(GatewayEnforcementError::NoAssignments(policy_id));
    }

    Ok(location_ids
        .into_iter()
        .map(|location_id| GatewayDeployment {
            location_id,
            command: GatewayCommand::FirewallConfigChanged(location_id, config.clone()),
        })
        .collect())
}

pub fn translate_policy(
    policy: &CompiledPolicy,
) -> Result<FirewallConfig, GatewayEnforcementError> {
    let default_policy = match policy.default_action {
        DefaultAction::Allow => FirewallPolicy::Allow,
        DefaultAction::Deny => FirewallPolicy::Deny,
    };

    let mut rules = Vec::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        rules.push(translate_rule(rule, policy.revision)?);
    }

    Ok(FirewallConfig {
        default_policy,
        rules,
        snat_bindings: Vec::new(),
    })
}

fn translate_rule(rule: &Rule, revision: u64) -> Result<FirewallRule, GatewayEnforcementError> {
    let (source_addrs, source_version) = translate_source(rule)?;
    let (destination_addrs, destination_version) = translate_destination(rule)?;
    let ip_version = merge_ip_versions(rule.id, source_version, destination_version)?;

    let destination_ports = match &rule.ports {
        Some(ports) if ports.start == ports.end => vec![Port::Single(u32::from(ports.start))],
        Some(ports) => vec![Port::Range(GatewayPortRange {
            start: u32::from(ports.start),
            end: u32::from(ports.end),
        })],
        None => Vec::new(),
    };

    let protocols = match rule.protocol {
        Protocol::Any => Vec::new(),
        Protocol::Tcp => vec![GatewayProtocol::Tcp],
        Protocol::Udp => vec![GatewayProtocol::Udp],
        Protocol::Icmp => vec![GatewayProtocol::Icmp],
    };

    let verdict = match rule.action {
        Action::Allow => FirewallPolicy::Allow,
        Action::Deny => FirewallPolicy::Deny,
        Action::Reject => return Err(GatewayEnforcementError::RejectUnsupported(rule.id)),
    };

    Ok(FirewallRule {
        id: rule.id,
        source_addrs,
        destination_addrs,
        destination_ports,
        protocols,
        verdict,
        comment: Some(format!(
            "S-Metric ACL rev {revision} priority {} - {}",
            rule.priority, rule.name
        )),
        ip_version,
    })
}

fn translate_source(rule: &Rule) -> Result<(Vec<IpAddress>, IpVersion), GatewayEnforcementError> {
    match &rule.source {
        Subject::Any => Ok((Vec::new(), IpVersion::Unspecified)),
        Subject::Cidr(value) => {
            let network = IpNetwork::from_str(value)
                .map_err(|_| GatewayEnforcementError::InvalidAddress(rule.id))?;
            Ok((
                vec![IpAddress::IpSubnet(value.clone())],
                network_version(network),
            ))
        }
        Subject::User(_) => Err(GatewayEnforcementError::UnsupportedSourceSelector {
            rule_id: rule.id,
            selector: "user",
        }),
        Subject::Group(_) => Err(GatewayEnforcementError::UnsupportedSourceSelector {
            rule_id: rule.id,
            selector: "group",
        }),
        Subject::Device(_) => Err(GatewayEnforcementError::UnsupportedSourceSelector {
            rule_id: rule.id,
            selector: "device",
        }),
        Subject::DeviceGroup(_) => Err(GatewayEnforcementError::UnsupportedSourceSelector {
            rule_id: rule.id,
            selector: "device_group",
        }),
        Subject::Location(_) => Err(GatewayEnforcementError::UnsupportedSourceSelector {
            rule_id: rule.id,
            selector: "location",
        }),
    }
}

fn translate_destination(
    rule: &Rule,
) -> Result<(Vec<IpAddress>, IpVersion), GatewayEnforcementError> {
    match &rule.destination {
        Destination::Any => Ok((Vec::new(), IpVersion::Unspecified)),
        Destination::Cidr(value) => {
            let network = IpNetwork::from_str(value)
                .map_err(|_| GatewayEnforcementError::InvalidAddress(rule.id))?;
            Ok((
                vec![IpAddress::IpSubnet(value.clone())],
                network_version(network),
            ))
        }
        Destination::Ip(value) => {
            let ip = IpAddr::from_str(value)
                .map_err(|_| GatewayEnforcementError::InvalidAddress(rule.id))?;
            Ok((vec![IpAddress::Ip(value.clone())], ip_version(ip)))
        }
        Destination::IpRange(value) => {
            let (start, end) = value
                .split_once('-')
                .ok_or(GatewayEnforcementError::InvalidAddress(rule.id))?;
            let start = IpAddr::from_str(start.trim())
                .map_err(|_| GatewayEnforcementError::InvalidAddress(rule.id))?;
            let end = IpAddr::from_str(end.trim())
                .map_err(|_| GatewayEnforcementError::InvalidAddress(rule.id))?;
            let version = merge_ip_versions(rule.id, ip_version(start), ip_version(end))?;
            Ok((
                vec![IpAddress::IpRange(IpRange {
                    start: start.to_string(),
                    end: end.to_string(),
                })],
                version,
            ))
        }
        Destination::Alias(_) => Err(GatewayEnforcementError::UnsupportedDestinationSelector {
            rule_id: rule.id,
            selector: "alias",
        }),
        Destination::Service(_) => Err(GatewayEnforcementError::UnsupportedDestinationSelector {
            rule_id: rule.id,
            selector: "service",
        }),
    }
}

fn network_version(network: IpNetwork) -> IpVersion {
    if network.is_ipv4() {
        IpVersion::Ipv4
    } else {
        IpVersion::Ipv6
    }
}

fn ip_version(ip: IpAddr) -> IpVersion {
    if ip.is_ipv4() {
        IpVersion::Ipv4
    } else {
        IpVersion::Ipv6
    }
}

fn merge_ip_versions(
    rule_id: i64,
    left: IpVersion,
    right: IpVersion,
) -> Result<IpVersion, GatewayEnforcementError> {
    match (left, right) {
        (IpVersion::Unspecified, other) | (other, IpVersion::Unspecified) => Ok(other),
        (IpVersion::Ipv4, IpVersion::Ipv4) => Ok(IpVersion::Ipv4),
        (IpVersion::Ipv6, IpVersion::Ipv6) => Ok(IpVersion::Ipv6),
        _ => Err(GatewayEnforcementError::AddressFamilyMismatch(rule_id)),
    }
}
