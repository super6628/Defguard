use std::{net::IpAddr, str::FromStr};

use defguard_common::gateway_types::{
    FirewallConfig, FirewallPolicy, FirewallRule, IpAddress, IpRange, IpVersion, Port,
    PortRange as GatewayPortRange, Protocol as GatewayProtocol, SnatBinding,
};
use ipnetwork::IpNetwork;
use sqlx::PgPool;

use super::service::ServiceError;
use super::{Action, CompiledPolicy, DefaultAction, Destination, Protocol, Rule, Subject};

#[derive(Debug, thiserror::Error)]
pub enum GatewayEnforcementError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(
        "rule {rule_id} source selector '{selector}' resolved to no VPN addresses at location {location_id}"
    )]
    EmptySourceResolution {
        rule_id: i64,
        selector: String,
        location_id: i64,
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

pub async fn translate_policy_for_location(
    pool: &PgPool,
    policy: &CompiledPolicy,
    location_id: i64,
) -> Result<FirewallConfig, GatewayEnforcementError> {
    let default_policy = match policy.default_action {
        DefaultAction::Allow => FirewallPolicy::Allow,
        DefaultAction::Deny => FirewallPolicy::Deny,
    };
    let mut rules = Vec::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        rules.push(translate_rule(pool, rule, policy.revision, location_id).await?);
    }
    let snat_bindings = resolve_snat_bindings(pool, location_id).await?;
    Ok(FirewallConfig {
        default_policy,
        rules,
        snat_bindings,
    })
}

async fn resolve_snat_bindings(
    pool: &PgPool,
    location_id: i64,
) -> Result<Vec<SnatBinding>, sqlx::Error> {
    let bindings = sqlx::query_as::<_, (i64, i64, IpAddr)>(
        "SELECT id, user_id, public_ip FROM user_snat_binding WHERE location_id = $1 ORDER BY id",
    )
    .bind(location_id)
    .fetch_all(pool)
    .await?;

    let mut result = Vec::with_capacity(bindings.len());
    for (binding_id, user_id, public_ip) in bindings {
        let mut source_ips = sqlx::query_scalar::<_, IpAddr>(
            "SELECT DISTINCT unnest(wnd.wireguard_ips)::inet FROM wireguard_network_device wnd JOIN device d ON d.id = wnd.device_id JOIN \"user\" u ON u.id = d.user_id WHERE wnd.wireguard_network_id = $1 AND u.id = $2 AND u.is_active = TRUE AND d.configured = TRUE ORDER BY 1",
        )
        .bind(location_id)
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        source_ips.retain(|ip| ip.is_ipv4() == public_ip.is_ipv4());
        source_ips.sort();
        source_ips.dedup();
        if source_ips.is_empty() {
            continue;
        }
        result.push(SnatBinding {
            id: binding_id,
            source_addrs: source_ips
                .into_iter()
                .map(|ip| IpAddress::Ip(ip.to_string()))
                .collect(),
            public_ip: public_ip.to_string(),
            comment: Some(format!("S-Metric preserved user {user_id} SNAT binding {binding_id}")),
        });
    }
    Ok(result)
}

async fn translate_rule(
    pool: &PgPool,
    rule: &Rule,
    revision: u64,
    location_id: i64,
) -> Result<FirewallRule, GatewayEnforcementError> {
    let (source_addrs, source_version) = translate_source(pool, rule, location_id).await?;
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

async fn translate_source(
    pool: &PgPool,
    rule: &Rule,
    location_id: i64,
) -> Result<(Vec<IpAddress>, IpVersion), GatewayEnforcementError> {
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
        Subject::User(username) => resolved_source(
            rule.id,
            location_id,
            format!("user:{username}"),
            resolve_user_ips(pool, location_id, username).await?,
        ),
        Subject::Group(group_name) => resolved_source(
            rule.id,
            location_id,
            format!("group:{group_name}"),
            resolve_group_ips(pool, location_id, group_name).await?,
        ),
        Subject::Device(device_name) => resolved_source(
            rule.id,
            location_id,
            format!("device:{device_name}"),
            resolve_device_ips(pool, location_id, device_name).await?,
        ),
        Subject::DeviceGroup(group_name) => resolved_source(
            rule.id,
            location_id,
            format!("device_group:{group_name}"),
            resolve_device_group_ips(pool, location_id, group_name).await?,
        ),
        Subject::Location(location_name) => resolved_source(
            rule.id,
            location_id,
            format!("location:{location_name}"),
            resolve_location_ips(pool, location_id, location_name).await?,
        ),
    }
}

async fn resolve_user_ips(
    pool: &PgPool,
    location_id: i64,
    username: &str,
) -> Result<Vec<IpAddr>, sqlx::Error> {
    sqlx::query_scalar::<_, IpAddr>(
        "SELECT DISTINCT unnest(wnd.wireguard_ips)::inet FROM wireguard_network_device wnd JOIN device d ON d.id = wnd.device_id JOIN \"user\" u ON u.id = d.user_id WHERE wnd.wireguard_network_id = $1 AND u.username = $2 AND u.is_active = TRUE AND d.configured = TRUE ORDER BY 1",
    )
    .bind(location_id)
    .bind(username)
    .fetch_all(pool)
    .await
}

async fn resolve_group_ips(
    pool: &PgPool,
    location_id: i64,
    group_name: &str,
) -> Result<Vec<IpAddr>, sqlx::Error> {
    sqlx::query_scalar::<_, IpAddr>(
        "SELECT DISTINCT unnest(wnd.wireguard_ips)::inet FROM wireguard_network_device wnd JOIN device d ON d.id = wnd.device_id JOIN \"user\" u ON u.id = d.user_id JOIN group_user gu ON gu.user_id = u.id JOIN \"group\" g ON g.id = gu.group_id WHERE wnd.wireguard_network_id = $1 AND g.name = $2 AND u.is_active = TRUE AND d.configured = TRUE ORDER BY 1",
    )
    .bind(location_id)
    .bind(group_name)
    .fetch_all(pool)
    .await
}

async fn resolve_device_ips(
    pool: &PgPool,
    location_id: i64,
    device_name: &str,
) -> Result<Vec<IpAddr>, sqlx::Error> {
    sqlx::query_scalar::<_, IpAddr>(
        "SELECT DISTINCT unnest(wnd.wireguard_ips)::inet FROM wireguard_network_device wnd JOIN device d ON d.id = wnd.device_id WHERE wnd.wireguard_network_id = $1 AND d.name = $2 AND d.configured = TRUE ORDER BY 1",
    )
    .bind(location_id)
    .bind(device_name)
    .fetch_all(pool)
    .await
}

async fn resolve_device_group_ips(
    pool: &PgPool,
    location_id: i64,
    group_name: &str,
) -> Result<Vec<IpAddr>, sqlx::Error> {
    sqlx::query_scalar::<_, IpAddr>(
        "SELECT DISTINCT unnest(wnd.wireguard_ips)::inet FROM smetric_acl_device_group dg JOIN smetric_acl_device_group_member dgm ON dgm.group_id = dg.id JOIN device d ON d.id = dgm.device_id JOIN wireguard_network_device wnd ON wnd.device_id = d.id WHERE dg.name = $1 AND dg.enabled = TRUE AND d.configured = TRUE AND wnd.wireguard_network_id = $2 ORDER BY 1",
    )
    .bind(group_name)
    .bind(location_id)
    .fetch_all(pool)
    .await
}

async fn resolve_location_ips(
    pool: &PgPool,
    deployment_location_id: i64,
    location_name: &str,
) -> Result<Vec<IpAddr>, sqlx::Error> {
    sqlx::query_scalar::<_, IpAddr>(
        "SELECT DISTINCT unnest(wnd.wireguard_ips)::inet FROM wireguard_network wn JOIN wireguard_network_device wnd ON wnd.wireguard_network_id = wn.id JOIN device d ON d.id = wnd.device_id WHERE wn.id = $1 AND wn.name = $2 AND d.configured = TRUE ORDER BY 1",
    )
    .bind(deployment_location_id)
    .bind(location_name)
    .fetch_all(pool)
    .await
}

fn resolved_source(
    rule_id: i64,
    location_id: i64,
    selector: String,
    mut ips: Vec<IpAddr>,
) -> Result<(Vec<IpAddress>, IpVersion), GatewayEnforcementError> {
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        return Err(GatewayEnforcementError::EmptySourceResolution {
            rule_id,
            selector,
            location_id,
        });
    }
    let mut version = IpVersion::Unspecified;
    let mut addrs = Vec::with_capacity(ips.len());
    for ip in ips {
        version = merge_ip_versions(rule_id, version, ip_version(ip))?;
        addrs.push(IpAddress::Ip(ip.to_string()));
    }
    Ok((addrs, version))
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
