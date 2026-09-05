use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};

use super::{
    Action, DefaultAction, Destination, Policy, PortRange, Protocol, Rule, Subject,
    ValidationError, compile, validate,
};

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("invalid stored S-Metric ACL value: {0}")]
    InvalidStoredValue(String),
    #[error("S-Metric ACL policy {0} was not found")]
    PolicyNotFound(i64),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicySummary {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub default_action: DefaultAction,
    pub revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreatePolicy {
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub default_action: DefaultAction,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateRule {
    pub name: String,
    pub description: Option<String>,
    pub priority: u32,
    pub enabled: bool,
    pub action: Action,
    pub protocol: Protocol,
    pub ports: Option<PortRange>,
    pub source: Subject,
    pub destination: Destination,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishedPolicy {
    pub policy_id: i64,
    pub revision: u64,
    pub checksum: String,
}

pub async fn list_policies(pool: &PgPool) -> Result<Vec<PolicySummary>, ServiceError> {
    let rows = sqlx::query_as::<_, (i64, String, Option<String>, bool, String, i64)>(
        "SELECT id, name, description, enabled, default_action, revision FROM smetric_acl_policy ORDER BY name, id",
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter().map(summary_from_row).collect()
}

pub async fn create_policy(
    pool: &PgPool,
    input: CreatePolicy,
) -> Result<PolicySummary, ServiceError> {
    if input.name.trim().is_empty() {
        return Err(ValidationError::EmptyPolicyName.into());
    }
    let row = sqlx::query_as::<_, (i64, String, Option<String>, bool, String, i64)>(
        "INSERT INTO smetric_acl_policy (name, description, enabled, default_action) VALUES ($1, $2, $3, $4) RETURNING id, name, description, enabled, default_action, revision",
    )
    .bind(input.name.trim())
    .bind(input.description)
    .bind(input.enabled)
    .bind(input.default_action.to_string())
    .fetch_one(pool)
    .await?;
    summary_from_row(row)
}

pub async fn delete_policy(pool: &PgPool, policy_id: i64) -> Result<(), ServiceError> {
    let result = sqlx::query("DELETE FROM smetric_acl_policy WHERE id = $1")
        .bind(policy_id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ServiceError::PolicyNotFound(policy_id));
    }
    Ok(())
}

pub async fn add_rule(
    pool: &PgPool,
    policy_id: i64,
    input: CreateRule,
) -> Result<Rule, ServiceError> {
    let mut tx = pool.begin().await?;
    ensure_policy(&mut tx, policy_id).await?;
    let (source_kind, source_value) = encode_subject(&input.source);
    let (destination_kind, destination_value) = encode_destination(&input.destination);
    let ports = input
        .ports
        .as_ref()
        .map(|p| format!("[{},{}]", p.start, u32::from(p.end) + 1));
    let row = sqlx::query_as::<_, (i64, String, i32, bool, String, String, Option<String>, String, Option<String>, String, Option<String>)>(
        "INSERT INTO smetric_acl_rule (policy_id, name, description, priority, enabled, action, protocol, ports, source_kind, source_value, destination_kind, destination_value) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::int8range,$9,$10,$11,$12) RETURNING id,name,priority,enabled,action,protocol,ports::text,source_kind,source_value,destination_kind,destination_value",
    )
    .bind(policy_id)
    .bind(input.name.trim())
    .bind(input.description)
    .bind(i32::try_from(input.priority).map_err(|_| ServiceError::InvalidStoredValue("priority exceeds PostgreSQL INTEGER".into()))?)
    .bind(input.enabled)
    .bind(action_str(input.action))
    .bind(protocol_str(input.protocol))
    .bind(ports)
    .bind(source_kind)
    .bind(source_value)
    .bind(destination_kind)
    .bind(destination_value)
    .fetch_one(&mut *tx)
    .await?;
    bump_revision(&mut tx, policy_id).await?;
    tx.commit().await?;
    rule_from_row(row)
}

pub async fn load_policy(pool: &PgPool, policy_id: i64) -> Result<Policy, ServiceError> {
    let row = sqlx::query_as::<_, (i64, String, Option<String>, bool, String, i64)>(
        "SELECT id, name, description, enabled, default_action, revision FROM smetric_acl_policy WHERE id = $1",
    )
    .bind(policy_id)
    .fetch_optional(pool)
    .await?
    .ok_or(ServiceError::PolicyNotFound(policy_id))?;
    let rules = sqlx::query_as::<_, (i64, String, i32, bool, String, String, Option<String>, String, Option<String>, String, Option<String>)>(
        "SELECT id,name,priority,enabled,action,protocol,ports::text,source_kind,source_value,destination_kind,destination_value FROM smetric_acl_rule WHERE policy_id=$1 ORDER BY priority,id",
    )
    .bind(policy_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(rule_from_row)
    .collect::<Result<Vec<_>, _>>()?;
    Ok(Policy {
        id: row.0,
        name: row.1,
        description: row.2,
        enabled: row.3,
        default_action: parse_default_action(&row.4)?,
        revision: u64::try_from(row.5)
            .map_err(|_| ServiceError::InvalidStoredValue("negative revision".into()))?,
        rules,
    })
}

pub async fn validate_policy(pool: &PgPool, policy_id: i64) -> Result<Policy, ServiceError> {
    let policy = load_policy(pool, policy_id).await?;
    validate(&policy)?;
    Ok(policy)
}

pub async fn publish_policy(
    pool: &PgPool,
    policy_id: i64,
) -> Result<PublishedPolicy, ServiceError> {
    let compiled = compile(load_policy(pool, policy_id).await?)?;
    sqlx::query("INSERT INTO smetric_acl_revision (policy_id, revision, checksum) VALUES ($1,$2,$3) ON CONFLICT (policy_id, revision) DO UPDATE SET checksum=EXCLUDED.checksum, compiled_at=NOW()")
        .bind(policy_id)
        .bind(i64::try_from(compiled.revision).map_err(|_| ServiceError::InvalidStoredValue("revision exceeds BIGINT".into()))?)
        .bind(&compiled.checksum)
        .execute(pool)
        .await?;
    Ok(PublishedPolicy {
        policy_id,
        revision: compiled.revision,
        checksum: compiled.checksum,
    })
}

async fn ensure_policy(
    tx: &mut Transaction<'_, Postgres>,
    policy_id: i64,
) -> Result<(), ServiceError> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM smetric_acl_policy WHERE id=$1)")
            .bind(policy_id)
            .fetch_one(&mut **tx)
            .await?;
    if exists {
        Ok(())
    } else {
        Err(ServiceError::PolicyNotFound(policy_id))
    }
}

async fn bump_revision(
    tx: &mut Transaction<'_, Postgres>,
    policy_id: i64,
) -> Result<(), ServiceError> {
    sqlx::query("UPDATE smetric_acl_policy SET revision=revision+1, updated_at=NOW() WHERE id=$1")
        .bind(policy_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

fn summary_from_row(
    row: (i64, String, Option<String>, bool, String, i64),
) -> Result<PolicySummary, ServiceError> {
    Ok(PolicySummary {
        id: row.0,
        name: row.1,
        description: row.2,
        enabled: row.3,
        default_action: parse_default_action(&row.4)?,
        revision: u64::try_from(row.5)
            .map_err(|_| ServiceError::InvalidStoredValue("negative revision".into()))?,
    })
}

fn action_str(value: Action) -> &'static str {
    match value {
        Action::Allow => "allow",
        Action::Deny => "deny",
        Action::Reject => "reject",
    }
}
fn protocol_str(value: Protocol) -> &'static str {
    match value {
        Protocol::Any => "any",
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
    }
}
fn parse_action(value: &str) -> Result<Action, ServiceError> {
    match value {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        "reject" => Ok(Action::Reject),
        _ => Err(ServiceError::InvalidStoredValue(format!("action {value}"))),
    }
}
fn parse_protocol(value: &str) -> Result<Protocol, ServiceError> {
    match value {
        "any" => Ok(Protocol::Any),
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "icmp" => Ok(Protocol::Icmp),
        _ => Err(ServiceError::InvalidStoredValue(format!(
            "protocol {value}"
        ))),
    }
}
fn parse_default_action(value: &str) -> Result<DefaultAction, ServiceError> {
    match value {
        "allow" => Ok(DefaultAction::Allow),
        "deny" => Ok(DefaultAction::Deny),
        _ => Err(ServiceError::InvalidStoredValue(format!(
            "default action {value}"
        ))),
    }
}

fn encode_subject(value: &Subject) -> (&'static str, Option<&str>) {
    match value {
        Subject::Any => ("any", None),
        Subject::User(v) => ("user", Some(v)),
        Subject::Group(v) => ("group", Some(v)),
        Subject::Device(v) => ("device", Some(v)),
        Subject::DeviceGroup(v) => ("device_group", Some(v)),
        Subject::Location(v) => ("location", Some(v)),
        Subject::Cidr(v) => ("cidr", Some(v)),
    }
}
fn encode_destination(value: &Destination) -> (&'static str, Option<&str>) {
    match value {
        Destination::Any => ("any", None),
        Destination::Cidr(v) => ("cidr", Some(v)),
        Destination::Ip(v) => ("ip", Some(v)),
        Destination::IpRange(v) => ("ip_range", Some(v)),
        Destination::Alias(v) => ("alias", Some(v)),
        Destination::Service(v) => ("service", Some(v)),
    }
}

fn decode_subject(kind: &str, value: Option<String>) -> Result<Subject, ServiceError> {
    let required = || {
        value.clone().ok_or_else(|| {
            ServiceError::InvalidStoredValue(format!("missing source value for {kind}"))
        })
    };
    match kind {
        "any" => Ok(Subject::Any),
        "user" => Ok(Subject::User(required()?)),
        "group" => Ok(Subject::Group(required()?)),
        "device" => Ok(Subject::Device(required()?)),
        "device_group" => Ok(Subject::DeviceGroup(required()?)),
        "location" => Ok(Subject::Location(required()?)),
        "cidr" => Ok(Subject::Cidr(required()?)),
        _ => Err(ServiceError::InvalidStoredValue(format!(
            "source kind {kind}"
        ))),
    }
}
fn decode_destination(kind: &str, value: Option<String>) -> Result<Destination, ServiceError> {
    let required = || {
        value.clone().ok_or_else(|| {
            ServiceError::InvalidStoredValue(format!("missing destination value for {kind}"))
        })
    };
    match kind {
        "any" => Ok(Destination::Any),
        "cidr" => Ok(Destination::Cidr(required()?)),
        "ip" => Ok(Destination::Ip(required()?)),
        "ip_range" => Ok(Destination::IpRange(required()?)),
        "alias" => Ok(Destination::Alias(required()?)),
        "service" => Ok(Destination::Service(required()?)),
        _ => Err(ServiceError::InvalidStoredValue(format!(
            "destination kind {kind}"
        ))),
    }
}

fn parse_ports(value: Option<String>) -> Result<Option<PortRange>, ServiceError> {
    let Some(value) = value else { return Ok(None) };
    let trimmed = value.trim_matches(|c| c == '[' || c == ']' || c == '(' || c == ')');
    let (start, end) = trimmed
        .split_once(',')
        .ok_or_else(|| ServiceError::InvalidStoredValue(format!("port range {value}")))?;
    let start = u16::from_str(start.trim())
        .map_err(|_| ServiceError::InvalidStoredValue(format!("port range {value}")))?;
    let exclusive_end = u32::from_str(end.trim())
        .map_err(|_| ServiceError::InvalidStoredValue(format!("port range {value}")))?;
    let end = exclusive_end
        .checked_sub(1)
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(|| ServiceError::InvalidStoredValue(format!("port range {value}")))?;
    Ok(Some(PortRange { start, end }))
}

fn rule_from_row(
    row: (
        i64,
        String,
        i32,
        bool,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        String,
        Option<String>,
    ),
) -> Result<Rule, ServiceError> {
    if row.2 < 0 {
        return Err(ServiceError::InvalidStoredValue("negative priority".into()));
    }
    Ok(Rule {
        id: row.0,
        name: row.1,
        priority: row.2,
        enabled: row.3,
        action: parse_action(&row.4)?,
        protocol: parse_protocol(&row.5)?,
        ports: parse_ports(row.6)?,
        source: decode_subject(&row.7, row.8)?,
        destination: decode_destination(&row.9, row.10)?,
    })
}
