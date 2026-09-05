use std::{net::IpAddr, str::FromStr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use sha256::digest;
use sqlx::{PgPool, Postgres, Transaction};

use super::{
    EffectiveTrafficPolicy, TrafficDestination, TrafficMode, TrafficPolicy, TrafficTarget,
    resolve_effective_policy,
};

#[derive(Debug, thiserror::Error)]
pub enum TrafficPolicyError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("client traffic policy {0} was not found")]
    NotFound(i64),
    #[error("device {0} was not found")]
    DeviceNotFound(i64),
    #[error("invalid client traffic policy value: {0}")]
    InvalidStoredValue(String),
    #[error("client traffic policy name cannot be empty")]
    EmptyName,
    #[error("split-tunnel and bypass policies require at least one destination")]
    MissingDestinations,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateTrafficPolicy {
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub mode: TrafficMode,
    pub priority: u32,
    pub targets: Vec<TrafficTarget>,
    pub destinations: Vec<TrafficDestination>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishedTrafficPolicy {
    pub policy_id: i64,
    pub revision: u64,
    pub checksum: String,
}

type PolicyRow = (i64, String, Option<String>, bool, String, i32, i64);

pub async fn create_policy(
    pool: &PgPool,
    input: CreateTrafficPolicy,
) -> Result<TrafficPolicy, TrafficPolicyError> {
    validate_input(&input)?;
    let mut tx = pool.begin().await?;
    let row = sqlx::query_as::<_, PolicyRow>(
        "INSERT INTO smetric_traffic_policy (name, description, enabled, mode, priority) \
         VALUES ($1,$2,$3,$4,$5) \
         RETURNING id,name,description,enabled,mode,priority,revision",
    )
    .bind(input.name.trim())
    .bind(input.description)
    .bind(input.enabled)
    .bind(mode_str(input.mode))
    .bind(i32::try_from(input.priority).map_err(|_| {
        TrafficPolicyError::InvalidStoredValue("priority exceeds PostgreSQL INTEGER".into())
    })?)
    .fetch_one(&mut *tx)
    .await?;

    replace_targets(&mut tx, row.0, &input.targets).await?;
    replace_destinations(&mut tx, row.0, &input.destinations).await?;
    tx.commit().await?;
    load_policy(pool, row.0).await
}

pub async fn load_policy(
    pool: &PgPool,
    policy_id: i64,
) -> Result<TrafficPolicy, TrafficPolicyError> {
    let row = sqlx::query_as::<_, PolicyRow>(
        "SELECT id,name,description,enabled,mode,priority,revision \
         FROM smetric_traffic_policy WHERE id=$1",
    )
    .bind(policy_id)
    .fetch_optional(pool)
    .await?
    .ok_or(TrafficPolicyError::NotFound(policy_id))?;
    policy_from_row(pool, row).await
}

pub async fn list_policies(pool: &PgPool) -> Result<Vec<TrafficPolicy>, TrafficPolicyError> {
    let rows = sqlx::query_as::<_, PolicyRow>(
        "SELECT id,name,description,enabled,mode,priority,revision \
         FROM smetric_traffic_policy ORDER BY priority,id",
    )
    .fetch_all(pool)
    .await?;
    let mut policies = Vec::with_capacity(rows.len());
    for row in rows {
        policies.push(policy_from_row(pool, row).await?);
    }
    Ok(policies)
}

pub async fn delete_policy(pool: &PgPool, policy_id: i64) -> Result<(), TrafficPolicyError> {
    let result = sqlx::query("DELETE FROM smetric_traffic_policy WHERE id=$1")
        .bind(policy_id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(TrafficPolicyError::NotFound(policy_id));
    }
    Ok(())
}

pub async fn publish_policy(
    pool: &PgPool,
    policy_id: i64,
) -> Result<PublishedTrafficPolicy, TrafficPolicyError> {
    let policy = load_policy(pool, policy_id).await?;
    validate_policy(&policy)?;
    let checksum = digest(
        serde_json::to_string(&policy)
            .map_err(|error| TrafficPolicyError::InvalidStoredValue(error.to_string()))?,
    );
    sqlx::query(
        "INSERT INTO smetric_traffic_policy_revision (policy_id,revision,checksum) \
         VALUES ($1,$2,$3) \
         ON CONFLICT (policy_id,revision) DO UPDATE \
         SET checksum=EXCLUDED.checksum, compiled_at=NOW()",
    )
    .bind(policy_id)
    .bind(i64::try_from(policy.revision).map_err(|_| {
        TrafficPolicyError::InvalidStoredValue("revision exceeds PostgreSQL BIGINT".into())
    })?)
    .bind(&checksum)
    .execute(pool)
    .await?;
    Ok(PublishedTrafficPolicy {
        policy_id,
        revision: policy.revision,
        checksum,
    })
}

/// Resolve the policy the client should apply for a device at a VPN location.
///
/// Only policies whose current revision has been explicitly published participate. Matching is
/// deterministic: Device > User > Group > Location > Global, then lower numeric priority, then id.
pub async fn effective_for_device(
    pool: &PgPool,
    device_id: i64,
    location_id: i64,
) -> Result<Option<EffectiveTrafficPolicy>, TrafficPolicyError> {
    let user_id = sqlx::query_scalar::<_, i64>("SELECT user_id FROM device WHERE id=$1")
        .bind(device_id)
        .fetch_optional(pool)
        .await?
        .ok_or(TrafficPolicyError::DeviceNotFound(device_id))?;
    let group_ids = sqlx::query_scalar::<_, i64>(
        "SELECT group_id FROM group_user WHERE user_id=$1 ORDER BY group_id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let policies = list_policies(pool).await?;
    let mut matches = Vec::new();
    for policy in &policies {
        if !current_revision_is_published(pool, policy).await? {
            continue;
        }
        let best = policy
            .targets
            .iter()
            .filter(|target| target_matches(target, device_id, user_id, location_id, &group_ids))
            .max_by_key(|target| target.specificity());
        if let Some(target) = best {
            matches.push((policy, target));
        }
    }

    Ok(resolve_effective_policy(matches).map(EffectiveTrafficPolicy::from))
}

async fn current_revision_is_published(
    pool: &PgPool,
    policy: &TrafficPolicy,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM smetric_traffic_policy_revision \
         WHERE policy_id=$1 AND revision=$2)",
    )
    .bind(policy.id)
    .bind(i64::try_from(policy.revision).unwrap_or(i64::MAX))
    .fetch_one(pool)
    .await
}

fn target_matches(
    target: &TrafficTarget,
    device_id: i64,
    user_id: i64,
    location_id: i64,
    group_ids: &[i64],
) -> bool {
    match target {
        TrafficTarget::Global => true,
        TrafficTarget::Location(id) => *id == location_id,
        TrafficTarget::Group(id) => group_ids.contains(id),
        TrafficTarget::User(id) => *id == user_id,
        TrafficTarget::Device(id) => *id == device_id,
    }
}

async fn policy_from_row(
    pool: &PgPool,
    row: PolicyRow,
) -> Result<TrafficPolicy, TrafficPolicyError> {
    if row.5 < 0 || row.6 < 1 {
        return Err(TrafficPolicyError::InvalidStoredValue(
            "negative priority or non-positive revision".into(),
        ));
    }
    let target_rows = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT target_kind,target_value FROM smetric_traffic_policy_target \
         WHERE policy_id=$1 ORDER BY id",
    )
    .bind(row.0)
    .fetch_all(pool)
    .await?;
    let destination_rows = sqlx::query_as::<_, (String, String)>(
        "SELECT destination_kind,destination_value FROM smetric_traffic_policy_destination \
         WHERE policy_id=$1 ORDER BY id",
    )
    .bind(row.0)
    .fetch_all(pool)
    .await?;
    Ok(TrafficPolicy {
        id: row.0,
        name: row.1,
        description: row.2,
        enabled: row.3,
        mode: parse_mode(&row.4)?,
        priority: u32::try_from(row.5)
            .map_err(|_| TrafficPolicyError::InvalidStoredValue("negative priority".into()))?,
        revision: u64::try_from(row.6)
            .map_err(|_| TrafficPolicyError::InvalidStoredValue("negative revision".into()))?,
        targets: target_rows
            .into_iter()
            .map(|(kind, value)| parse_target(&kind, value))
            .collect::<Result<_, _>>()?,
        destinations: destination_rows
            .into_iter()
            .map(|(kind, value)| parse_destination(&kind, &value))
            .collect::<Result<_, _>>()?,
    })
}

async fn replace_targets(
    tx: &mut Transaction<'_, Postgres>,
    policy_id: i64,
    targets: &[TrafficTarget],
) -> Result<(), TrafficPolicyError> {
    for target in targets {
        let (kind, value) = encode_target(target);
        sqlx::query(
            "INSERT INTO smetric_traffic_policy_target (policy_id,target_kind,target_value) \
             VALUES ($1,$2,$3)",
        )
        .bind(policy_id)
        .bind(kind)
        .bind(value)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn replace_destinations(
    tx: &mut Transaction<'_, Postgres>,
    policy_id: i64,
    destinations: &[TrafficDestination],
) -> Result<(), TrafficPolicyError> {
    for destination in destinations {
        let (kind, value) = encode_destination(destination);
        sqlx::query(
            "INSERT INTO smetric_traffic_policy_destination \
             (policy_id,destination_kind,destination_value) VALUES ($1,$2,$3)",
        )
        .bind(policy_id)
        .bind(kind)
        .bind(value)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

fn validate_input(input: &CreateTrafficPolicy) -> Result<(), TrafficPolicyError> {
    if input.name.trim().is_empty() {
        return Err(TrafficPolicyError::EmptyName);
    }
    if !matches!(input.mode, TrafficMode::FullTunnel) && input.destinations.is_empty() {
        return Err(TrafficPolicyError::MissingDestinations);
    }
    Ok(())
}

fn validate_policy(policy: &TrafficPolicy) -> Result<(), TrafficPolicyError> {
    if policy.name.trim().is_empty() {
        return Err(TrafficPolicyError::EmptyName);
    }
    if !matches!(policy.mode, TrafficMode::FullTunnel) && policy.destinations.is_empty() {
        return Err(TrafficPolicyError::MissingDestinations);
    }
    Ok(())
}

fn mode_str(mode: TrafficMode) -> &'static str {
    match mode {
        TrafficMode::FullTunnel => "full_tunnel",
        TrafficMode::SplitTunnel => "split_tunnel",
        TrafficMode::Bypass => "bypass",
    }
}

fn parse_mode(value: &str) -> Result<TrafficMode, TrafficPolicyError> {
    match value {
        "full_tunnel" => Ok(TrafficMode::FullTunnel),
        "split_tunnel" => Ok(TrafficMode::SplitTunnel),
        "bypass" => Ok(TrafficMode::Bypass),
        _ => Err(TrafficPolicyError::InvalidStoredValue(format!("mode {value}"))),
    }
}

fn encode_target(target: &TrafficTarget) -> (&'static str, Option<String>) {
    match target {
        TrafficTarget::Global => ("global", None),
        TrafficTarget::Location(id) => ("location", Some(id.to_string())),
        TrafficTarget::Group(id) => ("group", Some(id.to_string())),
        TrafficTarget::User(id) => ("user", Some(id.to_string())),
        TrafficTarget::Device(id) => ("device", Some(id.to_string())),
    }
}

fn parse_target(kind: &str, value: Option<String>) -> Result<TrafficTarget, TrafficPolicyError> {
    let id = || {
        value
            .as_deref()
            .ok_or_else(|| TrafficPolicyError::InvalidStoredValue(format!("missing {kind} target")))?
            .parse::<i64>()
            .map_err(|_| TrafficPolicyError::InvalidStoredValue(format!("invalid {kind} target")))
    };
    match kind {
        "global" => Ok(TrafficTarget::Global),
        "location" => Ok(TrafficTarget::Location(id()?)),
        "group" => Ok(TrafficTarget::Group(id()?)),
        "user" => Ok(TrafficTarget::User(id()?)),
        "device" => Ok(TrafficTarget::Device(id()?)),
        _ => Err(TrafficPolicyError::InvalidStoredValue(format!("target kind {kind}"))),
    }
}

fn encode_destination(destination: &TrafficDestination) -> (&'static str, String) {
    match destination {
        TrafficDestination::Cidr(value) => ("cidr", value.to_string()),
        TrafficDestination::Ip(value) => ("ip", value.to_string()),
    }
}

fn parse_destination(
    kind: &str,
    value: &str,
) -> Result<TrafficDestination, TrafficPolicyError> {
    match kind {
        "cidr" => Ok(TrafficDestination::Cidr(
            IpNetwork::from_str(value).map_err(|_| {
                TrafficPolicyError::InvalidStoredValue(format!("invalid CIDR {value}"))
            })?,
        )),
        "ip" => Ok(TrafficDestination::Ip(IpAddr::from_str(value).map_err(|_| {
            TrafficPolicyError::InvalidStoredValue(format!("invalid IP {value}"))
        })?)),
        _ => Err(TrafficPolicyError::InvalidStoredValue(format!(
            "destination kind {kind}"
        ))),
    }
}
