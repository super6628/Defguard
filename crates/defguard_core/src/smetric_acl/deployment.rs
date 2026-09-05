use defguard_common::{gateway_event::GatewayCommand, gateway_types::FirewallConfig};
use serde::Serialize;
use sha256::digest;
use sqlx::PgPool;
use tokio::sync::broadcast::Sender;

use super::{
    compile,
    gateway::{GatewayEnforcementError, translate_policy_for_location},
    service::{ServiceError, load_policy},
};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Pending,
    Applied,
    Failed,
    GatewayOffline,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeploymentState {
    pub policy_id: i64,
    pub location_id: i64,
    pub desired_generation: i64,
    pub desired_policy_revision: i64,
    pub desired_checksum: String,
    pub applied_generation: Option<i64>,
    pub last_error: Option<String>,
    pub gateway_online: bool,
    pub status: DeploymentStatus,
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Gateway(#[from] GatewayEnforcementError),
    #[error("failed to queue reconciled firewall configuration for location {0}")]
    GatewayChannelClosed(i64),
}

pub async fn record_desired(
    pool: &PgPool,
    policy_id: i64,
    location_id: i64,
    policy_revision: u64,
    checksum: &str,
) -> Result<i64, sqlx::Error> {
    let generation: i64 =
        sqlx::query_scalar("SELECT nextval('smetric_acl_deployment_generation_seq')::bigint")
            .fetch_one(pool)
            .await?;
    let revision = i64::try_from(policy_revision).map_err(|error| {
        sqlx::Error::Protocol(format!("S-Metric ACL policy revision exceeds BIGINT: {error}"))
    })?;

    sqlx::query(
        "INSERT INTO smetric_acl_deployment_state \
         (policy_id, location_id, desired_generation, desired_policy_revision, desired_checksum, desired_at, last_error, last_error_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,NOW(),NULL,NULL,NOW()) \
         ON CONFLICT (policy_id, location_id) DO UPDATE SET \
           desired_generation=EXCLUDED.desired_generation, \
           desired_policy_revision=EXCLUDED.desired_policy_revision, \
           desired_checksum=EXCLUDED.desired_checksum, \
           desired_at=NOW(), last_error=NULL, last_error_at=NULL, updated_at=NOW()",
    )
    .bind(policy_id)
    .bind(location_id)
    .bind(generation)
    .bind(revision)
    .bind(checksum)
    .execute(pool)
    .await?;

    Ok(generation)
}

pub async fn mark_applied(
    pool: &PgPool,
    policy_id: i64,
    location_id: i64,
    generation: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE smetric_acl_deployment_state SET \
           applied_generation=$3, applied_at=NOW(), last_error=NULL, last_error_at=NULL, updated_at=NOW() \
         WHERE policy_id=$1 AND location_id=$2 AND desired_generation=$3 \
           AND (applied_generation IS DISTINCT FROM $3 OR last_error IS NOT NULL)",
    )
    .bind(policy_id)
    .bind(location_id)
    .bind(generation)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn mark_error(
    pool: &PgPool,
    policy_id: i64,
    location_id: i64,
    generation: i64,
    error: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE smetric_acl_deployment_state SET last_error=$4, last_error_at=NOW(), updated_at=NOW() \
         WHERE policy_id=$1 AND location_id=$2 AND desired_generation=$3 \
           AND applied_generation IS DISTINCT FROM $3",
    )
    .bind(policy_id)
    .bind(location_id)
    .bind(generation)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn reconcile_location(
    pool: &PgPool,
    gateway_tx: &Sender<GatewayCommand>,
    location_id: i64,
) -> Result<usize, ReconcileError> {
    let rows = sqlx::query_as::<_, (i64, i64, String)>(
        "SELECT ds.policy_id, ds.desired_generation, ds.desired_checksum \
         FROM smetric_acl_deployment_state ds \
         JOIN smetric_acl_policy_assignment a \
           ON a.policy_id = ds.policy_id AND a.location_id = ds.location_id \
         JOIN smetric_acl_policy p ON p.id = ds.policy_id \
         WHERE ds.location_id = $1 \
           AND a.enabled = TRUE \
           AND p.enabled = TRUE \
           AND ds.applied_generation IS DISTINCT FROM ds.desired_generation \
         ORDER BY ds.policy_id",
    )
    .bind(location_id)
    .fetch_all(pool)
    .await?;

    let mut sent = 0usize;
    for (policy_id, desired_generation, desired_checksum) in rows {
        let policy = compile(load_policy(pool, policy_id).await?).map_err(ServiceError::Validation)?;
        let config = translate_policy_for_location(pool, &policy, location_id).await?;
        let effective_checksum = effective_config_checksum(&config);

        let generation = if effective_checksum == desired_checksum {
            desired_generation
        } else {
            record_desired(
                pool,
                policy_id,
                location_id,
                policy.revision,
                &effective_checksum,
            )
            .await?
        };

        if gateway_tx
            .send(GatewayCommand::FirewallConfigChanged(location_id, config))
            .is_err()
        {
            let _ = mark_error(
                pool,
                policy_id,
                location_id,
                generation,
                "gateway command channel is closed during reconnect reconciliation",
            )
            .await;
            return Err(ReconcileError::GatewayChannelClosed(location_id));
        }
        sent += 1;
    }

    Ok(sent)
}

fn effective_config_checksum(config: &FirewallConfig) -> String {
    digest(format!("{config:?}"))
}

pub async fn list_for_policy(
    pool: &PgPool,
    policy_id: i64,
) -> Result<Vec<DeploymentState>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (i64, i64, i64, i64, String, Option<i64>, Option<String>, bool)>(
        "SELECT ds.policy_id, ds.location_id, ds.desired_generation, ds.desired_policy_revision, \
                ds.desired_checksum, ds.applied_generation, ds.last_error, \
                EXISTS ( \
                    SELECT 1 FROM gateway g \
                    WHERE g.location_id = ds.location_id \
                      AND g.enabled = TRUE \
                      AND g.connected_at IS NOT NULL \
                      AND (g.disconnected_at IS NULL OR g.disconnected_at <= g.connected_at) \
                ) AS gateway_online \
         FROM smetric_acl_deployment_state ds \
         WHERE ds.policy_id=$1 ORDER BY ds.location_id",
    )
    .bind(policy_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let status = if row.5 == Some(row.2) {
                DeploymentStatus::Applied
            } else if row.6.is_some() {
                DeploymentStatus::Failed
            } else if !row.7 {
                DeploymentStatus::GatewayOffline
            } else {
                DeploymentStatus::Pending
            };
            DeploymentState {
                policy_id: row.0,
                location_id: row.1,
                desired_generation: row.2,
                desired_policy_revision: row.3,
                desired_checksum: row.4,
                applied_generation: row.5,
                last_error: row.6,
                gateway_online: row.7,
                status,
            }
        })
        .collect())
}
