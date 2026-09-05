use serde::Serialize;
use sqlx::PgPool;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationDeploymentStatus {
    Pending,
    Applied,
    Failed,
    GatewayOffline,
    NotDeployed,
}

#[derive(Clone, Debug, Serialize)]
pub struct LocationDeploymentState {
    pub location_id: i64,
    pub desired_generation: i64,
    pub desired_checksum: String,
    pub applied_generation: Option<i64>,
    pub applied_checksum: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyLocationDeploymentStatus {
    pub policy_id: i64,
    pub location_id: i64,
    pub desired_generation: Option<i64>,
    pub desired_checksum: Option<String>,
    pub applied_generation: Option<i64>,
    pub applied_checksum: Option<String>,
    pub last_error: Option<String>,
    pub gateway_online: bool,
    pub status: LocationDeploymentStatus,
}

pub async fn get(
    pool: &PgPool,
    location_id: i64,
) -> Result<Option<LocationDeploymentState>, sqlx::Error> {
    let row = sqlx::query_as::<_, (i64, i64, String, Option<i64>, Option<String>, Option<String>)>(
        "SELECT location_id, desired_generation, desired_checksum, applied_generation, applied_checksum, last_error \
         FROM smetric_acl_location_deployment_state WHERE location_id=$1",
    )
    .bind(location_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| LocationDeploymentState {
        location_id: row.0,
        desired_generation: row.1,
        desired_checksum: row.2,
        applied_generation: row.3,
        applied_checksum: row.4,
        last_error: row.5,
    }))
}

pub async fn list_for_policy(
    pool: &PgPool,
    policy_id: i64,
) -> Result<Vec<PolicyLocationDeploymentStatus>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (
        i64,
        i64,
        Option<i64>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
        bool,
    )>(
        "SELECT a.policy_id, a.location_id, ds.desired_generation, ds.desired_checksum, \
                ds.applied_generation, ds.applied_checksum, ds.last_error, \
                EXISTS ( \
                    SELECT 1 FROM gateway g \
                    WHERE g.location_id = a.location_id \
                      AND g.enabled = TRUE \
                      AND g.connected_at IS NOT NULL \
                      AND (g.disconnected_at IS NULL OR g.disconnected_at <= g.connected_at) \
                ) AS gateway_online \
         FROM smetric_acl_policy_assignment a \
         LEFT JOIN smetric_acl_location_deployment_state ds ON ds.location_id = a.location_id \
         WHERE a.policy_id=$1 AND a.enabled=TRUE \
         ORDER BY a.location_id",
    )
    .bind(policy_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| {
            let status = match row.2 {
                None => LocationDeploymentStatus::NotDeployed,
                Some(desired_generation) if row.4 == Some(desired_generation) => {
                    LocationDeploymentStatus::Applied
                }
                Some(_) if row.6.is_some() => LocationDeploymentStatus::Failed,
                Some(_) if !row.7 => LocationDeploymentStatus::GatewayOffline,
                Some(_) => LocationDeploymentStatus::Pending,
            };
            PolicyLocationDeploymentStatus {
                policy_id: row.0,
                location_id: row.1,
                desired_generation: row.2,
                desired_checksum: row.3,
                applied_generation: row.4,
                applied_checksum: row.5,
                last_error: row.6,
                gateway_online: row.7,
                status,
            }
        })
        .collect())
}

pub async fn record_desired(
    pool: &PgPool,
    location_id: i64,
    checksum: &str,
) -> Result<i64, sqlx::Error> {
    let generation: i64 = sqlx::query_scalar(
        "SELECT nextval('smetric_acl_location_deployment_generation_seq')::bigint",
    )
    .fetch_one(pool)
    .await?;

    sqlx::query(
        "INSERT INTO smetric_acl_location_deployment_state \
         (location_id, desired_generation, desired_checksum, desired_at, last_error, last_error_at, updated_at) \
         VALUES ($1,$2,$3,NOW(),NULL,NULL,NOW()) \
         ON CONFLICT (location_id) DO UPDATE SET \
           desired_generation=EXCLUDED.desired_generation, \
           desired_checksum=EXCLUDED.desired_checksum, \
           desired_at=NOW(), last_error=NULL, last_error_at=NULL, updated_at=NOW()",
    )
    .bind(location_id)
    .bind(generation)
    .bind(checksum)
    .execute(pool)
    .await?;
    Ok(generation)
}

/// Atomically preserve the current desired generation when the checksum is unchanged, or allocate
/// a new generation when the effective location firewall changes. The single upsert removes the
/// read-then-write race between concurrent publishers for the same location.
pub async fn ensure_desired(
    pool: &PgPool,
    location_id: i64,
    checksum: &str,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO smetric_acl_location_deployment_state \
         (location_id, desired_generation, desired_checksum, desired_at, last_error, last_error_at, updated_at) \
         VALUES ($1, nextval('smetric_acl_location_deployment_generation_seq')::bigint, $2, NOW(), NULL, NULL, NOW()) \
         ON CONFLICT (location_id) DO UPDATE SET \
           desired_generation = CASE \
             WHEN smetric_acl_location_deployment_state.desired_checksum = EXCLUDED.desired_checksum \
             THEN smetric_acl_location_deployment_state.desired_generation \
             ELSE nextval('smetric_acl_location_deployment_generation_seq')::bigint \
           END, \
           desired_checksum = EXCLUDED.desired_checksum, \
           desired_at = CASE \
             WHEN smetric_acl_location_deployment_state.desired_checksum = EXCLUDED.desired_checksum \
             THEN smetric_acl_location_deployment_state.desired_at \
             ELSE NOW() \
           END, \
           last_error = CASE \
             WHEN smetric_acl_location_deployment_state.desired_checksum = EXCLUDED.desired_checksum \
             THEN smetric_acl_location_deployment_state.last_error \
             ELSE NULL \
           END, \
           last_error_at = CASE \
             WHEN smetric_acl_location_deployment_state.desired_checksum = EXCLUDED.desired_checksum \
             THEN smetric_acl_location_deployment_state.last_error_at \
             ELSE NULL \
           END, \
           updated_at = CASE \
             WHEN smetric_acl_location_deployment_state.desired_checksum = EXCLUDED.desired_checksum \
             THEN smetric_acl_location_deployment_state.updated_at \
             ELSE NOW() \
           END \
         RETURNING desired_generation",
    )
    .bind(location_id)
    .bind(checksum)
    .fetch_one(pool)
    .await
}

pub async fn mark_applied(
    pool: &PgPool,
    location_id: i64,
    generation: i64,
    checksum: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE smetric_acl_location_deployment_state SET \
           applied_generation=$2, applied_checksum=$3, applied_at=NOW(), \
           last_error=NULL, last_error_at=NULL, updated_at=NOW() \
         WHERE location_id=$1 AND desired_generation=$2 AND desired_checksum=$3 \
           AND (applied_generation IS DISTINCT FROM $2 OR applied_checksum IS DISTINCT FROM $3 OR last_error IS NOT NULL)",
    )
    .bind(location_id)
    .bind(generation)
    .bind(checksum)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn mark_error(
    pool: &PgPool,
    location_id: i64,
    generation: i64,
    error: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE smetric_acl_location_deployment_state SET \
           last_error=$3, last_error_at=NOW(), updated_at=NOW() \
         WHERE location_id=$1 AND desired_generation=$2 \
           AND applied_generation IS DISTINCT FROM $2",
    )
    .bind(location_id)
    .bind(generation)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}
