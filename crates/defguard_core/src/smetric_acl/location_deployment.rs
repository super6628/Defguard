use serde::Serialize;
use sqlx::PgPool;

#[derive(Clone, Debug, Serialize)]
pub struct LocationDeploymentState {
    pub location_id: i64,
    pub desired_generation: i64,
    pub desired_checksum: String,
    pub applied_generation: Option<i64>,
    pub applied_checksum: Option<String>,
    pub last_error: Option<String>,
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

/// Return the current desired generation when the effective checksum is unchanged. Allocate a new
/// generation only when the desired effective location firewall actually changes.
pub async fn ensure_desired(
    pool: &PgPool,
    location_id: i64,
    checksum: &str,
) -> Result<i64, sqlx::Error> {
    if let Some(state) = get(pool, location_id).await? {
        if state.desired_checksum == checksum {
            return Ok(state.desired_generation);
        }
    }
    record_desired(pool, location_id, checksum).await
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
