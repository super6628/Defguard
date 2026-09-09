pub mod dispatcher;
pub mod runtime;

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

const MAX_DELIVERY_ERROR_CHARS: usize = 4096;
const INITIAL_RETRY_SECONDS: i64 = 5;
const MAX_RETRY_SECONDS: i64 = 3600;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventCategory {
    Firewall,
    ClientTrafficPolicy,
    Deployment,
    Gateway,
    System,
}

impl SecurityEventCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Firewall => "firewall",
            Self::ClientTrafficPolicy => "client_traffic_policy",
            Self::Deployment => "deployment",
            Self::Gateway => "gateway",
            Self::System => "system",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl SecurityEventSeverity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SecurityEventActor {
    pub user_id: Option<i64>,
    pub username: Option<String>,
    pub ip: Option<IpAddr>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NewSecurityEvent {
    pub event_type: String,
    pub category: SecurityEventCategory,
    pub severity: SecurityEventSeverity,
    pub actor: SecurityEventActor,
    pub subject_type: String,
    pub subject_id: Option<String>,
    pub description: String,
    pub payload: Value,
}

impl NewSecurityEvent {
    #[must_use]
    pub fn management(
        event_type: impl Into<String>,
        category: SecurityEventCategory,
        subject_type: impl Into<String>,
        subject_id: impl Into<Option<String>>,
        description: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            category,
            severity: SecurityEventSeverity::Info,
            actor: SecurityEventActor::default(),
            subject_type: subject_type.into(),
            subject_id: subject_id.into(),
            description: description.into(),
            payload,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, sqlx::FromRow)]
pub struct QueuedSecurityEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub category: String,
    pub severity: String,
    pub actor_user_id: Option<i64>,
    pub actor_username: Option<String>,
    pub actor_ip: Option<String>,
    pub subject_type: String,
    pub subject_id: Option<String>,
    pub description: String,
    pub payload: Value,
    pub attempts: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SecurityEventOutboxStats {
    pub ready: i64,
    pub delayed: i64,
    pub delivered_retained: i64,
    pub dead_lettered: i64,
}

fn insert_query(
    event_id: Uuid,
    event: &NewSecurityEvent,
) -> sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        "INSERT INTO smetric_security_event_outbox (\
            event_id,event_type,category,severity,actor_user_id,actor_username,actor_ip,\
            subject_type,subject_id,description,payload\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7::inet,$8,$9,$10,$11)",
    )
    .bind(event_id)
    .bind(&event.event_type)
    .bind(event.category.as_str())
    .bind(event.severity.as_str())
    .bind(event.actor.user_id)
    .bind(&event.actor.username)
    .bind(event.actor.ip.map(|ip| ip.to_string()))
    .bind(&event.subject_type)
    .bind(&event.subject_id)
    .bind(&event.description)
    .bind(&event.payload)
}

pub async fn enqueue(pool: &PgPool, event: &NewSecurityEvent) -> Result<Uuid, sqlx::Error> {
    let event_id = Uuid::new_v4();
    insert_query(event_id, event).execute(pool).await?;
    Ok(event_id)
}

pub async fn enqueue_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    event: &NewSecurityEvent,
) -> Result<Uuid, sqlx::Error> {
    let event_id = Uuid::new_v4();
    insert_query(event_id, event)
        .execute(&mut **transaction)
        .await?;
    Ok(event_id)
}

pub async fn outbox_stats(pool: &PgPool) -> Result<SecurityEventOutboxStats, sqlx::Error> {
    let row = sqlx::query_as::<_, (i64, i64, i64, i64)>(
        "SELECT \
            COUNT(*) FILTER (WHERE delivered_at IS NULL AND dead_lettered_at IS NULL AND next_attempt_at <= NOW())::bigint, \
            COUNT(*) FILTER (WHERE delivered_at IS NULL AND dead_lettered_at IS NULL AND next_attempt_at > NOW())::bigint, \
            COUNT(*) FILTER (WHERE delivered_at IS NOT NULL)::bigint, \
            COUNT(*) FILTER (WHERE dead_lettered_at IS NOT NULL)::bigint \
         FROM smetric_security_event_outbox",
    )
    .fetch_one(pool)
    .await?;
    Ok(SecurityEventOutboxStats {
        ready: row.0,
        delayed: row.1,
        delivered_retained: row.2,
        dead_lettered: row.3,
    })
}

pub async fn claim_pending(
    pool: &PgPool,
    limit: i64,
    lease_seconds: i32,
) -> Result<Vec<QueuedSecurityEvent>, sqlx::Error> {
    let limit = limit.clamp(1, 500);
    let lease_seconds = lease_seconds.clamp(5, 3600);
    sqlx::query_as::<_, QueuedSecurityEvent>(
        "WITH candidates AS (\
            SELECT id FROM smetric_security_event_outbox \
            WHERE delivered_at IS NULL AND dead_lettered_at IS NULL AND next_attempt_at <= NOW() \
            ORDER BY next_attempt_at, id \
            FOR UPDATE SKIP LOCKED \
            LIMIT $1\
         ) \
         UPDATE smetric_security_event_outbox AS event \
         SET attempts = event.attempts + 1, \
             next_attempt_at = NOW() + make_interval(secs => $2) \
         FROM candidates \
         WHERE event.id = candidates.id \
         RETURNING event.event_id,event.event_type,event.category,event.severity,\
             event.actor_user_id,event.actor_username,host(event.actor_ip) AS actor_ip,event.subject_type,\
             event.subject_id,event.description,event.payload,event.attempts",
    )
    .bind(limit)
    .bind(lease_seconds)
    .fetch_all(pool)
    .await
}

pub async fn mark_delivered(
    pool: &PgPool,
    event_id: Uuid,
    attempts: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE smetric_security_event_outbox \
         SET delivered_at = COALESCE(delivered_at, NOW()), last_error = NULL \
         WHERE event_id = $1 AND delivered_at IS NULL AND dead_lettered_at IS NULL AND attempts = $2",
    )
    .bind(event_id)
    .bind(attempts)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn mark_failed(
    pool: &PgPool,
    event_id: Uuid,
    attempts: i64,
    error: &str,
) -> Result<bool, sqlx::Error> {
    let exponent = u32::try_from(attempts.saturating_sub(1).clamp(0, 10)).unwrap_or(0);
    let retry_seconds = INITIAL_RETRY_SECONDS
        .saturating_mul(1_i64 << exponent)
        .min(MAX_RETRY_SECONDS);
    let error = error.chars().take(MAX_DELIVERY_ERROR_CHARS).collect::<String>();
    let result = sqlx::query(
        "UPDATE smetric_security_event_outbox \
         SET next_attempt_at = NOW() + ($2 * INTERVAL '1 second'), last_error = $3 \
         WHERE event_id = $1 AND delivered_at IS NULL AND dead_lettered_at IS NULL AND attempts = $4",
    )
    .bind(event_id)
    .bind(retry_seconds)
    .bind(error)
    .bind(attempts)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn mark_dead_lettered(
    pool: &PgPool,
    event_id: Uuid,
    attempts: i64,
    error: &str,
) -> Result<bool, sqlx::Error> {
    let error = error.chars().take(MAX_DELIVERY_ERROR_CHARS).collect::<String>();
    let result = sqlx::query(
        "UPDATE smetric_security_event_outbox \
         SET dead_lettered_at = COALESCE(dead_lettered_at, NOW()), last_error = $2 \
         WHERE event_id = $1 AND delivered_at IS NULL AND dead_lettered_at IS NULL AND attempts = $3",
    )
    .bind(event_id)
    .bind(error)
    .bind(attempts)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Requeue one dead-lettered event after an operator has corrected the delivery configuration.
/// Resetting attempts prevents an immediately requeued authentication failure from being sent
/// straight back to the dead-letter state.
pub async fn requeue_dead_lettered(pool: &PgPool, event_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE smetric_security_event_outbox \
         SET dead_lettered_at = NULL, attempts = 0, next_attempt_at = NOW(), last_error = NULL \
         WHERE event_id = $1 AND delivered_at IS NULL AND dead_lettered_at IS NOT NULL",
    )
    .bind(event_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Requeue at most `limit` dead-lettered events, oldest first. Row locking keeps concurrent recovery
/// operations from selecting the same events, while resetting attempts gives corrected credentials
/// or endpoint configuration a fresh delivery window.
pub async fn requeue_dead_lettered_batch(
    pool: &PgPool,
    limit: i64,
) -> Result<u64, sqlx::Error> {
    let limit = limit.clamp(1, 10_000);
    let result = sqlx::query(
        "WITH candidates AS (\
            SELECT id FROM smetric_security_event_outbox \
            WHERE delivered_at IS NULL AND dead_lettered_at IS NOT NULL \
            ORDER BY dead_lettered_at, id \
            FOR UPDATE SKIP LOCKED \
            LIMIT $1\
         ) \
         UPDATE smetric_security_event_outbox AS event \
         SET dead_lettered_at = NULL, attempts = 0, next_attempt_at = NOW(), last_error = NULL \
         FROM candidates \
         WHERE event.id = candidates.id",
    )
    .bind(limit)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Delete a bounded batch of successfully delivered events older than the retention window.
/// Dead-lettered and pending rows are never touched. Row locking lets multiple Core instances
/// purge concurrently without repeatedly selecting the same retained events.
pub async fn purge_delivered(
    pool: &PgPool,
    retention_seconds: i64,
    batch_size: i64,
) -> Result<u64, sqlx::Error> {
    let retention_seconds = retention_seconds.clamp(3600, 31_536_000);
    let batch_size = batch_size.clamp(1, 10_000);
    let result = sqlx::query(
        "WITH purge_candidates AS (\
            SELECT id FROM smetric_security_event_outbox \
            WHERE delivered_at IS NOT NULL AND dead_lettered_at IS NULL \
              AND delivered_at < NOW() - ($1 * INTERVAL '1 second') \
            ORDER BY delivered_at, id \
            FOR UPDATE SKIP LOCKED \
            LIMIT $2\
         ) \
         DELETE FROM smetric_security_event_outbox AS event \
         USING purge_candidates \
         WHERE event.id = purge_candidates.id",
    )
    .bind(retention_seconds)
    .bind(batch_size)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}