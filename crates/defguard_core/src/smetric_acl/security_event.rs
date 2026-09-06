pub mod dispatcher;

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

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
    pub actor_ip: Option<IpAddr>,
    pub subject_type: String,
    pub subject_id: Option<String>,
    pub description: String,
    pub payload: Value,
    pub attempts: i32,
}

fn insert_query(
    event_id: Uuid,
    event: &NewSecurityEvent,
) -> sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        "INSERT INTO smetric_security_event_outbox (\
            event_id,event_type,category,severity,actor_user_id,actor_username,actor_ip,\
            subject_type,subject_id,description,payload\
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(event_id)
    .bind(&event.event_type)
    .bind(event.category.as_str())
    .bind(event.severity.as_str())
    .bind(event.actor.user_id)
    .bind(&event.actor.username)
    .bind(event.actor.ip)
    .bind(&event.subject_type)
    .bind(&event.subject_id)
    .bind(&event.description)
    .bind(&event.payload)
}

/// Enqueue a security event durably outside an existing transaction. Delivery is intentionally
/// decoupled from the management request so a temporary SIEM outage cannot fail policy changes.
pub async fn enqueue(pool: &PgPool, event: &NewSecurityEvent) -> Result<Uuid, sqlx::Error> {
    let event_id = Uuid::new_v4();
    insert_query(event_id, event).execute(pool).await?;
    Ok(event_id)
}

/// Enqueue a security event in the caller's transaction so the event and the management change
/// commit or roll back together.
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

/// Atomically lease pending events for one dispatcher. Leased rows are moved into the future so
/// concurrent workers skip them; if the worker dies, they become claimable again after the lease.
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
            WHERE delivered_at IS NULL AND next_attempt_at <= NOW() \
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
             event.actor_user_id,event.actor_username,event.actor_ip,event.subject_type,\
             event.subject_id,event.description,event.payload,event.attempts",
    )
    .bind(limit)
    .bind(lease_seconds)
    .fetch_all(pool)
    .await
}

/// Mark an event as successfully delivered. Repeated acknowledgements are harmless.
pub async fn mark_delivered(pool: &PgPool, event_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE smetric_security_event_outbox \
         SET delivered_at = COALESCE(delivered_at, NOW()), last_error = NULL \
         WHERE event_id = $1",
    )
    .bind(event_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Release a failed delivery with bounded exponential backoff. The attempt number comes from the
/// claimed event and therefore includes the current delivery attempt.
pub async fn mark_failed(
    pool: &PgPool,
    event_id: Uuid,
    attempts: i32,
    error: &str,
) -> Result<(), sqlx::Error> {
    let exponent = u32::try_from(attempts.saturating_sub(1).clamp(0, 9)).unwrap_or(0);
    let retry_seconds = 5_i64.saturating_mul(1_i64 << exponent).min(3600);
    sqlx::query(
        "UPDATE smetric_security_event_outbox \
         SET next_attempt_at = NOW() + ($2 * INTERVAL '1 second'), last_error = $3 \
         WHERE event_id = $1 AND delivered_at IS NULL",
    )
    .bind(event_id)
    .bind(retry_seconds)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}
