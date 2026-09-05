use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
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

/// Enqueue a security event durably. Delivery is intentionally decoupled from
/// the management request so a temporary SIEM outage cannot fail policy changes.
pub async fn enqueue(pool: &PgPool, event: &NewSecurityEvent) -> Result<Uuid, sqlx::Error> {
    let event_id = Uuid::new_v4();
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
    .execute(pool)
    .await?;
    Ok(event_id)
}
