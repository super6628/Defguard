use std::time::Duration;

use reqwest::Client;
use serde::Serialize;
use sqlx::PgPool;

use super::{QueuedSecurityEvent, claim_pending, mark_delivered, mark_failed};

#[derive(Clone)]
pub struct HttpSiemTransport {
    client: Client,
    endpoint: String,
    bearer_token: Option<String>,
}

impl HttpSiemTransport {
    pub fn new(
        endpoint: impl Into<String>,
        bearer_token: Option<String>,
        timeout: Duration,
    ) -> Result<Self, reqwest::Error> {
        let client = Client::builder().timeout(timeout).build()?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
            bearer_token,
        })
    }

    async fn send(&self, event: &QueuedSecurityEvent) -> Result<(), reqwest::Error> {
        let mut request = self.client.post(&self.endpoint).json(&SiemEnvelope::from(event));
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        request.send().await?.error_for_status()?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct SiemEnvelope<'a> {
    schema: &'static str,
    event_id: uuid::Uuid,
    event_type: &'a str,
    category: &'a str,
    severity: &'a str,
    actor: SiemActor<'a>,
    subject: SiemSubject<'a>,
    description: &'a str,
    payload: &'a serde_json::Value,
    delivery_attempt: i32,
}

#[derive(Debug, Serialize)]
struct SiemActor<'a> {
    user_id: Option<i64>,
    username: Option<&'a str>,
    ip: Option<std::net::IpAddr>,
}

#[derive(Debug, Serialize)]
struct SiemSubject<'a> {
    r#type: &'a str,
    id: Option<&'a str>,
}

impl<'a> From<&'a QueuedSecurityEvent> for SiemEnvelope<'a> {
    fn from(event: &'a QueuedSecurityEvent) -> Self {
        Self {
            schema: "smetric.security_event.v1",
            event_id: event.event_id,
            event_type: &event.event_type,
            category: &event.category,
            severity: &event.severity,
            actor: SiemActor {
                user_id: event.actor_user_id,
                username: event.actor_username.as_deref(),
                ip: event.actor_ip,
            },
            subject: SiemSubject {
                r#type: &event.subject_type,
                id: event.subject_id.as_deref(),
            },
            description: &event.description,
            payload: &event.payload,
            delivery_attempt: event.attempts,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DispatchStats {
    pub claimed: usize,
    pub delivered: usize,
    pub failed: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("failed to claim S-Metric security events: {0}")]
    Claim(#[source] sqlx::Error),
    #[error("failed to update S-Metric security event delivery state: {0}")]
    State(#[source] sqlx::Error),
}

pub async fn dispatch_once(
    pool: &PgPool,
    transport: &HttpSiemTransport,
    batch_size: i64,
    lease_seconds: i32,
) -> Result<DispatchStats, DispatchError> {
    let events = claim_pending(pool, batch_size, lease_seconds)
        .await
        .map_err(DispatchError::Claim)?;
    let mut stats = DispatchStats {
        claimed: events.len(),
        ..DispatchStats::default()
    };

    for event in events {
        match transport.send(&event).await {
            Ok(()) => {
                mark_delivered(pool, event.event_id)
                    .await
                    .map_err(DispatchError::State)?;
                stats.delivered += 1;
            }
            Err(error) => {
                mark_failed(pool, event.event_id, event.attempts, &error.to_string())
                    .await
                    .map_err(DispatchError::State)?;
                stats.failed += 1;
            }
        }
    }

    Ok(stats)
}
