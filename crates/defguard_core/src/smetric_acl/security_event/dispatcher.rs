use std::time::Duration;

use futures::{StreamExt, stream};
use reqwest::Client;
use serde::Serialize;
use sqlx::PgPool;
use tokio::{sync::watch, time::MissedTickBehavior};

use super::{QueuedSecurityEvent, claim_pending, mark_dead_lettered, mark_delivered, mark_failed};

const MAX_DISPATCH_CONCURRENCY: i64 = 32;
const MAX_CONFIGURATION_FAILURE_ATTEMPTS: i64 = 12;

#[derive(Clone)]
pub struct HttpSiemTransport {
    client: Client,
    endpoint: String,
    bearer_token: Option<String>,
    timeout: Duration,
}

impl HttpSiemTransport {
    pub fn new(
        endpoint: impl Into<String>,
        bearer_token: Option<String>,
        timeout: Duration,
    ) -> Result<Self, reqwest::Error> {
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
            bearer_token,
            timeout,
        })
    }

    async fn send(&self, event: &QueuedSecurityEvent) -> Result<(), TransportError> {
        let mut request = self
            .client
            .post(&self.endpoint)
            .json(&SiemEnvelope::from(event));
        if let Some(token) = &self.bearer_token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(TransportError::from_reqwest)?;
        let status = response.status();
        if !status.is_success() {
            return Err(TransportError::HttpStatus(status.as_u16()));
        }
        Ok(())
    }

    fn minimum_lease_seconds(&self) -> i32 {
        let timeout_seconds = self.timeout.as_secs().min(3594);
        i32::try_from(timeout_seconds + 5).unwrap_or(3599)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
enum TransportError {
    #[error("SIEM endpoint returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("SIEM request timed out")]
    Timeout,
    #[error("failed to connect to SIEM endpoint")]
    Connect,
    #[error("SIEM HTTP request failed")]
    Request,
}

impl TransportError {
    fn from_reqwest(error: reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else if error.is_connect() {
            Self::Connect
        } else {
            Self::Request
        }
    }

    fn is_terminal(self) -> bool {
        match self {
            Self::HttpStatus(status) if (300..400).contains(&status) => true,
            Self::HttpStatus(400 | 404 | 405 | 410 | 413 | 414 | 415 | 422) => true,
            _ => false,
        }
    }

    fn is_bounded_configuration_failure(self) -> bool {
        matches!(self, Self::HttpStatus(401 | 403) | Self::Request)
    }
}

#[derive(Debug, Serialize)]
struct SiemEnvelope<'a> {
    schema: &'static str,
    event_id: String,
    event_type: &'a str,
    category: &'a str,
    severity: &'a str,
    actor: SiemActor<'a>,
    subject: SiemSubject<'a>,
    description: &'a str,
    payload: &'a serde_json::Value,
    delivery_attempt: i64,
}

#[derive(Debug, Serialize)]
struct SiemActor<'a> {
    user_id: Option<i64>,
    username: Option<&'a str>,
    ip: Option<&'a str>,
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
            event_id: event.event_id.to_string(),
            event_type: &event.event_type,
            category: &event.category,
            severity: &event.severity,
            actor: SiemActor {
                user_id: event.actor_user_id,
                username: event.actor_username.as_deref(),
                ip: event.actor_ip.as_deref(),
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
    pub dead_lettered: usize,
    pub stale: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct DispatcherConfig {
    pub batch_size: i64,
    pub lease_seconds: i32,
    pub poll_interval: Duration,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            batch_size: 32,
            lease_seconds: 180,
            poll_interval: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("failed to claim S-Metric security events: {0}")]
    Claim(#[source] sqlx::Error),
    #[error("failed to update S-Metric security event delivery state: {0}")]
    State(#[source] sqlx::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DispatchOutcome {
    Delivered,
    Failed,
    DeadLettered,
    Stale,
}

pub async fn dispatch_once(
    pool: &PgPool,
    transport: &HttpSiemTransport,
    batch_size: i64,
    lease_seconds: i32,
) -> Result<DispatchStats, DispatchError> {
    let claim_size = batch_size.clamp(1, MAX_DISPATCH_CONCURRENCY);
    let lease_seconds = lease_seconds.max(transport.minimum_lease_seconds());
    let events = claim_pending(pool, claim_size, lease_seconds)
        .await
        .map_err(DispatchError::Claim)?;
    let claimed = events.len();

    let results = stream::iter(events.into_iter().map(|event| async move {
        match transport.send(&event).await {
            Ok(()) => {
                let updated = mark_delivered(pool, event.event_id, event.attempts)
                    .await
                    .map_err(DispatchError::State)?;
                Ok::<DispatchOutcome, DispatchError>(if updated {
                    DispatchOutcome::Delivered
                } else {
                    DispatchOutcome::Stale
                })
            }
            Err(error)
                if error.is_terminal()
                    || (error.is_bounded_configuration_failure()
                        && event.attempts >= MAX_CONFIGURATION_FAILURE_ATTEMPTS) =>
            {
                let updated =
                    mark_dead_lettered(pool, event.event_id, event.attempts, &error.to_string())
                        .await
                        .map_err(DispatchError::State)?;
                Ok(if updated {
                    DispatchOutcome::DeadLettered
                } else {
                    DispatchOutcome::Stale
                })
            }
            Err(error) => {
                let updated = mark_failed(pool, event.event_id, event.attempts, &error.to_string())
                    .await
                    .map_err(DispatchError::State)?;
                Ok(if updated {
                    DispatchOutcome::Failed
                } else {
                    DispatchOutcome::Stale
                })
            }
        }
    }))
    .buffer_unordered(MAX_DISPATCH_CONCURRENCY as usize)
    .collect::<Vec<_>>()
    .await;

    let mut stats = DispatchStats {
        claimed,
        ..DispatchStats::default()
    };
    for result in results {
        match result? {
            DispatchOutcome::Delivered => stats.delivered += 1,
            DispatchOutcome::Failed => stats.failed += 1,
            DispatchOutcome::DeadLettered => stats.dead_lettered += 1,
            DispatchOutcome::Stale => stats.stale += 1,
        }
    }

    Ok(stats)
}

/// Run the SIEM dispatcher until shutdown is requested. Individual dispatch failures are logged
/// and retried on the next tick so a database or remote SIEM outage does not terminate the worker.
pub async fn run_dispatcher(
    pool: PgPool,
    transport: HttpSiemTransport,
    config: DispatcherConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    if *shutdown.borrow() {
        tracing::debug!(
            "S-Metric SIEM dispatcher not started because shutdown was already requested"
        );
        return;
    }

    let poll_interval = config.poll_interval.max(Duration::from_millis(250));
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::debug!("S-Metric SIEM dispatcher stopping");
                    break;
                }
            }
            _ = ticker.tick() => {
                let dispatch = dispatch_once(
                    &pool,
                    &transport,
                    config.batch_size,
                    config.lease_seconds,
                );
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            tracing::debug!("S-Metric SIEM dispatcher stopping during dispatch");
                            break;
                        }
                    }
                    result = dispatch => {
                        match result {
                            Ok(stats) if stats.claimed > 0 => {
                                if stats.dead_lettered > 0 {
                                    tracing::warn!(
                                        dead_lettered = stats.dead_lettered,
                                        "S-Metric SIEM events were dead-lettered; inspect the outbox last_error values"
                                    );
                                }
                                tracing::info!(
                                    claimed = stats.claimed,
                                    delivered = stats.delivered,
                                    failed = stats.failed,
                                    dead_lettered = stats.dead_lettered,
                                    stale = stats.stale,
                                    "S-Metric SIEM dispatch cycle completed"
                                );
                            }
                            Ok(_) => {}
                            Err(error) => {
                                tracing::error!(%error, "S-Metric SIEM dispatch cycle failed");
                            }
                        }
                    }
                }
            }
        }
    }
}
