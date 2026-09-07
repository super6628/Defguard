use std::{env, time::Duration};

use reqwest::Url;
use sqlx::PgPool;
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{MissedTickBehavior, interval},
};

use super::{
    dispatcher::{DispatcherConfig, HttpSiemTransport, run_dispatcher},
    purge_delivered,
};

const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_BATCH_SIZE: i64 = 32;
const DEFAULT_LEASE_SECS: i32 = 180;
const DEFAULT_POLL_SECS: u64 = 5;
const DEFAULT_RETENTION_PURGE_SECS: u64 = 3600;
const DEFAULT_RETENTION_BATCH_SIZE: i64 = 1000;

#[derive(Clone, Copy)]
pub struct RetentionConfig {
    pub retention_seconds: i64,
    pub purge_interval: Duration,
    pub batch_size: i64,
}

#[derive(Clone)]
pub struct SiemRuntimeConfig {
    pub endpoint: Url,
    pub bearer_token: Option<String>,
    pub request_timeout: Duration,
    pub dispatcher: DispatcherConfig,
    pub retention: Option<RetentionConfig>,
}

#[derive(Debug, thiserror::Error)]
pub enum SiemRuntimeConfigError {
    #[error("invalid DEFGUARD_SIEM_HTTP_URL: {0}")]
    InvalidEndpoint(String),
    #[error("unsupported DEFGUARD_SIEM_HTTP_URL scheme: {0}; expected http or https")]
    UnsupportedEndpointScheme(String),
    #[error("DEFGUARD_SIEM_HTTP_URL must not contain embedded username or password credentials")]
    EmbeddedEndpointCredentials,
    #[error("invalid integer in {name}: {value}")]
    InvalidInteger { name: &'static str, value: String },
    #[error("failed to build S-Metric SIEM HTTP client: {0}")]
    HttpClient(#[source] reqwest::Error),
}

impl SiemRuntimeConfig {
    pub fn from_env() -> Result<Option<Self>, SiemRuntimeConfigError> {
        let Some(endpoint) = non_empty_env("DEFGUARD_SIEM_HTTP_URL") else {
            return Ok(None);
        };
        let endpoint = Url::parse(&endpoint)
            .map_err(|error| SiemRuntimeConfigError::InvalidEndpoint(error.to_string()))?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(SiemRuntimeConfigError::UnsupportedEndpointScheme(
                endpoint.scheme().to_owned(),
            ));
        }
        if !endpoint.username().is_empty() || endpoint.password().is_some() {
            return Err(SiemRuntimeConfigError::EmbeddedEndpointCredentials);
        }

        let timeout_secs = parse_env_u64("DEFGUARD_SIEM_HTTP_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS)?;
        let batch_size = parse_env_i64("DEFGUARD_SIEM_BATCH_SIZE", DEFAULT_BATCH_SIZE)?;
        let lease_seconds = parse_env_i32("DEFGUARD_SIEM_LEASE_SECS", DEFAULT_LEASE_SECS)?;
        let poll_secs = parse_env_u64("DEFGUARD_SIEM_POLL_SECS", DEFAULT_POLL_SECS)?;
        let retention = parse_retention_config()?;

        Ok(Some(Self {
            endpoint,
            bearer_token: non_empty_env("DEFGUARD_SIEM_BEARER_TOKEN"),
            request_timeout: Duration::from_secs(timeout_secs.clamp(1, 300)),
            dispatcher: DispatcherConfig {
                batch_size: batch_size.clamp(1, 32),
                lease_seconds: lease_seconds.clamp(5, 3600),
                poll_interval: Duration::from_secs(poll_secs.clamp(1, 3600)),
            },
            retention,
        }))
    }
}

pub fn spawn_if_configured(
    pool: PgPool,
    shutdown: watch::Receiver<bool>,
) -> Result<Option<JoinHandle<()>>, SiemRuntimeConfigError> {
    let Some(config) = SiemRuntimeConfig::from_env()? else {
        tracing::info!(
            "S-Metric SIEM dispatcher disabled; DEFGUARD_SIEM_HTTP_URL is not configured"
        );
        return Ok(None);
    };

    let endpoint_origin = match config.endpoint.port() {
        Some(port) => format!(
            "{}://{}:{port}",
            config.endpoint.scheme(),
            config.endpoint.host_str().unwrap_or("<unknown>")
        ),
        None => format!(
            "{}://{}",
            config.endpoint.scheme(),
            config.endpoint.host_str().unwrap_or("<unknown>")
        ),
    };
    let transport = HttpSiemTransport::new(
        config.endpoint.to_string(),
        config.bearer_token,
        config.request_timeout,
    )
    .map_err(SiemRuntimeConfigError::HttpClient)?;

    tracing::info!(
        endpoint_origin = %endpoint_origin,
        batch_size = config.dispatcher.batch_size,
        lease_seconds = config.dispatcher.lease_seconds,
        poll_seconds = config.dispatcher.poll_interval.as_secs(),
        retention_enabled = config.retention.is_some(),
        "Starting S-Metric SIEM dispatcher"
    );

    Ok(Some(tokio::spawn(async move {
        if let Some(retention) = config.retention {
            let purge_pool = pool.clone();
            let purge_shutdown = shutdown.clone();
            tokio::join!(
                run_dispatcher(pool, transport, config.dispatcher, shutdown),
                run_retention_purge(purge_pool, retention, purge_shutdown),
            );
        } else {
            run_dispatcher(pool, transport, config.dispatcher, shutdown).await;
        }
    })))
}

async fn run_retention_purge(
    pool: PgPool,
    config: RetentionConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut ticker = interval(config.purge_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    tracing::debug!("S-Metric SIEM retention purge stopping");
                    break;
                }
            }
            _ = ticker.tick() => {
                match purge_delivered(&pool, config.retention_seconds, config.batch_size).await {
                    Ok(removed) if removed > 0 => {
                        tracing::info!(removed, "Purged delivered S-Metric SIEM events");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::error!(%error, "Failed to purge delivered S-Metric SIEM events");
                    }
                }
            }
        }
    }
}

fn parse_retention_config() -> Result<Option<RetentionConfig>, SiemRuntimeConfigError> {
    let Some(retention_seconds) = non_empty_env("DEFGUARD_SIEM_DELIVERED_RETENTION_SECS") else {
        return Ok(None);
    };
    let retention_seconds = retention_seconds
        .parse::<i64>()
        .map_err(|_| SiemRuntimeConfigError::InvalidInteger {
            name: "DEFGUARD_SIEM_DELIVERED_RETENTION_SECS",
            value: retention_seconds,
        })?
        .clamp(3600, 31_536_000);
    let purge_seconds = parse_env_u64(
        "DEFGUARD_SIEM_RETENTION_PURGE_SECS",
        DEFAULT_RETENTION_PURGE_SECS,
    )?;
    let batch_size = parse_env_i64(
        "DEFGUARD_SIEM_RETENTION_BATCH_SIZE",
        DEFAULT_RETENTION_BATCH_SIZE,
    )?;

    Ok(Some(RetentionConfig {
        retention_seconds,
        purge_interval: Duration::from_secs(purge_seconds.clamp(60, 86_400)),
        batch_size: batch_size.clamp(1, 10_000),
    }))
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_env_u64(name: &'static str, default: u64) -> Result<u64, SiemRuntimeConfigError> {
    match non_empty_env(name) {
        Some(value) => value
            .parse()
            .map_err(|_| SiemRuntimeConfigError::InvalidInteger { name, value }),
        None => Ok(default),
    }
}

fn parse_env_i64(name: &'static str, default: i64) -> Result<i64, SiemRuntimeConfigError> {
    match non_empty_env(name) {
        Some(value) => value
            .parse()
            .map_err(|_| SiemRuntimeConfigError::InvalidInteger { name, value }),
        None => Ok(default),
    }
}

fn parse_env_i32(name: &'static str, default: i32) -> Result<i32, SiemRuntimeConfigError> {
    match non_empty_env(name) {
        Some(value) => value
            .parse()
            .map_err(|_| SiemRuntimeConfigError::InvalidInteger { name, value }),
        None => Ok(default),
    }
}
