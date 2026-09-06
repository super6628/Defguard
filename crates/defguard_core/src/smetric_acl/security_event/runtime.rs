use std::{env, time::Duration};

use reqwest::Url;
use sqlx::PgPool;
use tokio::{sync::watch, task::JoinHandle};

use super::dispatcher::{DispatcherConfig, HttpSiemTransport, run_dispatcher};

const DEFAULT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_BATCH_SIZE: i64 = 100;
const DEFAULT_LEASE_SECS: i32 = 60;
const DEFAULT_POLL_SECS: u64 = 5;

#[derive(Clone, Debug)]
pub struct SiemRuntimeConfig {
    pub endpoint: Url,
    pub bearer_token: Option<String>,
    pub request_timeout: Duration,
    pub dispatcher: DispatcherConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum SiemRuntimeConfigError {
    #[error("invalid DEFGUARD_SIEM_HTTP_URL: {0}")]
    InvalidEndpoint(#[source] url::ParseError),
    #[error("invalid integer in {name}: {value}")]
    InvalidInteger { name: &'static str, value: String },
}

impl SiemRuntimeConfig {
    pub fn from_env() -> Result<Option<Self>, SiemRuntimeConfigError> {
        let Some(endpoint) = non_empty_env("DEFGUARD_SIEM_HTTP_URL") else {
            return Ok(None);
        };
        let endpoint = Url::parse(&endpoint).map_err(SiemRuntimeConfigError::InvalidEndpoint)?;

        let timeout_secs = parse_env_u64("DEFGUARD_SIEM_HTTP_TIMEOUT_SECS", DEFAULT_TIMEOUT_SECS)?;
        let batch_size = parse_env_i64("DEFGUARD_SIEM_BATCH_SIZE", DEFAULT_BATCH_SIZE)?;
        let lease_seconds = parse_env_i32("DEFGUARD_SIEM_LEASE_SECS", DEFAULT_LEASE_SECS)?;
        let poll_secs = parse_env_u64("DEFGUARD_SIEM_POLL_SECS", DEFAULT_POLL_SECS)?;

        Ok(Some(Self {
            endpoint,
            bearer_token: non_empty_env("DEFGUARD_SIEM_BEARER_TOKEN"),
            request_timeout: Duration::from_secs(timeout_secs.clamp(1, 300)),
            dispatcher: DispatcherConfig {
                batch_size: batch_size.clamp(1, 500),
                lease_seconds: lease_seconds.clamp(5, 3600),
                poll_interval: Duration::from_secs(poll_secs.clamp(1, 3600)),
            },
        }))
    }
}

pub fn spawn_if_configured(
    pool: PgPool,
    shutdown: watch::Receiver<bool>,
) -> Result<Option<JoinHandle<()>>, SiemRuntimeConfigError> {
    let Some(config) = SiemRuntimeConfig::from_env()? else {
        info!("S-Metric SIEM dispatcher disabled; DEFGUARD_SIEM_HTTP_URL is not configured");
        return Ok(None);
    };

    let transport = HttpSiemTransport::new(
        config.endpoint.to_string(),
        config.bearer_token,
        config.request_timeout,
    )
    .expect("building the reqwest SIEM client should not fail after config validation");

    info!(
        endpoint = %config.endpoint,
        batch_size = config.dispatcher.batch_size,
        lease_seconds = config.dispatcher.lease_seconds,
        poll_seconds = config.dispatcher.poll_interval.as_secs(),
        "Starting S-Metric SIEM dispatcher"
    );

    Ok(Some(tokio::spawn(run_dispatcher(
        pool,
        transport,
        config.dispatcher,
        shutdown,
    ))))
}

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().map(|value| value.trim().to_owned()).filter(|value| !value.is_empty())
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
