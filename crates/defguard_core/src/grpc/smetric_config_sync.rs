use std::{
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use defguard_proto::smetric::config_sync::{
    AckResponse, ConfigAck, ConfigChanged, ConfigVersion, GetVersionRequest, SubscribeRequest,
    config_sync_service_server::ConfigSyncService,
};
use futures::{Stream, StreamExt, stream};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tonic::{Request, Response, Status};

const EVENT_BUFFER: usize = 256;

#[derive(Clone, Debug)]
pub struct ConfigSyncEvent {
    pub version: u64,
    pub reason: String,
    pub changed_at_unix_ms: i64,
}

pub struct ConfigSyncHub {
    version: AtomicU64,
    tx: broadcast::Sender<ConfigSyncEvent>,
}

impl ConfigSyncHub {
    fn new() -> Self {
        let (tx, _) = broadcast::channel(EVENT_BUFFER);
        Self {
            version: AtomicU64::new(0),
            tx,
        }
    }

    #[must_use]
    pub fn desired_version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    pub fn publish(&self, reason: impl Into<String>) -> u64 {
        let version = self.version.fetch_add(1, Ordering::AcqRel) + 1;
        let changed_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
            .unwrap_or_default();
        let _ = self.tx.send(ConfigSyncEvent {
            version,
            reason: reason.into(),
            changed_at_unix_ms,
        });
        version
    }

    fn subscribe(&self) -> broadcast::Receiver<ConfigSyncEvent> {
        self.tx.subscribe()
    }
}

static CONFIG_SYNC_HUB: OnceLock<Arc<ConfigSyncHub>> = OnceLock::new();

#[must_use]
pub fn config_sync_hub() -> Arc<ConfigSyncHub> {
    Arc::clone(CONFIG_SYNC_HUB.get_or_init(|| Arc::new(ConfigSyncHub::new())))
}

/// Notify connected S-Metric clients that their effective configuration may have changed.
///
/// Callers publish only a version/reason. Clients fetch their effective configuration through
/// the normal authenticated configuration API, so secrets and complete configurations are never
/// broadcast over this stream.
pub fn notify_config_changed(reason: impl Into<String>) -> u64 {
    config_sync_hub().publish(reason)
}

#[derive(Clone)]
pub struct ConfigSyncServer {
    hub: Arc<ConfigSyncHub>,
}

impl ConfigSyncServer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            hub: config_sync_hub(),
        }
    }
}

impl Default for ConfigSyncServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl ConfigSyncService for ConfigSyncServer {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<ConfigChanged, Status>> + Send + 'static>>;

    async fn subscribe(
        &self,
        request: Request<SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let last_applied = request.into_inner().last_applied_version;
        let desired = self.hub.desired_version();
        let initial = (last_applied < desired).then_some(Ok(ConfigChanged {
            version: desired,
            reason: "reconcile".to_owned(),
            changed_at_unix_ms: 0,
        }));

        let live = BroadcastStream::new(self.hub.subscribe()).filter_map(|event| async move {
            match event {
                Ok(event) => Some(Ok(ConfigChanged {
                    version: event.version,
                    reason: event.reason,
                    changed_at_unix_ms: event.changed_at_unix_ms,
                })),
                Err(_) => None,
            }
        });
        let stream = stream::iter(initial).chain(live);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_version(
        &self,
        _request: Request<GetVersionRequest>,
    ) -> Result<Response<ConfigVersion>, Status> {
        Ok(Response::new(ConfigVersion {
            desired_version: self.hub.desired_version(),
        }))
    }

    async fn acknowledge(
        &self,
        request: Request<ConfigAck>,
    ) -> Result<Response<AckResponse>, Status> {
        let ack = request.into_inner();
        let desired = self.hub.desired_version();
        if ack.success {
            debug!(version = ack.version, desired, "Client acknowledged S-Metric config version");
        } else {
            warn!(
                version = ack.version,
                desired,
                error = %ack.error,
                "Client failed to apply S-Metric config version"
            );
        }
        Ok(Response::new(AckResponse {
            accepted: ack.version <= desired,
            desired_version: desired,
        }))
    }
}
