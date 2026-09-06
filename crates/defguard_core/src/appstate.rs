use std::{
    sync::{Arc, Mutex, RwLock, atomic::AtomicBool},
    time::Duration,
};

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use defguard_common::{db::models::Settings, types::proxy::ProxyControlMessage};
use reqwest::Client;
use serde_json::json;
use sqlx::PgPool;
use tokio::{
    sync::{broadcast::Sender, mpsc::{UnboundedReceiver, UnboundedSender}},
    task::spawn,
};

use crate::{
    auth::failed_login::FailedLoginMap,
    db::{AppEvent, WebHook},
    error::WebError,
    events::{ApiEvent, DirectorySyncEvent, LdapSyncEventType},
    grpc::{GatewayCommand, send_gateway_command, send_multiple_gateway_commands},
    version::IncompatibleComponents,
};

const X_DEFGUARD_EVENT: &str = "x-defguard-event";
const WEBHOOK_DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    tx: UnboundedSender<AppEvent>,
    pub gateway_tx: Sender<GatewayCommand>,
    pub web_reload_tx: tokio::sync::broadcast::Sender<()>,
    pub failed_logins: Arc<Mutex<FailedLoginMap>>,
    key: Key,
    pub event_tx: UnboundedSender<ApiEvent>,
    pub ldap_tx: UnboundedSender<LdapSyncEventType>,
    pub dirsync_tx: UnboundedSender<DirectorySyncEvent>,
    pub incompatible_components: Arc<RwLock<IncompatibleComponents>>,
    pub proxy_control_tx: tokio::sync::mpsc::Sender<ProxyControlMessage>,
    pub tls_active: Arc<AtomicBool>,
}

impl AppState {
    pub(crate) fn trigger_action(&self, event: AppEvent) {
        let event_name = event.name().to_owned();
        match self.tx.send(event) { Ok(()) => info!("Sent trigger {event_name}"), Err(err) => error!("Error sending trigger {event_name}: {err}") }
    }

    async fn handle_triggers(pool: PgPool, mut rx: UnboundedReceiver<AppEvent>) {
        let reqwest_client = Client::builder().user_agent("defguard-webhook/1").timeout(WEBHOOK_DELIVERY_TIMEOUT).build().expect("Failed to build webhook HTTP client");
        while let Some(msg) = rx.recv().await {
            if let Ok(webhooks) = WebHook::all_enabled(&pool, &msg).await {
                debug!("Found {} enabled webhook(s)", webhooks.len());
                let (payload, event) = match msg {
                    AppEvent::UserCreated(user) => (json!(user), "user_created"),
                    AppEvent::UserModified(user) => (json!(user), "user_modified"),
                    AppEvent::UserDeleted(username) => (json!({"username": username}), "user_deleted"),
                    AppEvent::HWKeyProvision(data) => (json!(data), "user_keys"),
                };
                for webhook in webhooks {
                    let mut request = reqwest_client.post(&webhook.url).header(X_DEFGUARD_EVENT, event).json(&payload);
                    if !webhook.token.trim().is_empty() { request = request.bearer_auth(&webhook.token); }
                    match request.send().await {
                        Ok(res) if res.status().is_success() => info!("Webhook {} delivered, status {}", webhook.id, res.status()),
                        Ok(res) => warn!("Webhook {} returned non-success status {}", webhook.id, res.status()),
                        Err(_) => error!("Webhook {} delivery failed", webhook.id),
                    }
                }
            }
        }
    }

    pub fn send_gateway_command(&self, command: GatewayCommand) { send_gateway_command(command, &self.gateway_tx); }
    pub fn send_multiple_gateway_commands(&self, commands: Vec<GatewayCommand>) { send_multiple_gateway_commands(commands, &self.gateway_tx); }
    pub fn emit_event(&self, event: ApiEvent) -> Result<(), WebError> { Ok(self.event_tx.send(event)?) }
    pub fn webauthn(&self) -> Result<Arc<webauthn_rs::Webauthn>, WebError> {
        let settings = Settings::get_current_settings();
        settings.build_webauthn().map(Arc::new).map_err(|err| { error!("Failed to build WebAuthn configuration from current settings: {err}"); WebError::Http(axum::http::StatusCode::INTERNAL_SERVER_ERROR) })
    }
    pub fn new(pool: PgPool, tx: UnboundedSender<AppEvent>, rx: UnboundedReceiver<AppEvent>, gateway_tx: Sender<GatewayCommand>, web_reload_tx: tokio::sync::broadcast::Sender<()>, key: Key, failed_logins: Arc<Mutex<FailedLoginMap>>, event_tx: UnboundedSender<ApiEvent>, ldap_tx: UnboundedSender<LdapSyncEventType>, dirsync_tx: UnboundedSender<DirectorySyncEvent>, incompatible_components: Arc<RwLock<IncompatibleComponents>>, proxy_control_tx: tokio::sync::mpsc::Sender<ProxyControlMessage>, tls_active: Arc<AtomicBool>) -> Self {
        spawn(Self::handle_triggers(pool.clone(), rx));
        Self { pool, tx, gateway_tx, web_reload_tx, failed_logins, key, event_tx, ldap_tx, dirsync_tx, incompatible_components, proxy_control_tx, tls_active }
    }
}

impl FromRef<AppState> for Key { fn from_ref(state: &AppState) -> Self { state.key.clone() } }
