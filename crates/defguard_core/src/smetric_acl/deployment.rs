use defguard_common::gateway_event::GatewayCommand;
use sqlx::PgPool;
use tokio::sync::broadcast::Sender;

use super::{
    gateway::GatewayEnforcementError,
    location_deployment::{ensure_desired as ensure_location_desired, mark_error as mark_location_error},
    location_effective::compile_location_firewall,
};

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Gateway(#[from] GatewayEnforcementError),
    #[error("failed to queue reconciled firewall configuration for location {0}")]
    GatewayChannelClosed(i64),
}

/// Reconcile a location against the gateway's authoritative effective firewall state.
///
/// Reconnects do not allocate a new generation when the effective checksum is unchanged. If the
/// effective firewall changed while the gateway was offline, ensure_location_desired allocates a
/// new location generation before the complete aggregated FirewallConfig is queued.
pub async fn reconcile_location(
    pool: &PgPool,
    gateway_tx: &Sender<GatewayCommand>,
    location_id: i64,
) -> Result<usize, ReconcileError> {
    let effective = compile_location_firewall(pool, location_id).await?;
    if effective.policy_ids.is_empty() {
        return Ok(0);
    }

    let generation = ensure_location_desired(pool, location_id, &effective.checksum).await?;

    if gateway_tx
        .send(GatewayCommand::FirewallConfigChanged(
            location_id,
            effective.config,
        ))
        .is_err()
    {
        let _ = mark_location_error(
            pool,
            location_id,
            generation,
            "gateway command channel is closed during reconnect reconciliation",
        )
        .await;
        return Err(ReconcileError::GatewayChannelClosed(location_id));
    }

    Ok(1)
}
