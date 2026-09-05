use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};

use crate::{appstate::AppState, auth::AdminRole};

use super::location_deployment::{get, mark_applied, mark_error};

#[derive(Clone, Debug, Deserialize)]
pub struct DeploymentAcknowledgement {
    pub location_id: i64,
    pub generation: i64,
    pub checksum: String,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeploymentAcknowledgementResult {
    pub accepted: bool,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/deployments/acknowledge", post(acknowledge))
}

pub async fn acknowledge(
    _admin: AdminRole,
    State(state): State<AppState>,
    Json(input): Json<DeploymentAcknowledgement>,
) -> Result<Json<DeploymentAcknowledgementResult>, Response> {
    let checksum = input.checksum.trim();
    if input.location_id <= 0 || input.generation <= 0 || checksum.is_empty() {
        tracing::warn!(
            security_event = "smetric_acl_deployment_ack_rejected",
            location_id = input.location_id,
            generation = input.generation,
            reason = "invalid_acknowledgement",
            "Rejected invalid S-Metric firewall deployment acknowledgement"
        );
        return Err((StatusCode::BAD_REQUEST, "invalid deployment acknowledgement").into_response());
    }

    if input.success && input.error.is_some() {
        tracing::warn!(
            security_event = "smetric_acl_deployment_ack_rejected",
            location_id = input.location_id,
            generation = input.generation,
            checksum,
            reason = "success_with_error",
            "Rejected malformed S-Metric firewall deployment acknowledgement"
        );
        return Err((
            StatusCode::BAD_REQUEST,
            "successful acknowledgement must not contain an error",
        )
            .into_response());
    }

    let desired = get(&state.pool, input.location_id)
        .await
        .map_err(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load desired deployment state: {error}"),
            )
                .into_response()
        })?;
    let Some(desired) = desired else {
        tracing::warn!(
            security_event = "smetric_acl_deployment_ack_stale",
            location_id = input.location_id,
            generation = input.generation,
            checksum,
            reason = "no_desired_state",
            "Ignored S-Metric firewall deployment acknowledgement without desired state"
        );
        return Ok(Json(DeploymentAcknowledgementResult { accepted: false }));
    };
    if desired.desired_generation != input.generation || desired.desired_checksum != checksum {
        tracing::warn!(
            security_event = "smetric_acl_deployment_ack_stale",
            location_id = input.location_id,
            generation = input.generation,
            desired_generation = desired.desired_generation,
            checksum,
            desired_checksum = %desired.desired_checksum,
            reason = "generation_or_checksum_mismatch",
            "Ignored stale S-Metric firewall deployment acknowledgement"
        );
        return Ok(Json(DeploymentAcknowledgementResult { accepted: false }));
    }

    let accepted = if input.success {
        mark_applied(
            &state.pool,
            input.location_id,
            input.generation,
            checksum,
        )
        .await
    } else {
        let error = input
            .error
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "failed acknowledgement requires an error message",
                )
                    .into_response()
            })?;
        mark_error(&state.pool, input.location_id, input.generation, error).await
    }
    .map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to record deployment acknowledgement: {error}"),
        )
            .into_response()
    })?;

    if accepted {
        if input.success {
            tracing::info!(
                security_event = "smetric_acl_deployment_applied",
                location_id = input.location_id,
                generation = input.generation,
                checksum,
                "S-Metric firewall deployment applied"
            );
        } else {
            tracing::error!(
                security_event = "smetric_acl_deployment_failed",
                location_id = input.location_id,
                generation = input.generation,
                checksum,
                error = %input.error.as_deref().unwrap_or_default(),
                "S-Metric firewall deployment failed"
            );
        }
    } else {
        tracing::warn!(
            security_event = "smetric_acl_deployment_ack_not_applied",
            location_id = input.location_id,
            generation = input.generation,
            checksum,
            success = input.success,
            "S-Metric firewall deployment acknowledgement was not applied"
        );
    }

    Ok(Json(DeploymentAcknowledgementResult { accepted }))
}
