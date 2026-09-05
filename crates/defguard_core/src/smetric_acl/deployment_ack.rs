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
        return Err((StatusCode::BAD_REQUEST, "invalid deployment acknowledgement").into_response());
    }

    if input.success && input.error.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "successful acknowledgement must not contain an error",
        )
            .into_response());
    }

    // Bind both generation and checksum to the current desired location state. This prevents a
    // stale gateway response from acknowledging a newer aggregate configuration that happens to
    // share the same location id.
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
        return Ok(Json(DeploymentAcknowledgementResult { accepted: false }));
    };
    if desired.desired_generation != input.generation || desired.desired_checksum != checksum {
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

    Ok(Json(DeploymentAcknowledgementResult { accepted }))
}
