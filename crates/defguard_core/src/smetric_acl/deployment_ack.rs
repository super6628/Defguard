use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};

use crate::{appstate::AppState, auth::AdminRole};

use super::deployment::{mark_applied, mark_error};

#[derive(Clone, Debug, Deserialize)]
pub struct DeploymentAcknowledgement {
    pub policy_id: i64,
    pub location_id: i64,
    pub generation: i64,
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
    if input.policy_id <= 0 || input.location_id <= 0 || input.generation <= 0 {
        return Err((StatusCode::BAD_REQUEST, "invalid deployment acknowledgement").into_response());
    }

    if input.success && input.error.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "successful acknowledgement must not contain an error",
        )
            .into_response());
    }

    let accepted = if input.success {
        mark_applied(
            &state.pool,
            input.policy_id,
            input.location_id,
            input.generation,
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
        mark_error(
            &state.pool,
            input.policy_id,
            input.location_id,
            input.generation,
            error,
        )
        .await
    }
    .map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to record deployment acknowledgement: {error}"),
        )
            .into_response()
    })?;

    // A stale or unknown generation is intentionally not treated as a server error. The caller
    // receives accepted=false and can reconcile against the current desired generation.
    Ok(Json(DeploymentAcknowledgementResult { accepted }))
}
