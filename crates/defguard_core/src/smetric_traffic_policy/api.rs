use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::{
    appstate::AppState, auth::AdminRole, grpc::smetric_config_sync::notify_config_changed,
};

use super::{
    EffectiveTrafficPolicy, TrafficPolicy,
    service::{
        CreateTrafficPolicy, PublishedTrafficPolicy, TrafficPolicyError, create_policy,
        delete_policy, effective_for_device, list_policies, load_policy, publish_policy,
        set_enabled, update_policy,
    },
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/policies", get(list).post(create))
        .route(
            "/policies/{policy_id}",
            get(get_policy).post(update).delete(remove),
        )
        .route("/policies/{policy_id}/enabled", post(set_policy_enabled))
        .route("/policies/{policy_id}/publish", post(publish))
        .route(
            "/effective/device/{device_id}/location/{location_id}",
            get(effective),
        )
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug)]
pub struct ApiError(pub TrafficPolicyError);

impl From<TrafficPolicyError> for ApiError {
    fn from(value: TrafficPolicyError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            TrafficPolicyError::NotFound(_)
            | TrafficPolicyError::DeviceNotFound(_)
            | TrafficPolicyError::TargetNotFound(_) => StatusCode::NOT_FOUND,
            TrafficPolicyError::EmptyName
            | TrafficPolicyError::MissingTargets
            | TrafficPolicyError::MissingDestinations
            | TrafficPolicyError::NeverPublished(_)
            | TrafficPolicyError::InvalidStoredValue(_) => StatusCode::BAD_REQUEST,
            TrafficPolicyError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(ErrorBody {
                error: self.0.to_string(),
            }),
        )
            .into_response()
    }
}

pub async fn list(
    _admin: AdminRole,
    State(state): State<AppState>,
) -> Result<Json<Vec<TrafficPolicy>>, ApiError> {
    Ok(Json(list_policies(&state.pool).await?))
}

pub async fn create(
    _admin: AdminRole,
    State(state): State<AppState>,
    Json(input): Json<CreateTrafficPolicy>,
) -> Result<(StatusCode, Json<TrafficPolicy>), ApiError> {
    let policy = create_policy(&state.pool, input).await?;
    notify_config_changed(format!("smetric_traffic_policy:{}:created", policy.id));
    Ok((StatusCode::CREATED, Json(policy)))
}

pub async fn get_policy(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<TrafficPolicy>, ApiError> {
    Ok(Json(load_policy(&state.pool, policy_id).await?))
}

pub async fn update(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
    Json(input): Json<CreateTrafficPolicy>,
) -> Result<Json<TrafficPolicy>, ApiError> {
    let policy = update_policy(&state.pool, policy_id, input).await?;
    notify_config_changed(format!(
        "smetric_traffic_policy:{policy_id}:draft_revision:{}",
        policy.revision
    ));
    Ok(Json(policy))
}

pub async fn remove(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    delete_policy(&state.pool, policy_id).await?;
    notify_config_changed(format!("smetric_traffic_policy:{policy_id}:deleted"));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Clone, Debug, Deserialize)]
pub struct SetEnabled {
    pub enabled: bool,
}

pub async fn set_policy_enabled(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
    Json(input): Json<SetEnabled>,
) -> Result<Json<TrafficPolicy>, ApiError> {
    set_enabled(&state.pool, policy_id, input.enabled).await?;
    let policy = load_policy(&state.pool, policy_id).await?;
    notify_config_changed(format!(
        "smetric_traffic_policy:{policy_id}:enabled:{}",
        input.enabled
    ));
    Ok(Json(policy))
}

pub async fn publish(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<PublishedTrafficPolicy>, ApiError> {
    let published = publish_policy(&state.pool, policy_id).await?;
    notify_config_changed(format!(
        "smetric_traffic_policy:{policy_id}:revision:{}",
        published.revision
    ));
    Ok(Json(published))
}

pub async fn effective(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path((device_id, location_id)): Path<(i64, i64)>,
) -> Result<Json<Option<EffectiveTrafficPolicy>>, ApiError> {
    Ok(Json(
        effective_for_device(&state.pool, device_id, location_id).await?,
    ))
}
