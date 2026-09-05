use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get as route_get, post},
};
use serde::Serialize;

use crate::{
    appstate::AppState, auth::AdminRole, grpc::smetric_config_sync::notify_config_changed,
};

use super::gateway::{GatewayEnforcementError, prepare_deployments};
use super::service::{
    CreatePolicy, CreateRule, PolicySummary, PublishedPolicy, ServiceError, add_rule,
    create_policy, delete_policy, list_policies, load_policy, publish_policy, validate_policy,
};
use super::{Policy, Rule};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/policies", route_get(list).post(create))
        .route("/policies/{policy_id}", route_get(get).delete(remove))
        .route("/policies/{policy_id}/rules", post(create_rule))
        .route("/policies/{policy_id}/validate", post(validate))
        .route("/policies/{policy_id}/publish", post(publish))
        .merge(super::device_groups::router())
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    error: String,
}

#[derive(Debug)]
pub struct ApiError(pub ServiceError);

impl From<ServiceError> for ApiError {
    fn from(value: ServiceError) -> Self {
        Self(value)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            ServiceError::PolicyNotFound(_) => StatusCode::NOT_FOUND,
            ServiceError::Validation(_) | ServiceError::InvalidStoredValue(_) => {
                StatusCode::BAD_REQUEST
            }
            ServiceError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
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

fn gateway_error_response(error: GatewayEnforcementError) -> Response {
    let status = match error {
        GatewayEnforcementError::Database(_)
        | GatewayEnforcementError::Service(ServiceError::Database(_)) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        GatewayEnforcementError::Service(ServiceError::PolicyNotFound(_)) => StatusCode::NOT_FOUND,
        _ => StatusCode::BAD_REQUEST,
    };
    (
        status,
        Json(ErrorBody {
            error: error.to_string(),
        }),
    )
        .into_response()
}

pub async fn list(
    _admin: AdminRole,
    State(state): State<AppState>,
) -> Result<Json<Vec<PolicySummary>>, ApiError> {
    Ok(Json(list_policies(&state.pool).await?))
}

pub async fn create(
    _admin: AdminRole,
    State(state): State<AppState>,
    Json(input): Json<CreatePolicy>,
) -> Result<(StatusCode, Json<PolicySummary>), ApiError> {
    let policy = create_policy(&state.pool, input).await?;
    Ok((StatusCode::CREATED, Json(policy)))
}

pub async fn get(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<Policy>, ApiError> {
    Ok(Json(load_policy(&state.pool, policy_id).await?))
}

pub async fn remove(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    delete_policy(&state.pool, policy_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn create_rule(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
    Json(input): Json<CreateRule>,
) -> Result<(StatusCode, Json<Rule>), ApiError> {
    let rule = add_rule(&state.pool, policy_id, input).await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

pub async fn validate(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<Policy>, ApiError> {
    Ok(Json(validate_policy(&state.pool, policy_id).await?))
}

pub async fn publish(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<PublishedPolicy>, Response> {
    let deployments = prepare_deployments(&state.pool, policy_id)
        .await
        .map_err(gateway_error_response)?;
    let published = publish_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(error).into_response())?;

    for deployment in deployments {
        state.send_gateway_command(deployment.command);
    }

    notify_config_changed(format!(
        "smetric_acl:policy:{}:revision:{}",
        published.policy_id, published.revision
    ));
    Ok(Json(published))
}
