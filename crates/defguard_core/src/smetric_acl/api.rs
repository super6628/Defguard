use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::appstate::AppState;

use super::service::{
    CreatePolicy, CreateRule, PolicySummary, PublishedPolicy, ServiceError, add_rule, create_policy,
    delete_policy, list_policies, load_policy, publish_policy, validate_policy,
};
use super::{Policy, Rule};

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
        (status, Json(ErrorBody { error: self.0.to_string() })).into_response()
    }
}

pub async fn list(State(state): State<AppState>) -> Result<Json<Vec<PolicySummary>>, ApiError> {
    Ok(Json(list_policies(&state.pool).await?))
}

pub async fn create(
    State(state): State<AppState>,
    Json(input): Json<CreatePolicy>,
) -> Result<(StatusCode, Json<PolicySummary>), ApiError> {
    let policy = create_policy(&state.pool, input).await?;
    Ok((StatusCode::CREATED, Json(policy)))
}

pub async fn get(
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<Policy>, ApiError> {
    Ok(Json(load_policy(&state.pool, policy_id).await?))
}

pub async fn remove(
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    delete_policy(&state.pool, policy_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn create_rule(
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
    Json(input): Json<CreateRule>,
) -> Result<(StatusCode, Json<Rule>), ApiError> {
    let rule = add_rule(&state.pool, policy_id, input).await?;
    Ok((StatusCode::CREATED, Json(rule)))
}

pub async fn validate(
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<Policy>, ApiError> {
    Ok(Json(validate_policy(&state.pool, policy_id).await?))
}

pub async fn publish(
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<PublishedPolicy>, ApiError> {
    Ok(Json(publish_policy(&state.pool, policy_id).await?))
}
