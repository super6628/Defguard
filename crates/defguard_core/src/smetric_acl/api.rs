use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get as route_get, post},
};
use defguard_common::gateway_event::GatewayCommand;
use serde::Serialize;

use crate::{
    appstate::AppState, auth::AdminRole, grpc::smetric_config_sync::notify_config_changed,
};

use super::deployment::{DeploymentState, list_for_policy};
use super::gateway::GatewayEnforcementError;
use super::location_deployment::ensure_desired as ensure_location_desired;
use super::location_effective::compile_location_firewall;
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
        .route(
            "/policies/{policy_id}/deployments",
            route_get(deployment_status),
        )
        .merge(super::device_groups::router())
        .merge(super::deployment_ack::router())
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

pub async fn deployment_status(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<Vec<DeploymentState>>, Response> {
    load_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(error).into_response())?;
    let deployments = list_for_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;
    Ok(Json(deployments))
}

pub async fn publish(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<PublishedPolicy>, Response> {
    // Validate and persist the policy revision first so the location compiler sees this revision as
    // published when it builds the authoritative effective location firewall.
    let published = publish_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(error).into_response())?;

    let location_ids = sqlx::query_scalar::<_, i64>(
        "SELECT location_id FROM smetric_acl_policy_assignment \
         WHERE policy_id=$1 AND enabled=TRUE ORDER BY location_id",
    )
    .bind(policy_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;

    for location_id in location_ids {
        let effective = compile_location_firewall(&state.pool, location_id)
            .await
            .map_err(gateway_error_response)?;
        if effective.policy_ids.is_empty() {
            continue;
        }

        ensure_location_desired(&state.pool, location_id, &effective.checksum)
            .await
            .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;

        state.send_gateway_command(GatewayCommand::FirewallConfigChanged(
            location_id,
            effective.config,
        ));
    }

    notify_config_changed(format!(
        "smetric_acl:policy:{}:revision:{}",
        published.policy_id, published.revision
    ));
    Ok(Json(published))
}
