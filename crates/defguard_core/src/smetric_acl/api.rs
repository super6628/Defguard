use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get as route_get, post},
};
use defguard_common::gateway_event::GatewayCommand;
use serde::{Deserialize, Serialize};

use crate::{
    appstate::AppState, auth::AdminRole, grpc::smetric_config_sync::notify_config_changed,
};

use super::gateway::GatewayEnforcementError;
use super::location_deployment::{
    PolicyLocationDeploymentStatus, ensure_desired as ensure_location_desired,
    list_for_policy as list_location_deployments_for_policy,
};
use super::location_effective::{
    EffectiveLocationFirewall, compile_location_firewall, compile_location_firewall_with_policy,
    compile_location_firewall_without_policy,
};
use super::service::{
    CreatePolicy, CreateRule, PolicySummary, PublishedPolicy, ServiceError, add_rule,
    create_policy, delete_policy, list_policies, load_policy, publish_policy, validate_policy,
};
use super::{Policy, Rule};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/policies", route_get(list).post(create))
        .route("/policies/{policy_id}", route_get(get).delete(remove))
        .route("/policies/{policy_id}/enabled", post(set_policy_enabled))
        .route("/policies/{policy_id}/rules", post(create_rule))
        .route("/policies/{policy_id}/validate", post(validate))
        .route("/policies/{policy_id}/publish", post(publish))
        .route(
            "/policies/{policy_id}/deployments",
            route_get(deployment_status),
        )
        .route(
            "/policies/{policy_id}/assignments",
            route_get(list_assignments),
        )
        .route(
            "/policies/{policy_id}/assignments/{location_id}",
            post(set_assignment).delete(remove_assignment),
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

fn message_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
        .into_response()
}

async fn deploy_effective(
    state: &AppState,
    effective: EffectiveLocationFirewall,
) -> Result<(), Response> {
    ensure_location_desired(&state.pool, effective.location_id, &effective.checksum)
        .await
        .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;
    state.send_gateway_command(GatewayCommand::FirewallConfigChanged(
        effective.location_id,
        effective.config,
    ));
    Ok(())
}

async fn current_revision_is_published(
    state: &AppState,
    policy_id: i64,
) -> Result<bool, Response> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS( \
            SELECT 1 FROM smetric_acl_policy p \
            JOIN smetric_acl_revision r ON r.policy_id=p.id AND r.revision=p.revision \
            WHERE p.id=$1 \
        )",
    )
    .bind(policy_id)
    .fetch_one(&state.pool)
    .await
    .map_err(|error| ApiError(ServiceError::Database(error)).into_response())
}

async fn location_exists(state: &AppState, location_id: i64) -> Result<bool, Response> {
    sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM wireguard_network WHERE id=$1)")
        .bind(location_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|error| ApiError(ServiceError::Database(error)).into_response())
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

#[derive(Clone, Debug, Deserialize)]
pub struct SetPolicyEnabled {
    pub enabled: bool,
}

pub async fn set_policy_enabled(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
    Json(input): Json<SetPolicyEnabled>,
) -> Result<Json<Policy>, Response> {
    let policy = load_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(error).into_response())?;
    if policy.enabled == input.enabled {
        return Ok(Json(policy));
    }

    let location_ids = sqlx::query_scalar::<_, i64>(
        "SELECT location_id FROM smetric_acl_policy_assignment \
         WHERE policy_id=$1 AND enabled=TRUE ORDER BY location_id",
    )
    .bind(policy_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;

    if input.enabled && !current_revision_is_published(&state, policy_id).await? {
        return Err(message_response(
            StatusCode::BAD_REQUEST,
            "publish the current policy revision before enabling it",
        ));
    }

    let mut replacements = Vec::with_capacity(location_ids.len());
    for location_id in location_ids {
        let effective = if input.enabled {
            compile_location_firewall_with_policy(&state.pool, location_id, policy_id).await
        } else {
            compile_location_firewall_without_policy(&state.pool, location_id, policy_id).await
        }
        .map_err(gateway_error_response)?;
        replacements.push(effective);
    }

    sqlx::query("UPDATE smetric_acl_policy SET enabled=$2, updated_at=NOW() WHERE id=$1")
        .bind(policy_id)
        .bind(input.enabled)
        .execute(&state.pool)
        .await
        .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;

    for effective in replacements {
        deploy_effective(&state, effective).await?;
    }
    notify_config_changed(format!(
        "smetric_acl:policy:{policy_id}:enabled:{}",
        input.enabled
    ));

    Ok(Json(
        load_policy(&state.pool, policy_id)
            .await
            .map_err(|error| ApiError(error).into_response())?,
    ))
}

pub async fn remove(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<StatusCode, Response> {
    load_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(error).into_response())?;

    let location_ids = sqlx::query_scalar::<_, i64>(
        "SELECT DISTINCT location_id FROM smetric_acl_policy_assignment \
         WHERE policy_id=$1 AND enabled=TRUE ORDER BY location_id",
    )
    .bind(policy_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;

    let mut replacements: Vec<EffectiveLocationFirewall> = Vec::with_capacity(location_ids.len());
    for location_id in location_ids {
        replacements.push(
            compile_location_firewall_without_policy(&state.pool, location_id, policy_id)
                .await
                .map_err(gateway_error_response)?,
        );
    }

    delete_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(error).into_response())?;

    for effective in replacements {
        deploy_effective(&state, effective).await?;
    }

    notify_config_changed(format!("smetric_acl:policy:{policy_id}:deleted"));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyAssignment {
    pub policy_id: i64,
    pub location_id: i64,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SetPolicyAssignment {
    pub enabled: bool,
}

pub async fn list_assignments(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<Vec<PolicyAssignment>>, Response> {
    load_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(error).into_response())?;
    let rows = sqlx::query_as::<_, (i64, i64, bool)>(
        "SELECT policy_id, location_id, enabled FROM smetric_acl_policy_assignment \
         WHERE policy_id=$1 ORDER BY location_id",
    )
    .bind(policy_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;
    Ok(Json(
        rows.into_iter()
            .map(|row| PolicyAssignment {
                policy_id: row.0,
                location_id: row.1,
                enabled: row.2,
            })
            .collect(),
    ))
}

pub async fn set_assignment(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path((policy_id, location_id)): Path<(i64, i64)>,
    Json(input): Json<SetPolicyAssignment>,
) -> Result<Json<PolicyAssignment>, Response> {
    let policy = load_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(error).into_response())?;
    if !location_exists(&state, location_id).await? {
        return Err(message_response(
            StatusCode::NOT_FOUND,
            format!("VPN location {location_id} was not found"),
        ));
    }

    let existing = sqlx::query_scalar::<_, bool>(
        "SELECT enabled FROM smetric_acl_policy_assignment WHERE policy_id=$1 AND location_id=$2",
    )
    .bind(policy_id)
    .bind(location_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;

    let changes_effective_firewall = policy.enabled && existing != Some(input.enabled);
    let replacement = if changes_effective_firewall {
        if input.enabled {
            if !current_revision_is_published(&state, policy_id).await? {
                return Err(message_response(
                    StatusCode::BAD_REQUEST,
                    "publish the current policy revision before enabling its assignment",
                ));
            }
            Some(
                compile_location_firewall_with_policy(&state.pool, location_id, policy_id)
                    .await
                    .map_err(gateway_error_response)?,
            )
        } else {
            Some(
                compile_location_firewall_without_policy(&state.pool, location_id, policy_id)
                    .await
                    .map_err(gateway_error_response)?,
            )
        }
    } else {
        None
    };

    sqlx::query(
        "INSERT INTO smetric_acl_policy_assignment (policy_id, location_id, enabled) \
         VALUES ($1,$2,$3) \
         ON CONFLICT (policy_id, location_id) DO UPDATE SET enabled=EXCLUDED.enabled",
    )
    .bind(policy_id)
    .bind(location_id)
    .bind(input.enabled)
    .execute(&state.pool)
    .await
    .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;

    if let Some(effective) = replacement {
        deploy_effective(&state, effective).await?;
    }
    notify_config_changed(format!(
        "smetric_acl:policy:{policy_id}:location:{location_id}:assigned:{}",
        input.enabled
    ));

    Ok(Json(PolicyAssignment {
        policy_id,
        location_id,
        enabled: input.enabled,
    }))
}

pub async fn remove_assignment(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path((policy_id, location_id)): Path<(i64, i64)>,
) -> Result<StatusCode, Response> {
    let policy = load_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(error).into_response())?;
    let existing = sqlx::query_scalar::<_, bool>(
        "SELECT enabled FROM smetric_acl_policy_assignment WHERE policy_id=$1 AND location_id=$2",
    )
    .bind(policy_id)
    .bind(location_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?
    .ok_or_else(|| {
        message_response(
            StatusCode::NOT_FOUND,
            format!("policy {policy_id} is not assigned to location {location_id}"),
        )
    })?;

    let replacement = if policy.enabled && existing {
        Some(
            compile_location_firewall_without_policy(&state.pool, location_id, policy_id)
                .await
                .map_err(gateway_error_response)?,
        )
    } else {
        None
    };

    sqlx::query("DELETE FROM smetric_acl_policy_assignment WHERE policy_id=$1 AND location_id=$2")
        .bind(policy_id)
        .bind(location_id)
        .execute(&state.pool)
        .await
        .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;

    if let Some(effective) = replacement {
        deploy_effective(&state, effective).await?;
    }
    notify_config_changed(format!(
        "smetric_acl:policy:{policy_id}:location:{location_id}:unassigned"
    ));
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
) -> Result<Json<Vec<PolicyLocationDeploymentStatus>>, Response> {
    load_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(error).into_response())?;
    let deployments = list_location_deployments_for_policy(&state.pool, policy_id)
        .await
        .map_err(|error| ApiError(ServiceError::Database(error)).into_response())?;
    Ok(Json(deployments))
}

pub async fn publish(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(policy_id): Path<i64>,
) -> Result<Json<PublishedPolicy>, Response> {
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
        deploy_effective(&state, effective).await?;
    }

    notify_config_changed(format!(
        "smetric_acl:policy:{}:revision:{}",
        published.policy_id, published.revision
    ));
    Ok(Json(published))
}
