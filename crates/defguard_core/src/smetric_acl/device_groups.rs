use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use defguard_common::gateway_event::GatewayCommand;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{
    appstate::AppState,
    auth::AdminRole,
    grpc::smetric_config_sync::notify_config_changed,
};

use super::{
    gateway::GatewayEnforcementError,
    location_deployment::ensure_desired as ensure_location_desired,
    location_effective::compile_location_firewall,
};

#[derive(Clone, Debug, Serialize)]
pub struct DeviceGroup {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub members: Vec<DeviceGroupMember>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceGroupMember {
    pub device_id: i64,
    pub device_name: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateDeviceGroup {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdateDeviceGroup {
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AddDeviceGroupMember {
    pub device_id: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum DeviceGroupError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Gateway(#[from] GatewayEnforcementError),
    #[error("device group name cannot be empty")]
    EmptyName,
    #[error("S-Metric ACL device group {0} was not found")]
    GroupNotFound(i64),
    #[error("device {0} was not found")]
    DeviceNotFound(i64),
    #[error("a device group named '{0}' already exists")]
    DuplicateName(String),
    #[error("device group '{0}' is referenced by one or more ACL rules")]
    GroupInUse(String),
}

fn default_enabled() -> bool {
    true
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/device-groups", get(list).post(create))
        .route(
            "/device-groups/{group_id}",
            get(get_one).put(update).delete(remove),
        )
        .route("/device-groups/{group_id}/members", post(add_member))
        .route(
            "/device-groups/{group_id}/members/{device_id}",
            delete(remove_member),
        )
}

impl IntoResponse for DeviceGroupError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::EmptyName => StatusCode::BAD_REQUEST,
            Self::GroupNotFound(_) | Self::DeviceNotFound(_) => StatusCode::NOT_FOUND,
            Self::DuplicateName(_) | Self::GroupInUse(_) => StatusCode::CONFLICT,
            Self::Gateway(GatewayEnforcementError::Database(_))
            | Self::Gateway(GatewayEnforcementError::Service(
                super::service::ServiceError::Database(_),
            ))
            | Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Gateway(_) => StatusCode::BAD_REQUEST,
        };
        (status, Json(serde_json::json!({ "error": self.to_string() }))).into_response()
    }
}

pub async fn list(
    _admin: AdminRole,
    State(state): State<AppState>,
) -> Result<Json<Vec<DeviceGroup>>, DeviceGroupError> {
    let rows = sqlx::query_as::<_, (i64, String, Option<String>, bool)>(
        "SELECT id, name, description, enabled FROM smetric_acl_device_group ORDER BY name, id",
    )
    .fetch_all(&state.pool)
    .await?;
    let mut groups = Vec::with_capacity(rows.len());
    for (id, name, description, enabled) in rows {
        groups.push(DeviceGroup {
            id,
            name,
            description,
            enabled,
            members: load_members(&state.pool, id).await?,
        });
    }
    Ok(Json(groups))
}

pub async fn get_one(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Result<Json<DeviceGroup>, DeviceGroupError> {
    Ok(Json(load_group(&state.pool, group_id).await?))
}

pub async fn create(
    _admin: AdminRole,
    State(state): State<AppState>,
    Json(input): Json<CreateDeviceGroup>,
) -> Result<(StatusCode, Json<DeviceGroup>), DeviceGroupError> {
    let name = normalized_name(&input.name)?;
    let row = sqlx::query_as::<_, (i64, String, Option<String>, bool)>(
        "INSERT INTO smetric_acl_device_group (name, description, enabled) VALUES ($1,$2,$3) RETURNING id,name,description,enabled",
    )
    .bind(&name)
    .bind(input.description)
    .bind(input.enabled)
    .fetch_one(&state.pool)
    .await
    .map_err(|error| map_write_error(error, &name))?;
    notify_config_changed(format!("smetric_acl:device_group:{}:created", row.0));
    Ok((
        StatusCode::CREATED,
        Json(DeviceGroup {
            id: row.0,
            name: row.1,
            description: row.2,
            enabled: row.3,
            members: Vec::new(),
        }),
    ))
}

pub async fn update(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(input): Json<UpdateDeviceGroup>,
) -> Result<Json<DeviceGroup>, DeviceGroupError> {
    let old = load_group(&state.pool, group_id).await?;
    let name = normalized_name(&input.name)?;

    if old.name != name && group_is_referenced(&state.pool, &old.name).await? {
        return Err(DeviceGroupError::GroupInUse(old.name));
    }

    let row = sqlx::query_as::<_, (i64, String, Option<String>, bool)>(
        "UPDATE smetric_acl_device_group SET name=$2, description=$3, enabled=$4, updated_at=NOW() WHERE id=$1 RETURNING id,name,description,enabled",
    )
    .bind(group_id)
    .bind(&name)
    .bind(input.description)
    .bind(input.enabled)
    .fetch_optional(&state.pool)
    .await
    .map_err(|error| map_write_error(error, &name))?
    .ok_or(DeviceGroupError::GroupNotFound(group_id))?;

    if old.enabled != row.3 {
        if let Err(error) = redeploy_published_policies_for_group(&state, &row.1).await {
            restore_group(&state.pool, &old).await?;
            return Err(error);
        }
    }

    notify_config_changed(format!("smetric_acl:device_group:{group_id}:updated"));
    Ok(Json(DeviceGroup {
        id: row.0,
        name: row.1,
        description: row.2,
        enabled: row.3,
        members: load_members(&state.pool, group_id).await?,
    }))
}

pub async fn remove(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Result<StatusCode, DeviceGroupError> {
    let group = load_group(&state.pool, group_id).await?;
    if group_is_referenced(&state.pool, &group.name).await? {
        return Err(DeviceGroupError::GroupInUse(group.name));
    }

    let result = sqlx::query("DELETE FROM smetric_acl_device_group WHERE id=$1")
        .bind(group_id)
        .execute(&state.pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(DeviceGroupError::GroupNotFound(group_id));
    }
    notify_config_changed(format!("smetric_acl:device_group:{group_id}:deleted"));
    Ok(StatusCode::NO_CONTENT)
}

pub async fn add_member(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(input): Json<AddDeviceGroupMember>,
) -> Result<(StatusCode, Json<DeviceGroup>), DeviceGroupError> {
    let group = load_group(&state.pool, group_id).await?;
    ensure_device(&state.pool, input.device_id).await?;
    let result = sqlx::query(
        "INSERT INTO smetric_acl_device_group_member (group_id, device_id) VALUES ($1,$2) ON CONFLICT (group_id, device_id) DO NOTHING",
    )
    .bind(group_id)
    .bind(input.device_id)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() > 0 {
        if let Err(error) = redeploy_published_policies_for_group(&state, &group.name).await {
            sqlx::query(
                "DELETE FROM smetric_acl_device_group_member WHERE group_id=$1 AND device_id=$2",
            )
            .bind(group_id)
            .bind(input.device_id)
            .execute(&state.pool)
            .await?;
            return Err(error);
        }
        notify_config_changed(format!(
            "smetric_acl:device_group:{group_id}:member:{}:added",
            input.device_id
        ));
    }

    Ok((
        StatusCode::CREATED,
        Json(load_group(&state.pool, group_id).await?),
    ))
}

pub async fn remove_member(
    _admin: AdminRole,
    State(state): State<AppState>,
    Path((group_id, device_id)): Path<(i64, i64)>,
) -> Result<StatusCode, DeviceGroupError> {
    let group = load_group(&state.pool, group_id).await?;
    let result = sqlx::query(
        "DELETE FROM smetric_acl_device_group_member WHERE group_id=$1 AND device_id=$2",
    )
    .bind(group_id)
    .bind(device_id)
    .execute(&state.pool)
    .await?;
    if result.rows_affected() == 0 {
        return Err(DeviceGroupError::DeviceNotFound(device_id));
    }

    if let Err(error) = redeploy_published_policies_for_group(&state, &group.name).await {
        sqlx::query(
            "INSERT INTO smetric_acl_device_group_member (group_id, device_id) VALUES ($1,$2) ON CONFLICT (group_id, device_id) DO NOTHING",
        )
        .bind(group_id)
        .bind(device_id)
        .execute(&state.pool)
        .await?;
        return Err(error);
    }

    notify_config_changed(format!(
        "smetric_acl:device_group:{group_id}:member:{device_id}:removed"
    ));
    Ok(StatusCode::NO_CONTENT)
}

async fn redeploy_published_policies_for_group(
    state: &AppState,
    group_name: &str,
) -> Result<(), DeviceGroupError> {
    let location_ids = published_location_ids_for_group(&state.pool, group_name).await?;
    let mut prepared = Vec::with_capacity(location_ids.len());

    // Compile every affected location before changing desired deployment state. A selector/render
    // failure therefore leaves all location generations untouched and allows the caller's existing
    // device-group mutation compensation to restore the database change safely.
    for location_id in location_ids {
        let effective = compile_location_firewall(&state.pool, location_id).await?;
        if !effective.policy_ids.is_empty() {
            prepared.push((location_id, effective));
        }
    }

    let mut commands = Vec::with_capacity(prepared.len());
    for (location_id, effective) in prepared {
        ensure_location_desired(&state.pool, location_id, &effective.checksum).await?;
        commands.push(GatewayCommand::FirewallConfigChanged(
            location_id,
            effective.config,
        ));
    }

    if !commands.is_empty() {
        state.send_multiple_gateway_commands(commands);
    }
    Ok(())
}

async fn published_location_ids_for_group(
    pool: &PgPool,
    group_name: &str,
) -> Result<Vec<i64>, sqlx::Error> {
    sqlx::query_scalar::<_, i64>(
        "SELECT DISTINCT a.location_id \
         FROM smetric_acl_policy p \
         JOIN smetric_acl_rule r ON r.policy_id = p.id \
         JOIN smetric_acl_policy_assignment a ON a.policy_id = p.id AND a.enabled = TRUE \
         WHERE p.enabled = TRUE \
           AND r.enabled = TRUE \
           AND r.source_kind = 'device_group' \
           AND r.source_value = $1 \
           AND EXISTS ( \
               SELECT 1 FROM smetric_acl_revision rev \
               WHERE rev.policy_id = p.id AND rev.revision = p.revision \
           ) \
         ORDER BY a.location_id",
    )
    .bind(group_name)
    .fetch_all(pool)
    .await
}

async fn group_is_referenced(pool: &PgPool, group_name: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS( \
             SELECT 1 FROM smetric_acl_rule \
             WHERE source_kind = 'device_group' AND source_value = $1 \
         )",
    )
    .bind(group_name)
    .fetch_one(pool)
    .await
}

async fn restore_group(pool: &PgPool, group: &DeviceGroup) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE smetric_acl_device_group SET name=$2, description=$3, enabled=$4, updated_at=NOW() WHERE id=$1",
    )
    .bind(group.id)
    .bind(&group.name)
    .bind(&group.description)
    .bind(group.enabled)
    .execute(pool)
    .await?;
    Ok(())
}

async fn load_group(pool: &PgPool, group_id: i64) -> Result<DeviceGroup, DeviceGroupError> {
    let row = sqlx::query_as::<_, (i64, String, Option<String>, bool)>(
        "SELECT id, name, description, enabled FROM smetric_acl_device_group WHERE id=$1",
    )
    .bind(group_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DeviceGroupError::GroupNotFound(group_id))?;
    Ok(DeviceGroup {
        id: row.0,
        name: row.1,
        description: row.2,
        enabled: row.3,
        members: load_members(pool, group_id).await?,
    })
}

async fn load_members(
    pool: &PgPool,
    group_id: i64,
) -> Result<Vec<DeviceGroupMember>, DeviceGroupError> {
    let rows = sqlx::query_as::<_, (i64, String)>(
        "SELECT d.id, d.name FROM smetric_acl_device_group_member m JOIN device d ON d.id=m.device_id WHERE m.group_id=$1 ORDER BY d.name,d.id",
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(device_id, device_name)| DeviceGroupMember {
            device_id,
            device_name,
        })
        .collect())
}

async fn ensure_device(pool: &PgPool, device_id: i64) -> Result<(), DeviceGroupError> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM device WHERE id=$1)")
        .bind(device_id)
        .fetch_one(pool)
        .await?;
    if exists {
        Ok(())
    } else {
        Err(DeviceGroupError::DeviceNotFound(device_id))
    }
}

fn normalized_name(value: &str) -> Result<String, DeviceGroupError> {
    let value = value.trim();
    if value.is_empty() {
        Err(DeviceGroupError::EmptyName)
    } else {
        Ok(value.to_owned())
    }
}

fn map_write_error(error: sqlx::Error, name: &str) -> DeviceGroupError {
    if let sqlx::Error::Database(database) = &error {
        if database.is_unique_violation() {
            return DeviceGroupError::DuplicateName(name.to_owned());
        }
    }
    DeviceGroupError::Database(error)
}
