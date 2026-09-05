use axum::{
    Json,
    extract::{Path, State},
};
use defguard_common::db::{Id, NoId};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::{PgConnection, PgPool, query, query_as};
use utoipa::ToSchema;

use super::{AclStateCount, LicenseInfo};
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    enterprise::db::models::acl::{
        AclAlias, AclAliasDestinationRange, AclAliasInfo, AclError, AliasKind, AliasState,
        Protocol, acl_delete_related_objects, parse_destination_addresses,
    },
    error::WebError,
    handlers::{ApiErrorResponse, ApiResponse, ApiResult},
};

/// An ACL destination, as accepted when creating or updating one.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, ToSchema)]
pub struct EditAclDestination {
    pub name: String,
    pub addresses: String,
    pub ports: String,
    pub protocols: Vec<Protocol>,
    pub any_address: bool,
    pub any_port: bool,
    pub any_protocol: bool,
}

impl EditAclDestination {
    fn validate(&self) -> Result<(), WebError> {
        if self.name.trim().is_empty() {
            return Err(WebError::BadRequest(
                "Destination name cannot be empty".to_owned(),
            ));
        }
        if !self.any_address && self.addresses.trim().is_empty() {
            return Err(WebError::BadRequest(
                "Must provide destination addresses or enable any address".to_owned(),
            ));
        }
        if !self.any_port && self.ports.trim().is_empty() {
            return Err(WebError::BadRequest(
                "Must provide destination ports or enable any port".to_owned(),
            ));
        }
        if !self.any_protocol && self.protocols.is_empty() {
            return Err(WebError::BadRequest(
                "Must provide destination protocols or enable any protocol".to_owned(),
            ));
        }

        Ok(())
    }

    /// Creates relation objects for a given [`AclAlias`] based on [`AclAliasInfo`] object.
    pub(crate) async fn create_related_objects(
        &self,
        transaction: &mut PgConnection,
        alias_id: Id,
    ) -> Result<(), AclError> {
        debug!("Creating related objects for ACL alias {self:?}");
        let destination = parse_destination_addresses(&self.addresses)?;
        for range in destination.ranges {
            let obj = AclAliasDestinationRange {
                id: NoId,
                alias_id,
                start: range.0,
                end: range.1,
            };
            obj.save(&mut *transaction).await?;
        }

        info!("Created related objects for ACL alias {self:?}");
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, ToSchema)]
pub struct ApiAclDestination {
    #[serde(default)]
    pub id: Id,
    pub parent_id: Option<Id>,
    pub name: String,
    pub kind: AliasKind,
    pub state: AliasState,
    pub addresses: String,
    pub ports: String,
    pub protocols: Vec<Protocol>,
    pub rules: Vec<Id>,
    pub any_address: bool,
    pub any_port: bool,
    pub any_protocol: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ApplyAclDestinationsData {
    destinations: Vec<Id>,
}

impl ApiAclDestination {
    pub(crate) async fn create_from_api(
        pool: &PgPool,
        api_alias: &EditAclDestination,
        actor: &str,
    ) -> Result<Self, AclError> {
        let mut transaction = pool.begin().await?;

        let mut alias = AclAlias::try_from(api_alias)?;
        alias.stamp_modified(actor);
        let alias = alias.save(&mut *transaction).await?;

        api_alias
            .create_related_objects(&mut transaction, alias.id)
            .await?;

        transaction.commit().await?;
        Ok(Self::from(alias.to_info(pool).await?))
    }

    pub(crate) async fn update_from_api(
        pool: &PgPool,
        id: Id,
        api_alias: &EditAclDestination,
        actor: &str,
    ) -> Result<Self, AclError> {
        let mut transaction = pool.begin().await?;
        let existing_alias =
            AclAlias::find_by_id_and_kind(&mut *transaction, id, AliasKind::Destination)
                .await?
                .ok_or_else(|| {
                    warn!("Update of nonexistent alias ({id}) failed");
                    AclError::AliasNotFoundError(id)
                })?;

        let mut alias = AclAlias::try_from(api_alias)?;
        alias.stamp_modified(actor);

        let alias = match existing_alias.state {
            AliasState::Applied => {
                let result = query!("DELETE FROM aclalias WHERE parent_id = $1", id)
                    .execute(&mut *transaction)
                    .await?;
                debug!(
                    "Removed {} old modifications of alias {id}",
                    result.rows_affected(),
                );

                alias.state = AliasState::Modified;
                alias.parent_id = Some(id);
                let alias = alias.save(&mut *transaction).await?;
                api_alias
                    .create_related_objects(&mut transaction, alias.id)
                    .await?;
                alias
            }
            AliasState::Modified => {
                let mut alias = alias.with_id(id);
                alias.parent_id = existing_alias.parent_id;
                alias.state = existing_alias.state;
                alias.save(&mut *transaction).await?;
                acl_delete_related_objects(&mut transaction, alias.id).await?;
                api_alias
                    .create_related_objects(&mut transaction, alias.id)
                    .await?;
                alias
            }
        };

        transaction.commit().await?;
        Ok(alias.to_info(pool).await?.into())
    }
}

impl From<AclAliasInfo> for ApiAclDestination {
    fn from(info: AclAliasInfo) -> Self {
        Self {
            addresses: info.format_destination(),
            ports: info.format_ports(),
            id: info.id,
            parent_id: info.parent_id,
            name: info.name,
            kind: info.kind,
            state: info.state,
            protocols: info.protocols,
            rules: info.rules.iter().map(|v| v.id).collect(),
            any_address: info.any_address,
            any_port: info.any_port,
            any_protocol: info.any_protocol,
        }
    }
}

#[utoipa::path(get, path = "/api/v1/acl/destination", tag = "ACL", responses((status = 200, body = [ApiAclDestination])))]
pub(crate) async fn list_acl_destinations(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
) -> ApiResult {
    debug!("User {} listing ACL destinations", session.user.username);
    let aliases = AclAlias::all_of_kind(&appstate.pool, AliasKind::Destination).await?;
    let mut api_aliases = Vec::<ApiAclDestination>::with_capacity(aliases.len());
    for alias in &aliases {
        let info = alias.to_info(&appstate.pool).await.map_err(|err| {
            error!("Error retrieving ACL destination {alias:?}: {err}");
            err
        })?;
        api_aliases.push(info.into());
    }
    Ok(ApiResponse::json(api_aliases, StatusCode::OK))
}

#[utoipa::path(get, path = "/api/v1/acl/destination/count", tag = "ACL", responses((status = 200, body = AclStateCount)))]
pub(crate) async fn count_acl_destinations(
    _admin: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    let counts = query_as::<_, AclStateCount>(
        "SELECT COUNT(*) FILTER (WHERE state = 'applied'::aclalias_state) AS applied, COUNT(*) FILTER (WHERE state = 'modified'::aclalias_state) AS pending FROM aclalias WHERE kind = $1",
    )
    .bind(AliasKind::Destination)
    .fetch_one(&appstate.pool)
    .await?;
    Ok(ApiResponse::json(counts, StatusCode::OK))
}

#[utoipa::path(get, path = "/api/v1/acl/destination/{id}", tag = "ACL", params(("id" = i64, Path)), responses((status = 200, body = ApiAclDestination)))]
pub(crate) async fn get_acl_destination(
    _license: LicenseInfo,
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    Path(id): Path<Id>,
) -> ApiResult {
    let (alias, status) =
        match AclAlias::find_by_id_and_kind(&appstate.pool, id, AliasKind::Destination).await? {
            Some(alias) => (
                json!(ApiAclDestination::from(alias.to_info(&appstate.pool).await?)),
                StatusCode::OK,
            ),
            None => (Value::Null, StatusCode::NOT_FOUND),
        };
    info!("User {} retrieved ACL destination {id}", session.user.username);
    Ok(ApiResponse::new(alias, status))
}

#[utoipa::path(post, path = "/api/v1/acl/destination", tag = "ACL", request_body = EditAclDestination, responses((status = 201, body = ApiAclDestination)))]
pub(crate) async fn create_acl_destination(
    _license: LicenseInfo,
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    Json(data): Json<EditAclDestination>,
) -> ApiResult {
    data.validate()?;
    let alias = ApiAclDestination::create_from_api(&appstate.pool, &data, &session.user.username).await?;
    Ok(ApiResponse::json(alias, StatusCode::CREATED))
}

#[utoipa::path(put, path = "/api/v1/acl/destination/{id}", tag = "ACL", params(("id" = i64, Path)), request_body = EditAclDestination, responses((status = 200, body = ApiAclDestination)))]
pub(crate) async fn update_acl_destination(
    _license: LicenseInfo,
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    Path(id): Path<Id>,
    Json(data): Json<EditAclDestination>,
) -> ApiResult {
    data.validate()?;
    let alias = ApiAclDestination::update_from_api(&appstate.pool, id, &data, &session.user.username).await?;
    Ok(ApiResponse::json(alias, StatusCode::OK))
}

#[utoipa::path(delete, path = "/api/v1/acl/destination/{id}", tag = "ACL", params(("id" = i64, Path)), responses((status = 200)))]
pub(crate) async fn delete_acl_destination(
    _license: LicenseInfo,
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    Path(id): Path<Id>,
) -> ApiResult {
    AclAlias::delete_by_kind(&appstate.pool, id, AliasKind::Destination).await?;
    info!("User {} deleted ACL destination {id}", session.user.username);
    Ok(ApiResponse::default())
}

#[utoipa::path(put, path = "/api/v1/acl/destination/apply", tag = "ACL", request_body = ApplyAclDestinationsData, responses((status = 200)))]
pub(crate) async fn apply_acl_destinations(
    _license: LicenseInfo,
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    Json(data): Json<ApplyAclDestinationsData>,
) -> ApiResult {
    if data.destinations.is_empty() {
        return Err(WebError::BadRequest(
            "Must provide at least one ACL destination to apply".to_owned(),
        ));
    }

    AclAlias::apply_by_kind(
        &data.destinations,
        AliasKind::Destination,
        &session.user.username,
        &appstate.pool,
        &appstate.gateway_tx,
    )
    .await?;
    Ok(ApiResponse::default())
}
