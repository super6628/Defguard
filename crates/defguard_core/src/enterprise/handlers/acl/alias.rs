use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use defguard_common::db::{Id, NoId};
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, ToSchema)]
pub struct EditAclAlias {
    pub name: String,
    pub addresses: String,
    pub ports: String,
    pub protocols: Vec<Protocol>,
}

impl EditAclAlias {
    fn validate(&self) -> Result<(), WebError> {
        if self.name.trim().is_empty() {
            return Err(WebError::BadRequest("Alias name cannot be empty".to_owned()));
        }
        if self.addresses.trim().is_empty()
            && self.ports.trim().is_empty()
            && self.protocols.is_empty()
        {
            return Err(WebError::BadRequest(
                "Must provide alias addresses, ports, or protocols".to_owned(),
            ));
        }
        Ok(())
    }

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
pub struct ApiAclAlias {
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
}

#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ApplyAclAliasesData {
    aliases: Vec<Id>,
}

impl ApiAclAlias {
    pub(crate) async fn create_from_api(
        pool: &PgPool,
        api_alias: &EditAclAlias,
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
        api_alias: &EditAclAlias,
        actor: &str,
    ) -> Result<Self, AclError> {
        let mut transaction = pool.begin().await?;
        let existing_alias =
            AclAlias::find_by_id_and_kind(&mut *transaction, id, AliasKind::Component)
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
                debug!("Removed {} old modifications of alias {id}", result.rows_affected());
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

impl From<AclAliasInfo> for ApiAclAlias {
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
        }
    }
}

#[utoipa::path(get, path = "/api/v1/acl/alias", tag = "ACL", responses((status = 200, body = [ApiAclAlias])))]
pub(crate) async fn list_acl_aliases(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
) -> ApiResult {
    debug!("User {} listing ACL aliases", session.user.username);
    let aliases = AclAlias::all_of_kind(&appstate.pool, AliasKind::Component).await?;
    let mut api_aliases = Vec::<ApiAclAlias>::with_capacity(aliases.len());
    for alias in &aliases {
        let info = alias.to_info(&appstate.pool).await.map_err(|err| {
            error!("Error retrieving ACL alias {alias:?}: {err}");
            err
        })?;
        api_aliases.push(info.into());
    }
    Ok(ApiResponse::json(api_aliases, StatusCode::OK))
}

#[utoipa::path(get, path = "/api/v1/acl/alias/count", tag = "ACL", responses((status = 200, body = AclStateCount)))]
pub(crate) async fn count_acl_aliases(_admin: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    let counts = query_as::<_, AclStateCount>(
        "SELECT COUNT(*) FILTER (WHERE state = 'applied'::aclalias_state) AS applied, COUNT(*) FILTER (WHERE state = 'modified'::aclalias_state) AS pending FROM aclalias WHERE kind = $1",
    )
    .bind(AliasKind::Component)
    .fetch_one(&appstate.pool)
    .await?;
    Ok(ApiResponse::json(counts, StatusCode::OK))
}

#[utoipa::path(get, path = "/api/v1/acl/alias/{id}", tag = "ACL", params(("id" = i64, Path)), responses((status = 200, body = ApiAclAlias)))]
pub(crate) async fn get_acl_alias(
    _license: LicenseInfo,
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    Path(id): Path<Id>,
) -> ApiResult {
    let (alias, status) = match AclAlias::find_by_id_and_kind(&appstate.pool, id, AliasKind::Component).await? {
        Some(alias) => (
            json!(ApiAclAlias::from(alias.to_info(&appstate.pool).await?)),
            StatusCode::OK,
        ),
        None => (Value::Null, StatusCode::NOT_FOUND),
    };
    Ok(ApiResponse::new(alias, status))
}

#[utoipa::path(post, path = "/api/v1/acl/alias", tag = "ACL", request_body = EditAclAlias, responses((status = 201, body = ApiAclAlias)))]
pub(crate) async fn create_acl_alias(
    _license: LicenseInfo,
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    Json(data): Json<EditAclAlias>,
) -> ApiResult {
    data.validate()?;
    let alias = ApiAclAlias::create_from_api(&appstate.pool, &data, &session.user.username).await?;
    Ok(ApiResponse::json(alias, StatusCode::CREATED))
}

#[utoipa::path(put, path = "/api/v1/acl/alias/{id}", tag = "ACL", params(("id" = i64, Path)), request_body = EditAclAlias, responses((status = 200, body = ApiAclAlias)))]
pub(crate) async fn update_acl_alias(
    _license: LicenseInfo,
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    Path(id): Path<Id>,
    Json(data): Json<EditAclAlias>,
) -> ApiResult {
    data.validate()?;
    let alias = ApiAclAlias::update_from_api(&appstate.pool, id, &data, &session.user.username).await?;
    Ok(ApiResponse::json(alias, StatusCode::OK))
}

#[utoipa::path(delete, path = "/api/v1/acl/alias/{id}", tag = "ACL", params(("id" = i64, Path)), responses((status = 200)))]
pub(crate) async fn delete_acl_alias(
    _license: LicenseInfo,
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    Path(id): Path<Id>,
) -> ApiResult {
    AclAlias::delete_by_kind(&appstate.pool, id, AliasKind::Component).await?;
    info!("User {} deleted ACL alias {id}", session.user.username);
    Ok(ApiResponse::default())
}

#[utoipa::path(put, path = "/api/v1/acl/alias/apply", tag = "ACL", request_body = ApplyAclAliasesData, responses((status = 200)))]
pub(crate) async fn apply_acl_aliases(
    _license: LicenseInfo,
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    Json(data): Json<ApplyAclAliasesData>,
) -> ApiResult {
    if data.aliases.is_empty() {
        return Err(WebError::BadRequest(
            "Must provide at least one ACL alias to apply".to_owned(),
        ));
    }
    AclAlias::apply_by_kind(
        &data.aliases,
        AliasKind::Component,
        &session.user.username,
        &appstate.pool,
        &appstate.gateway_tx,
    )
    .await?;
    Ok(ApiResponse::default())
}
