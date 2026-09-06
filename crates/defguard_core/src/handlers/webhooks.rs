use std::time::Duration;

use axum::{
    extract::{Json, Path, State},
    http::StatusCode,
};
use defguard_common::db::Id;
use reqwest::{Client, Url};
use utoipa::ToSchema;

use super::{ApiErrorResponse, ApiResponse, ApiResult, WebHookData};
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    db::WebHook,
    error::WebError,
    events::{ApiEvent, ApiEventType, ApiRequestContext},
};

const X_DEFGUARD_EVENT: &str = "x-defguard-event";
const WEBHOOK_TEST_TIMEOUT: Duration = Duration::from_secs(10);

fn validate_webhook_url(url: &str) -> Result<(), WebError> {
    let parsed = Url::parse(url)
        .map_err(|_| WebError::BadRequest("Webhook URL must be a valid URL".into()))?;

    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(WebError::BadRequest(
            "Webhook URL must use http or https".into(),
        ));
    }

    if parsed.host_str().is_none() {
        return Err(WebError::BadRequest(
            "Webhook URL must include a host".into(),
        ));
    }

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(WebError::BadRequest(
            "Webhook URL must not contain embedded credentials".into(),
        ));
    }

    Ok(())
}

fn redact_webhook_token(mut webhook: WebHook<Id>) -> WebHook<Id> {
    webhook.token.clear();
    webhook
}

#[derive(Serialize, ToSchema)]
pub struct WebHookTestResponse {
    /// Whether the target returned a successful (2xx) HTTP response.
    pub delivered: bool,
    /// HTTP status returned by the target, if a response was received.
    pub status: Option<u16>,
    /// Delivery error if the target could not be reached.
    pub error: Option<String>,
}

async fn send_test_webhook(
    session: &SessionInfo,
    appstate: &AppState,
    id: Id,
) -> ApiResult {
    debug!("User {} testing webhook {id}", session.user.username);
    let Some(webhook) = WebHook::find_by_id(&appstate.pool, id).await? else {
        return Ok(ApiResponse::with_status(StatusCode::NOT_FOUND));
    };

    validate_webhook_url(&webhook.url)?;

    let client = Client::builder()
        .timeout(WEBHOOK_TEST_TIMEOUT)
        .build()
        .map_err(|err| {
            error!("Failed to build webhook test client: {err}");
            WebError::Http(StatusCode::INTERNAL_SERVER_ERROR)
        })?;

    let payload = serde_json::json!({
        "event": "test",
        "source": "defguard",
        "webhook_id": id,
    });

    let mut request = client
        .post(&webhook.url)
        .header(X_DEFGUARD_EVENT, "test")
        .json(&payload);
    if !webhook.token.trim().is_empty() {
        request = request.bearer_auth(&webhook.token);
    }

    match request.send().await {
        Ok(response) => {
            let target_status = response.status();
            let delivered = target_status.is_success();
            let api_status = if delivered {
                StatusCode::OK
            } else {
                StatusCode::BAD_GATEWAY
            };
            info!(
                "Webhook {id} test sent by {}, target status {}",
                session.user.username, target_status
            );
            Ok(ApiResponse::json(
                WebHookTestResponse {
                    delivered,
                    status: Some(target_status.as_u16()),
                    error: None,
                },
                api_status,
            ))
        }
        Err(_) => {
            warn!("Webhook {id} test delivery failed");
            Ok(ApiResponse::json(
                WebHookTestResponse {
                    delivered: false,
                    status: None,
                    error: Some("Webhook target could not be reached".into()),
                },
                StatusCode::BAD_GATEWAY,
            ))
        }
    }
}

/// Create a webhook
#[utoipa::path(
    post,
    path = "/api/v1/webhook",
    tag = "webhook",
    request_body = WebHookData,
    responses(
        (status = 201, description = "Webhook created."),
        (status = 400, description = "Unable to save the webhook."),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 500, description = "Unable to create webhook.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = []),
        ("api_token" = [])
    )
)]
pub async fn add_webhook(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Json(webhookdata): Json<WebHookData>,
) -> ApiResult {
    validate_webhook_url(&webhookdata.url)?;
    debug!("User {} adding webhook", session.user.username);
    let webhook: WebHook = webhookdata.into();
    let status = match webhook.save(&appstate.pool).await {
        Ok(webhook) => {
            info!("User {} added webhook {}", session.user.username, webhook.id);
            appstate.emit_event(ApiEvent {
                context,
                event: Box::new(ApiEventType::WebHookAdded {
                    webhook: redact_webhook_token(webhook),
                }),
            })?;
            StatusCode::CREATED
        }
        Err(_) => StatusCode::BAD_REQUEST,
    };

    Ok(ApiResponse::with_status(status))
}

// TODO: paginate
/// List webhooks
#[utoipa::path(
    get,
    path = "/api/v1/webhook",
    tag = "webhook",
    responses(
        (status = 200, description = "All webhooks.", body = [WebHook]),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 500, description = "Unable to list webhooks.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = []),
        ("api_token" = [])
    )
)]
pub async fn list_webhooks(_admin: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    let webhooks = WebHook::all(&appstate.pool).await?;

    Ok(ApiResponse::json(webhooks, StatusCode::OK))
}

/// Get a webhook
#[utoipa::path(
    get,
    path = "/api/v1/webhook/{id}",
    tag = "webhook",
    params(
        ("id" = i64, Path, description = "ID of the webhook."),
    ),
    responses(
        (status = 200, description = "Webhook details.", body = WebHook),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 404, description = "Webhook not found."),
        (status = 500, description = "Unable to get webhook.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = []),
        ("api_token" = [])
    )
)]
pub async fn get_webhook(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
) -> ApiResult {
    match WebHook::find_by_id(&appstate.pool, id).await? {
        Some(webhook) => Ok(ApiResponse::json(webhook, StatusCode::OK)),
        None => Ok(ApiResponse::with_status(StatusCode::NOT_FOUND)),
    }
}

/// Update a webhook
#[utoipa::path(
    put,
    path = "/api/v1/webhook/{id}",
    tag = "webhook",
    request_body = WebHookData,
    params(
        ("id" = i64, Path, description = "ID of the webhook."),
    ),
    responses(
        (status = 200, description = "Webhook updated."),
        (status = 400, description = "Webhook URL is invalid.", body = ApiErrorResponse),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 404, description = "Webhook not found."),
        (status = 500, description = "Unable to update webhook.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = []),
        ("api_token" = [])
    )
)]
pub async fn change_webhook(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
    Json(data): Json<WebHookData>,
) -> ApiResult {
    validate_webhook_url(&data.url)?;
    debug!("User {} updating webhook {id}", session.user.username);
    let status = match WebHook::find_by_id(&appstate.pool, id).await? {
        Some(mut webhook) => {
            let before = redact_webhook_token(webhook.clone());
            webhook.url = data.url;
            webhook.description = data.description;
            webhook.token = data.token;
            webhook.enabled = data.enabled;
            webhook.on_user_created = data.on_user_created;
            webhook.on_user_deleted = data.on_user_deleted;
            webhook.on_user_modified = data.on_user_modified;
            webhook.on_hwkey_provision = data.on_hwkey_provision;
            webhook.save(&appstate.pool).await?;
            info!("User {} updated webhook {id}", session.user.username);
            appstate.emit_event(ApiEvent {
                context,
                event: Box::new(ApiEventType::WebHookModified {
                    before,
                    after: redact_webhook_token(webhook),
                }),
            })?;
            StatusCode::OK
        }
        None => StatusCode::NOT_FOUND,
    };

    Ok(ApiResponse::with_status(status))
}

/// Delete a webhook
#[utoipa::path(
    delete,
    path = "/api/v1/webhook/{id}",
    tag = "webhook",
    params(
        ("id" = i64, Path, description = "ID of the webhook."),
    ),
    responses(
        (status = 200, description = "Webhook deleted."),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 404, description = "Webhook not found."),
        (status = 500, description = "Unable to delete webhook.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = []),
        ("api_token" = [])
    )
)]
pub async fn delete_webhook(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    session: SessionInfo,
    context: ApiRequestContext,
    Path(id): Path<Id>,
) -> ApiResult {
    debug!("User {} deleting webhook {id}", session.user.username);
    let status = match WebHook::find_by_id(&appstate.pool, id).await? {
        Some(webhook) => {
            webhook.clone().delete(&appstate.pool).await?;
            info!("User {} deleted webhook {id}", session.user.username);
            appstate.emit_event(ApiEvent {
                context,
                event: Box::new(ApiEventType::WebHookRemoved {
                    webhook: redact_webhook_token(webhook),
                }),
            })?;
            StatusCode::OK
        }
        None => StatusCode::NOT_FOUND,
    };
    Ok(ApiResponse::with_status(status))
}

#[derive(Deserialize, ToSchema)]
pub struct ChangeStateData {
    /// New enabled state. Omit when requesting a test delivery.
    pub enabled: Option<bool>,
    /// Send a test event without changing the webhook state.
    #[serde(default)]
    pub test: bool,
}

/// Enable/disable a webhook or send a test event
#[utoipa::path(
    post,
    path = "/api/v1/webhook/{id}",
    tag = "webhook",
    request_body = ChangeStateData,
    params(
        ("id" = i64, Path, description = "ID of the webhook."),
    ),
    responses(
        (status = 200, description = "Webhook state changed or test delivery succeeded."),
        (status = 400, description = "Request must specify exactly one action: `enabled` or `test: true`.", body = ApiErrorResponse),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 404, description = "Webhook not found."),
        (status = 502, description = "Test target returned an error or could not be reached.", body = WebHookTestResponse),
        (status = 500, description = "Unable to process webhook action.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = []),
        ("api_token" = [])
    )
)]
pub async fn change_enabled(
    _admin: AdminRole,
    session: SessionInfo,
    context: ApiRequestContext,
    State(appstate): State<AppState>,
    Path(id): Path<Id>,
    Json(data): Json<ChangeStateData>,
) -> ApiResult {
    if data.test && data.enabled.is_some() {
        return Err(WebError::BadRequest(
            "Webhook action must specify exactly one of enabled or test=true".into(),
        ));
    }

    if data.test {
        return send_test_webhook(&session, &appstate, id).await;
    }

    let Some(enabled) = data.enabled else {
        return Err(WebError::BadRequest(
            "Webhook action must specify exactly one of enabled or test=true".into(),
        ));
    };

    debug!(
        "User {} changing webhook {id} enabled state to {enabled}",
        session.user.username
    );
    let status = match WebHook::find_by_id(&appstate.pool, id).await? {
        Some(mut webhook) => {
            webhook.enabled = enabled;
            webhook.save(&appstate.pool).await?;
            let enabled = webhook.enabled;
            info!(
                "User {} changed webhook {id} enabled state to {enabled}",
                session.user.username
            );
            appstate.emit_event(ApiEvent {
                context,
                event: Box::new(ApiEventType::WebHookStateChanged {
                    enabled,
                    webhook: redact_webhook_token(webhook),
                }),
            })?;
            StatusCode::OK
        }
        None => StatusCode::NOT_FOUND,
    };
    Ok(ApiResponse::with_status(status))
}

#[cfg(test)]
mod tests {
    use super::{ChangeStateData, validate_webhook_url};

    #[test]
    fn accepts_http_and_https_webhook_urls() {
        assert!(validate_webhook_url("https://hooks.example.com/defguard").is_ok());
        assert!(validate_webhook_url("http://127.0.0.1:8080/webhook").is_ok());
        assert!(validate_webhook_url("http://webhook.internal/events").is_ok());
    }

    #[test]
    fn rejects_malformed_webhook_urls() {
        assert!(validate_webhook_url("not a url").is_err());
        assert!(validate_webhook_url("://missing-scheme.example").is_err());
    }

    #[test]
    fn rejects_urls_without_hosts() {
        assert!(validate_webhook_url("http:/webhook").is_err());
    }

    #[test]
    fn rejects_unsupported_webhook_schemes() {
        assert!(validate_webhook_url("ftp://hooks.example.com/defguard").is_err());
        assert!(validate_webhook_url("file:///tmp/webhook").is_err());
    }

    #[test]
    fn rejects_embedded_webhook_credentials() {
        assert!(validate_webhook_url("https://user:pass@hooks.example.com/defguard").is_err());
        assert!(validate_webhook_url("https://user@hooks.example.com/defguard").is_err());
    }

    #[test]
    fn preserves_legacy_enabled_action_payload() {
        let data: ChangeStateData = serde_json::from_value(serde_json::json!({"enabled": true}))
            .expect("legacy enabled payload should deserialize");
        assert_eq!(data.enabled, Some(true));
        assert!(!data.test);
    }

    #[test]
    fn accepts_test_action_payload() {
        let data: ChangeStateData = serde_json::from_value(serde_json::json!({"test": true}))
            .expect("test action payload should deserialize");
        assert_eq!(data.enabled, None);
        assert!(data.test);
    }

    #[test]
    fn ambiguous_action_payload_is_detectable() {
        let data: ChangeStateData = serde_json::from_value(serde_json::json!({
            "enabled": false,
            "test": true
        }))
        .expect("ambiguous payload should still deserialize before validation");
        assert_eq!(data.enabled, Some(false));
        assert!(data.test);
    }
}
