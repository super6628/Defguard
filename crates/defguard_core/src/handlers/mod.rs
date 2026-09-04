use std::net::{IpAddr, SocketAddr};

use axum::{
    Json,
    extract::{ConnectInfo, FromRef, FromRequestParts},
    http::{HeaderName, StatusCode, header::FORWARDED, request::Parts},
    response::{IntoResponse, Response},
};
use axum_client_ip::{RightmostForwarded, RightmostXForwardedFor};
use axum_extra::{TypedHeader, headers::UserAgent};
use defguard_common::{
    config::server_config,
    db::{
        Id, NoId,
        models::{Device, User},
    },
    types::user_info::UserInfo,
};
use defguard_static_ip::error::StaticIpError;
use ipnetwork::IpNetworkError;
use serde_json::{Value, json};
use sqlx::PgPool;
use utoipa::ToSchema;
use webauthn_rs::prelude::RegisterPublicKeyCredential;

use crate::{
    appstate::AppState,
    auth::SessionInfo,
    db::WebHook,
    enterprise::{db::models::acl::AclError, license::LicenseError},
    error::WebError,
    events::ApiRequestContext,
};

pub(crate) mod activity_log;
pub mod app_info;
pub mod auth;
pub mod branding;
pub mod component_setup;
pub mod core_certs;
pub(crate) mod forward_auth;
pub mod gateway;
pub(crate) mod group;
pub mod license;
pub(crate) mod location_stats;
pub mod mail;
pub mod network_devices;
pub mod openid_clients;
pub mod openid_flow;
pub(crate) mod pagination;
pub mod proxy;
pub(crate) mod reserved;
pub mod resource_display;
pub mod session_info;
pub mod settings;
pub(crate) mod ssh_authorized_keys;
pub(crate) mod static_ips;
pub(crate) mod support;
pub(crate) mod updates;
pub mod user;
pub(crate) mod webhooks;
pub mod wireguard;
pub mod worker;
pub(crate) mod yubikey;

/// Machine-readable error code.
///
/// - `network_full`: the location has no free IP address left for another device.
/// - `user_groups_not_synced`: the groups of an externally authenticated user are not synced yet.
/// - `license_limit_reached`: the user limit of the license has been reached.
/// - `cert_missing_cert_pem`: `cert_pem` is missing.
/// - `cert_missing_key_pem`: `key_pem` is missing.
/// - `cert_invalid_cert_or_key`: the certificate or the private key is not valid PEM.
/// - `cert_invalid_validity_period`: the validity period of the certificate cannot be used.
/// - `cert_expired`: the certificate has expired.
/// - `cert_not_yet_valid`: the certificate is not valid yet.
/// - `cert_parse_error`: the certificate could not be parsed.
/// - `smtp_not_configured`: SMTP settings are empty.
/// - `mail_send_failed`: the message could not be sent.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebErrorCode {
    NetworkFull,
    UserGroupsNotSynced,
    LicenseLimitReached,
    CertMissingCertPem,
    CertMissingKeyPem,
    CertInvalidCertOrKey,
    CertInvalidValidityPeriod,
    CertExpired,
    CertNotYetValid,
    CertParseError,
    SmtpNotConfigured,
    MailSendFailed,
}

/// Body returned with error responses.
#[derive(ToSchema)]
pub struct ApiErrorResponse {
    /// Human-readable error message.
    pub msg: String,
    /// Machine-readable error code, returned for selected errors.
    #[schema(value_type = Option<String>)]
    pub code: Option<WebErrorCode>,
}

pub static SESSION_COOKIE_NAME: &str = "defguard_session";
pub(crate) static SIGN_IN_COOKIE_NAME: &str = "defguard_sign_in";
pub(crate) const SIGN_IN_COOKIE_MAX_AGE: time::Duration = time::Duration::minutes(10);

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// Extracts client IP address. It tries "forwarded", then "x-forwarded-for" headers,
/// with a fallback to `ConnectInfo` when these headers are absent.
pub struct ClientIpAddr(pub IpAddr);

impl<S> FromRequestParts<S> for ClientIpAddr
where
    S: Send + Sync,
{
    type Rejection = WebError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ip_addr = if parts.headers.contains_key(FORWARDED) {
            let RightmostForwarded(ip_addr) = RightmostForwarded::from_request_parts(parts, state)
                .await
                .map_err(|_| WebError::ClientIpError)?;
            ip_addr
        } else if parts.headers.contains_key(X_FORWARDED_FOR) {
            let RightmostXForwardedFor(ip_addr) =
                RightmostXForwardedFor::from_request_parts(parts, state)
                    .await
                    .map_err(|_| WebError::ClientIpError)?;
            ip_addr
        } else {
            let ConnectInfo(socket_addr) =
                ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
                    .await
                    .map_err(|_| WebError::ClientIpError)?;
            socket_addr.ip()
        };

        Ok(Self(ip_addr))
    }
}

pub(crate) fn cookie_domain() -> Option<String> {
    server_config().cookie_domain.clone().or_else(|| {
        let settings = defguard_common::db::models::Settings::get_current_settings();
        settings
            .cookie_domain()
            .map_err(|err| {
                warn!("Failed to derive cookie domain: {err}");
            })
            .ok()
    })
}

#[derive(Default)]
pub struct ApiResponse {
    json: Value,
    status: StatusCode,
}

impl ApiResponse {
    /// Build a new [`ApiResponse`].
    #[must_use]
    pub fn new(json: Value, status: StatusCode) -> Self {
        Self { json, status }
    }

    /// Response with `json` set to "{}", and a status code.
    #[must_use]
    pub fn with_status(status: StatusCode) -> Self {
        Self {
            json: Value::Object(serde_json::Map::new()),
            status,
        }
    }

    /// Response with serializable value for JSON, and a status code.
    #[must_use]
    pub fn json<T: serde::Serialize>(value: T, status: StatusCode) -> Self {
        let json = serde_json::to_value(value).expect("Failed to convert value to JSON");
        Self { json, status }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiResponseCode {
    LicenseReactivated,
}

impl From<ApiResponseCode> for ApiResponse {
    fn from(code: ApiResponseCode) -> Self {
        match code {
            ApiResponseCode::LicenseReactivated => Self::new(
                json!({"code": ApiResponseCode::LicenseReactivated}),
                StatusCode::OK,
            ),
        }
    }
}

impl From<WebError> for ApiResponse {
    fn from(web_error: WebError) -> Self {
        match web_error {
            WebError::ObjectNotFound(msg) => Self::new(json!({"msg": msg}), StatusCode::NOT_FOUND),
            WebError::ObjectAlreadyExists(msg) => {
                Self::new(json!({"msg": msg}), StatusCode::CONFLICT)
            }
            WebError::Authorization(msg) => {
                error!(msg);
                Self::new(json!({"msg": msg}), StatusCode::UNAUTHORIZED)
            }
            WebError::Authentication => Self::with_status(StatusCode::UNAUTHORIZED),
            WebError::Forbidden(msg) => {
                error!(msg);
                Self::new(json!({"msg": msg}), StatusCode::FORBIDDEN)
            }
            WebError::DbError(_)
            | WebError::Grpc(_)
            | WebError::WebauthnRegistration(_)
            | WebError::Serialization(_)
            | WebError::ModelError(_)
            | WebError::Email(_)
            | WebError::ClientIpError
            | WebError::FirewallError(_)
            | WebError::ApiEventChannelError(_)
            | WebError::ActivityLogStreamError(_)
            | WebError::UrlParseError(_)
            | WebError::CertificateError(_) => {
                error!("{web_error}");
                Self::new(
                    json!({"msg": "Internal server error"}),
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
            }
            WebError::StaticIpError(err) => match err {
                StaticIpError::InvalidIpAssignment(err) => {
                    Self::new(json!({"msg": err.to_string()}), StatusCode::BAD_REQUEST)
                }
                StaticIpError::NetworkNotFound(_) | StaticIpError::DeviceNotInNetwork(_, _) => {
                    error!("{err}");
                    Self::new(json!({"msg": err.to_string()}), StatusCode::BAD_REQUEST)
                }
                StaticIpError::SqlxError(_) => {
                    error!("{err}");
                    Self::new(
                        json!({"msg": "Internal server error"}),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    )
                }
            },
            WebError::AclError(err) => match err {
                AclError::ParseIntError(_)
                | AclError::IpNetworkError(_)
                | AclError::AddrParseError(_)
                | AclError::InvalidRelationError(_)
                | AclError::InvalidPortsFormat(_) => Self::new(
                    json!({"msg": "Unprocessable entity"}),
                    StatusCode::UNPROCESSABLE_ENTITY,
                ),
                AclError::InvalidIpRangeError(err) => Self::new(
                    json!({"msg": format!("Invalid IP range: {err}")}),
                    StatusCode::UNPROCESSABLE_ENTITY,
                ),
                AclError::RuleNotFoundError(id) => Self::new(
                    json!({"msg": format!("Rule {id} not found")}),
                    StatusCode::NOT_FOUND,
                ),
                AclError::RuleAlreadyAppliedError(id) => Self::new(
                    json!({"msg": format!("Rule {id} already applied")}),
                    StatusCode::BAD_REQUEST,
                ),
                AclError::AliasNotFoundError(id) => Self::new(
                    json!({"msg": format!("Alias {id} not found")}),
                    StatusCode::NOT_FOUND,
                ),
                AclError::DestinationNotFoundError(id) => Self::new(
                    json!({"msg": format!("Destination {id} not found")}),
                    StatusCode::NOT_FOUND,
                ),
                AclError::AliasAlreadyAppliedError(id) => Self::new(
                    json!({"msg": format!("Alias {id} already applied")}),
                    StatusCode::BAD_REQUEST,
                ),
                AclError::DestinationAlreadyAppliedError(id) => Self::new(
                    json!({"msg": format!("Destination {id} already applied")}),
                    StatusCode::BAD_REQUEST,
                ),
                AclError::AliasUsedByRulesError(id) => Self::new(
                    json!({"msg": format!("Alias {id} is used by some existing ACL rules")}),
                    StatusCode::BAD_REQUEST,
                ),
                AclError::DestinationUsedByRulesError(id) => Self::new(
                    json!({"msg": format!("Destination {id} is used by some existing ACL rules")}),
                    StatusCode::BAD_REQUEST,
                ),
                AclError::DbError(_) | AclError::FirewallError(_) => {
                    error!("{err}");
                    Self::new(json!({"msg": "Internal server error"}), StatusCode::INTERNAL_SERVER_ERROR)
                }
                AclError::CannotModifyDeletedRuleError(id) => Self::new(
                    json!({"msg": format!("Cannot modify deleted ACL rule {id}")}),
                    StatusCode::BAD_REQUEST,
                ),
                AclError::CannotUseModifiedAliasInRuleError(alias_ids) => Self::new(
                    json!({"msg": format!("Cannot use modified alias in ACL rule {alias_ids:?}")}),
                    StatusCode::BAD_REQUEST,
                ),
            },
            WebError::Http(status) => Self::new(json!({"msg": status.canonical_reason().unwrap_or_default()}), status),
            WebError::TooManyLoginAttempts(_) => Self::new(json!({"msg": "Too many login attempts"}), StatusCode::TOO_MANY_REQUESTS),
            WebError::PubkeyValidation(msg) | WebError::PubkeyExists(msg) | WebError::BadRequest(msg) => Self::new(json!({"msg": msg}), StatusCode::BAD_REQUEST),
            WebError::NetworkFull(msg) => Self::new(json!({"msg": msg, "code": WebErrorCode::NetworkFull}), StatusCode::BAD_REQUEST),
            WebError::UserGroupsNotSynced(msg) => Self::new(json!({"msg": msg, "code": WebErrorCode::UserGroupsNotSynced}), StatusCode::UNAUTHORIZED),
            WebError::LicenseLimitReached(msg) => Self::new(json!({"msg": msg, "code": WebErrorCode::LicenseLimitReached}), StatusCode::FORBIDDEN),
            WebError::CertMissingCertPem => Self::new(json!({"msg": web_error.to_string(), "code": WebErrorCode::CertMissingCertPem}), StatusCode::BAD_REQUEST),
            WebError::CertMissingKeyPem => Self::new(json!({"msg": web_error.to_string(), "code": WebErrorCode::CertMissingKeyPem}), StatusCode::BAD_REQUEST),
            WebError::CertInvalidCertOrKey => Self::new(json!({"msg": web_error.to_string(), "code": WebErrorCode::CertInvalidCertOrKey}), StatusCode::BAD_REQUEST),
            WebError::CertInvalidValidityPeriod => Self::new(json!({"msg": web_error.to_string(), "code": WebErrorCode::CertInvalidValidityPeriod}), StatusCode::BAD_REQUEST),
            WebError::CertExpired => Self::new(json!({"msg": web_error.to_string(), "code": WebErrorCode::CertExpired}), StatusCode::BAD_REQUEST),
            WebError::CertNotYetValid => Self::new(json!({"msg": web_error.to_string(), "code": WebErrorCode::CertNotYetValid}), StatusCode::BAD_REQUEST),
            WebError::CertParseError(msg) => Self::new(json!({"msg": msg, "code": WebErrorCode::CertParseError}), StatusCode::BAD_REQUEST),
            WebError::SmtpNotConfigured => Self::new(json!({"msg": web_error.to_string(), "code": WebErrorCode::SmtpNotConfigured}), StatusCode::SERVICE_UNAVAILABLE),
            WebError::MailSendFailed => Self::new(json!({"msg": web_error.to_string(), "code": WebErrorCode::MailSendFailed}), StatusCode::SERVICE_UNAVAILABLE),
            WebError::TemplateError(err) => {
                error!("Template error: {err}");
                Self::new(json!({"msg": "Internal server error"}), StatusCode::INTERNAL_SERVER_ERROR)
            }
            WebError::LicenseError(err) => match err {
                LicenseError::DecodeError(msg) => Self::new(json!({"msg": msg}), StatusCode::BAD_REQUEST),
                LicenseError::SignatureMismatch => Self::new(json!({"msg": "License signature doesn't match its content"}), StatusCode::BAD_REQUEST),
                LicenseError::InvalidSignature => Self::new(json!({"msg": "License signature is malformed and couldn't be read"}), StatusCode::BAD_REQUEST),
                LicenseError::LicenseNotFound => Self::new(json!({"msg": "License not found"}), StatusCode::NOT_FOUND),
                LicenseError::LicenseExpired => Self::new(json!({"msg": "License expired"}), StatusCode::FORBIDDEN),
                LicenseError::LicenseNotYetValid => Self::new(json!({"msg": "License not yet valid"}), StatusCode::FORBIDDEN),
                LicenseError::DbError(_) => Self::new(json!({"msg": "Internal server error"}), StatusCode::INTERNAL_SERVER_ERROR),
            },
        }
    }
}

impl IntoResponse for ApiResponse {
    fn into_response(self) -> Response {
        (self.status, Json(self.json)).into_response()
    }
}

pub type ApiResult = Result<ApiResponse, WebError>;

impl FromRef<AppState> for PgPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}
