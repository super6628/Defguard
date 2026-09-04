pub mod acl;
pub mod activity_log_stream;
pub mod api_tokens;
pub mod device_posture;
pub mod enterprise_settings;
pub mod smetric_microsoft_oidc;

// Keep the upstream modules compiled under compatibility names because internal
// directory-sync, proxy-manager, setup, and desktop-MFA code still consumes helper
// functions from them. The public compatibility modules below expose our independent
// S-Metric login/provider handlers while forwarding non-router helpers to upstream.
#[path = "openid_login.rs"]
pub mod upstream_openid_login;
#[path = "openid_providers.rs"]
pub mod upstream_openid_providers;

pub mod openid_login {
    pub use super::smetric_microsoft_oidc::{auth_callback, get_auth_info};
    pub use super::upstream_openid_login::{
        SELECT_ACCOUNT_SUPPORTED_PROVIDERS, __path_auth_callback, __path_get_auth_info,
        build_state, make_oidc_client, prune_username, user_from_claims,
    };
    pub(crate) use super::upstream_openid_login::extract_state_data;
}

pub mod openid_providers {
    pub use super::smetric_microsoft_oidc::{
        add_openid_provider, delete_openid_provider, get_current_openid_provider,
        get_openid_provider, list_openid_providers, modify_openid_provider,
        test_dirsync_connection,
    };

    // Preserve generated OpenAPI path descriptors expected by openapi.rs.
    pub use super::upstream_openid_providers::{
        __path_add_openid_provider, __path_delete_openid_provider,
        __path_get_current_openid_provider, __path_get_openid_provider,
        __path_list_openid_providers, __path_modify_openid_provider,
        __path_test_dirsync_connection,
    };
}

use std::marker::PhantomData;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
};
use serde::Serialize;

use super::{
    LicenseFeature,
    db::models::enterprise_settings::EnterpriseSettings,
    effective_features, get_counts, has_enterprise_access, is_business_license_active,
    license::{LicenseTier, get_cached_license, validate_license},
};
use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    error::WebError,
    handlers::{ApiErrorResponse, ApiResponse, ApiResult},
};

pub struct LicenseInfo {
    pub valid: bool,
}

/// Used to check if user is allowed to manage his devices.
pub struct CanManageDevices;

#[derive(Serialize)]
struct LimitInfo {
    current: u32,
    limit: u32,
}

#[derive(Serialize)]
struct LicenseLimitsInfo {
    // Retained for API compatibility. S-Metric Secure reports the real active-user count but
    // exposes no licensed user ceiling; `limit` is u32::MAX rather than an enforcement value.
    users: LimitInfo,
    locations: LimitInfo,
    user_devices: Option<LimitInfo>,
    network_devices: Option<LimitInfo>,
    devices: Option<LimitInfo>,
}

impl<S> FromRequestParts<S> for LicenseInfo
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = WebError;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if is_business_license_active() {
            Ok(Self { valid: true })
        } else {
            Err(WebError::Forbidden("Enterprise features are disabled"))
        }
    }
}

/// Marker type tying an extractor to a single enterprise feature flag.
pub trait EnterpriseFeature {
    const FEATURE: LicenseFeature;
}

/// Marker for the device posture feature.
pub struct DevicePostureFeature;

impl EnterpriseFeature for DevicePostureFeature {
    const FEATURE: LicenseFeature = LicenseFeature::DevicePosture;
}

/// Extractor that rejects with 403 unless the enterprise feature `F` is active for the current
/// license (either Enterprise tier or granted via an additive feature flag).
pub struct LicenseGated<F: EnterpriseFeature>(PhantomData<F>);

impl<S, F> FromRequestParts<S> for LicenseGated<F>
where
    S: Send + Sync,
    AppState: FromRef<S>,
    F: EnterpriseFeature,
{
    type Rejection = WebError;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if has_enterprise_access(Some(F::FEATURE)) {
            Ok(Self(PhantomData))
        } else {
            Err(WebError::Forbidden("Enterprise features are disabled"))
        }
    }
}

/// Get information about the enterprise license and enabled features
#[utoipa::path(
    get,
    path = "/api/v1/enterprise_info",
    tag = "license",
    responses(
        (status = 200, description = "License information and effective enterprise features.", body = Object, example = json!({
            "license_info": {
                "valid_until": "2027-01-01T00:00:00Z",
                "subscription": true,
                "expired": false,
                "limits_exceeded": false,
                "tier": "Enterprise",
                "support_type": "DirectEnterprise",
                "limits": {
                    "users": {"current": 12, "limit": 4294967295},
                    "locations": {"current": 2, "limit": 10},
                    "user_devices": null,
                    "network_devices": null,
                    "devices": {"current": 30, "limit": 500}
                },
                "features": ["DevicePosture"],
                "customer_id": "cus_00000000"
            }
        })),
        (status = 401, description = "Session is missing or invalid.", body = ApiErrorResponse, example = json!({"msg": "Session is required"})),
        (status = 403, description = "Requires admin privileges.", body = ApiErrorResponse, example = json!({"msg": "requires privileged access"})),
        (status = 500, description = "Unable to get license information.", body = ApiErrorResponse, example = json!({"msg": "Internal server error"})),
    ),
    security(
        ("cookie" = []),
        ("api_token" = [])
    )
)]
pub async fn check_enterprise_info(_admin: AdminRole, _session: SessionInfo) -> ApiResult {
    let license = get_cached_license();
    let license_info = license.as_ref().map(|license| {
        let counts = get_counts();
        let limits_info = license.limits.map(|limits| LicenseLimitsInfo {
            locations: LimitInfo {
                current: counts.location(),
                limit: limits.locations,
            },
            users: LimitInfo {
                current: counts.actual_user(),
                limit: u32::MAX,
            },
            devices: limits.network_devices.map_or(
                Some(LimitInfo {
                    current: counts.user_device() + counts.network_device(),
                    limit: limits.devices,
                }),
                |_| None,
            ),
            user_devices: limits.network_devices.map(|_| LimitInfo {
                current: counts.user_device(),
                limit: limits.devices,
            }),
            network_devices: limits
                .network_devices
                .map(|network_devices_limit| LimitInfo {
                    current: counts.network_device(),
                    limit: network_devices_limit,
                }),
        });

        let valid = validate_license(Some(license), &counts, LicenseTier::Business).is_ok();
        let features = if valid {
            effective_features(license)
        } else {
            Vec::new()
        };

        serde_json::json!({
            "valid_until": license.valid_until,
            "subscription": license.subscription,
            "expired": license.is_max_overdue(),
            "limits_exceeded": counts.is_over_license_limits(license),
            "tier": license.tier,
            "support_type": license.support_type,
            "limits": limits_info,
            "features": features,
            "customer_id": license.customer_id,
        })
    });
    Ok(ApiResponse::json(
        serde_json::json!({"license_info": license_info}),
        StatusCode::OK,
    ))
}

impl<S> FromRequestParts<S> for CanManageDevices
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = WebError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let appstate = AppState::from_ref(state);
        let session = SessionInfo::from_request_parts(parts, state).await?;
        let settings = EnterpriseSettings::get(&appstate.pool).await?;
        if settings.admin_device_management && !session.is_admin {
            Err(WebError::Forbidden("Only admin users can manage devices"))
        } else {
            Ok(Self)
        }
    }
}
