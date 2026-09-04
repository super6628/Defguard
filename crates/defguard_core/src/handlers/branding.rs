use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
};
use defguard_common::db::models::{Settings, WhiteLabelBranding};
use sqlx::PgPool;

use super::{ApiResponse, ApiResult};
use crate::{
    AppState,
    auth::AdminRole,
};

/// Public white-label branding configuration used before authentication.
pub async fn get_branding(Extension(pool): Extension<PgPool>) -> ApiResult {
    let branding = WhiteLabelBranding::get(&pool).await?;
    Ok(ApiResponse::json(branding, StatusCode::OK))
}

/// Replace the complete white-label branding configuration.
pub async fn update_branding(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Json(branding): Json<WhiteLabelBranding>,
) -> ApiResult {
    branding.save(&appstate.pool).await?;

    // Keep Defguard's legacy branding fields synchronized so existing pages,
    // clients and APIs which still consume Settings continue to show the same brand.
    let mut settings = Settings::get_current_settings();
    settings.instance_name = branding.product_name.clone();
    settings.main_logo_url = branding.logo_url.clone();
    settings.nav_logo_url = if branding.nav_logo_url.is_empty() {
        branding.logo_url.clone()
    } else {
        branding.nav_logo_url.clone()
    };
    defguard_common::db::models::settings::update_current_settings(&appstate.pool, settings).await?;

    Ok(ApiResponse::json(branding, StatusCode::OK))
}

/// Reset white-label branding to this fork's deployment defaults.
pub async fn reset_branding(
    _admin: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    let branding = WhiteLabelBranding::default();
    branding.save(&appstate.pool).await?;

    let mut settings = Settings::get_current_settings();
    settings.instance_name = branding.product_name.clone();
    settings.main_logo_url = branding.logo_url.clone();
    settings.nav_logo_url = branding.nav_logo_url.clone();
    defguard_common::db::models::settings::update_current_settings(&appstate.pool, settings).await?;

    Ok(ApiResponse::json(branding, StatusCode::OK))
}
