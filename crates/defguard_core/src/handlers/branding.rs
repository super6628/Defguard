use axum::{Extension, Json, extract::State, http::StatusCode};
use defguard_common::db::models::{Settings, WhiteLabelBranding};
use sqlx::PgPool;

use super::{ApiResponse, ApiResult};
use crate::{AppState, auth::AdminRole, error::WebError};

fn valid_optional_url(value: &str) -> bool {
    value.is_empty()
        || value.starts_with('/')
        || value.starts_with("https://")
        || value.starts_with("http://")
}

fn valid_optional_email(value: &str) -> bool {
    value.is_empty()
        || (!value.contains(char::is_whitespace)
            && value
                .split_once('@')
                .is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.')))
}

fn valid_optional_color(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let Some(hex) = value.strip_prefix('#') else {
        return false;
    };
    matches!(hex.len(), 3 | 4 | 6 | 8) && hex.chars().all(|c| c.is_ascii_hexdigit())
}

fn validate_branding(branding: &WhiteLabelBranding) -> Result<(), WebError> {
    if branding.company_name.trim().is_empty() {
        return Err(WebError::BadRequest("Company name cannot be empty".into()));
    }
    if branding.product_name.trim().is_empty() {
        return Err(WebError::BadRequest("Product name cannot be empty".into()));
    }
    if branding.short_name.trim().is_empty() {
        return Err(WebError::BadRequest("Short name cannot be empty".into()));
    }
    if branding.copyright_name.trim().is_empty() {
        return Err(WebError::BadRequest(
            "Copyright name cannot be empty".into(),
        ));
    }
    if !valid_optional_email(&branding.support_email) {
        return Err(WebError::BadRequest("Support email is invalid".into()));
    }
    for (label, value) in [
        ("Support URL", branding.support_url.as_str()),
        ("Documentation URL", branding.documentation_url.as_str()),
        ("Logo URL", branding.logo_url.as_str()),
        ("Navigation logo URL", branding.nav_logo_url.as_str()),
        ("Dark logo URL", branding.logo_dark_url.as_str()),
        ("Login image URL", branding.login_image_url.as_str()),
        ("Favicon URL", branding.favicon_url.as_str()),
    ] {
        if !valid_optional_url(value) {
            return Err(WebError::BadRequest(format!(
                "{label} must be empty, a root-relative path, or an http(s) URL"
            )));
        }
    }
    if !valid_optional_color(&branding.primary_color) {
        return Err(WebError::BadRequest(
            "Primary color must be an empty value or a CSS hex color".into(),
        ));
    }
    Ok(())
}

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
    validate_branding(&branding)?;

    // Store the new branding row and synchronize legacy Settings atomically.
    let mut transaction = appstate.pool.begin().await?;
    branding.save(&mut *transaction).await?;

    let mut settings = Settings::get_current_settings();
    settings.instance_name = branding.product_name.clone();
    settings.main_logo_url = branding.logo_url.clone();
    settings.nav_logo_url = if branding.nav_logo_url.is_empty() {
        branding.logo_url.clone()
    } else {
        branding.nav_logo_url.clone()
    };
    defguard_common::db::models::settings::update_current_settings(&mut *transaction, settings)
        .await?;
    transaction.commit().await?;

    Ok(ApiResponse::json(branding, StatusCode::OK))
}

/// Reset white-label branding to this fork's deployment defaults.
pub async fn reset_branding(_admin: AdminRole, State(appstate): State<AppState>) -> ApiResult {
    let branding = WhiteLabelBranding::default();

    let mut transaction = appstate.pool.begin().await?;
    branding.save(&mut *transaction).await?;

    let mut settings = Settings::get_current_settings();
    settings.instance_name = branding.product_name.clone();
    settings.main_logo_url = branding.logo_url.clone();
    settings.nav_logo_url = branding.nav_logo_url.clone();
    defguard_common::db::models::settings::update_current_settings(&mut *transaction, settings)
        .await?;
    transaction.commit().await?;

    Ok(ApiResponse::json(branding, StatusCode::OK))
}
