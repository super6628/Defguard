use axum::{Json, extract::{Path, State}, http::StatusCode};
use axum_extra::{TypedHeader, extract::{CookieJar, PrivateCookieJar, cookie::{Cookie, SameSite}}, headers::UserAgent};
use defguard_common::{
    config::server_config,
    db::{Id, models::{MFAInfo, Settings, User, settings::{OpenIdUsernameHandling, update_current_settings}}},
};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::Duration;
use utoipa::ToSchema;

use crate::{
    appstate::AppState,
    auth::{AdminRole, SessionInfo},
    enterprise::db::models::openid_provider::{
        DirectorySyncTarget, DirectorySyncUserBehavior, OpenIdProvider, OpenIdProviderKind,
    },
    error::WebError,
    handlers::{
        ApiResponse, ApiResult, AuthResponse, ClientIpAddr, SESSION_COOKIE_NAME,
        SIGN_IN_COOKIE_NAME, cookie_domain,
        auth::create_session,
        user::check_username,
    },
};

const OIDC_STATE_COOKIE: &str = "smetric_oidc_state";
const OIDC_NONCE_COOKIE: &str = "smetric_oidc_nonce";
const OIDC_PKCE_COOKIE: &str = "smetric_oidc_pkce";
const OIDC_COOKIE_MAX_AGE: Duration = Duration::minutes(10);
const MICROSOFT_HOST: &str = "login.microsoftonline.com";

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct AddProviderData {
    pub name: String,
    pub base_url: String,
    pub kind: OpenIdProviderKind,
    pub client_id: String,
    pub client_secret: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub create_account: bool,
    pub username_handling: OpenIdUsernameHandling,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub disable_password_management: bool,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationResponse {
    pub code: AuthorizationCode,
    pub state: CsrfToken,
}

fn microsoft_issuer(input: &AddProviderData) -> Result<String, WebError> {
    if let Some(tenant) = input.tenant_id.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        let lower = tenant.to_ascii_lowercase();
        if matches!(lower.as_str(), "common" | "organizations" | "consumers") {
            return Err(WebError::BadRequest(
                "Use a tenant-specific Microsoft Entra tenant ID for S-Metric Secure".into(),
            ));
        }
        return Ok(format!("https://{MICROSOFT_HOST}/{tenant}/v2.0"));
    }

    let url = Url::parse(input.base_url.trim())
        .map_err(|_| WebError::BadRequest("Invalid Microsoft issuer URL".into()))?;
    if url.scheme() != "https" || url.host_str() != Some(MICROSOFT_HOST) {
        return Err(WebError::BadRequest(
            "Microsoft issuer must use https://login.microsoftonline.com/<tenant-id>/v2.0".into(),
        ));
    }
    let parts: Vec<_> = url.path_segments().map(|p| p.collect()).unwrap_or_default();
    if parts.len() != 2 || parts[1] != "v2.0" || parts[0].is_empty() {
        return Err(WebError::BadRequest(
            "Microsoft issuer must use https://login.microsoftonline.com/<tenant-id>/v2.0".into(),
        ));
    }
    let tenant = parts[0].to_ascii_lowercase();
    if matches!(tenant.as_str(), "common" | "organizations" | "consumers") {
        return Err(WebError::BadRequest(
            "Use a tenant-specific Microsoft Entra tenant ID for S-Metric Secure".into(),
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn provider_for_response(mut provider: OpenIdProvider<Id>) -> OpenIdProvider<Id> {
    provider.client_secret.clear();
    provider.google_service_account_key = None;
    provider.okta_private_jwk = None;
    provider
}

fn provider_from_input(
    data: &AddProviderData,
    issuer: String,
    client_secret: String,
) -> OpenIdProvider {
    OpenIdProvider::new(
        data.name.clone(),
        issuer,
        OpenIdProviderKind::Microsoft,
        data.client_id.clone(),
        client_secret,
        data.display_name.clone().or_else(|| Some("Sign in with Microsoft".into())),
        None,
        None,
        None,
        false,
        3600,
        DirectorySyncUserBehavior::Keep,
        DirectorySyncUserBehavior::Keep,
        DirectorySyncTarget::Users,
        None,
        None,
        Vec::new(),
        None,
        false,
        data.disable_password_management,
        None,
    )
}

async fn save_core_settings(pool: &sqlx::PgPool, data: &AddProviderData) -> Result<(), WebError> {
    let mut settings = Settings::get_current_settings();
    settings.openid_create_account = data.create_account;
    settings.openid_username_handling = data.username_handling;
    update_current_settings(pool, settings).await?;
    Ok(())
}

pub(crate) async fn add_openid_provider(
    _admin: AdminRole,
    _session: SessionInfo,
    State(appstate): State<AppState>,
    Json(data): Json<AddProviderData>,
) -> ApiResult {
    if data.kind != OpenIdProviderKind::Microsoft {
        return Err(WebError::BadRequest(
            "S-Metric Secure currently supports Microsoft 365 / Entra ID for external OIDC authentication".into(),
        ));
    }
    if data.client_id.trim().is_empty() || data.client_secret.trim().is_empty() {
        return Err(WebError::BadRequest("Microsoft client ID and client secret are required".into()));
    }
    let issuer = microsoft_issuer(&data)?;
    save_core_settings(&appstate.pool, &data).await?;
    provider_from_input(&data, issuer, data.client_secret.clone())
        .upsert(&appstate.pool)
        .await?;
    Ok(ApiResponse::with_status(StatusCode::CREATED))
}

pub(crate) async fn modify_openid_provider(
    _admin: AdminRole,
    _session: SessionInfo,
    State(appstate): State<AppState>,
    Json(data): Json<AddProviderData>,
) -> ApiResult {
    if data.kind != OpenIdProviderKind::Microsoft {
        return Err(WebError::BadRequest("Only Microsoft 365 / Entra ID is supported by this OIDC implementation".into()));
    }
    let issuer = microsoft_issuer(&data)?;
    let existing = OpenIdProvider::get_current(&appstate.pool)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound("Microsoft OIDC provider is not configured".into()))?;
    let secret = if data.client_secret.trim().is_empty() {
        existing.client_secret
    } else {
        data.client_secret.clone()
    };
    if data.client_id.trim().is_empty() || secret.trim().is_empty() {
        return Err(WebError::BadRequest("Microsoft client ID and client secret are required".into()));
    }
    save_core_settings(&appstate.pool, &data).await?;
    provider_from_input(&data, issuer, secret)
        .upsert(&appstate.pool)
        .await?;
    Ok(ApiResponse::with_status(StatusCode::OK))
}

pub(crate) async fn get_openid_provider(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult {
    let settings = Settings::get_current_settings();
    let provider = OpenIdProvider::find_by_name(&appstate.pool, &name).await?;
    let provider = provider.filter(|p| p.kind == OpenIdProviderKind::Microsoft).map(provider_for_response);
    Ok(ApiResponse::json(
        json!({
            "provider": provider,
            "settings": {
                "create_account": settings.openid_create_account,
                "username_handling": settings.openid_username_handling,
            }
        }),
        if provider.is_some() { StatusCode::OK } else { StatusCode::NO_CONTENT },
    ))
}

pub(crate) async fn get_current_openid_provider(
    _admin: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    let settings = Settings::get_current_settings();
    let provider = OpenIdProvider::get_current(&appstate.pool)
        .await?
        .filter(|p| p.kind == OpenIdProviderKind::Microsoft)
        .map(provider_for_response);
    let status = if provider.is_some() { StatusCode::OK } else { StatusCode::NO_CONTENT };
    Ok(ApiResponse::json(
        json!({
            "provider": provider,
            "settings": {
                "create_account": settings.openid_create_account,
                "username_handling": settings.openid_username_handling,
            }
        }),
        status,
    ))
}

pub(crate) async fn list_openid_providers(
    _admin: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    let provider = OpenIdProvider::get_current(&appstate.pool)
        .await?
        .filter(|p| p.kind == OpenIdProviderKind::Microsoft)
        .map(provider_for_response);
    let providers: Vec<_> = provider.into_iter().collect();
    Ok(ApiResponse::json(providers, StatusCode::OK))
}

pub(crate) async fn delete_openid_provider(
    _admin: AdminRole,
    _session: SessionInfo,
    State(appstate): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult {
    let Some(provider) = OpenIdProvider::find_by_name(&appstate.pool, &name).await? else {
        return Ok(ApiResponse::with_status(StatusCode::NOT_FOUND));
    };
    if provider.kind != OpenIdProviderKind::Microsoft {
        return Err(WebError::BadRequest("Configured provider is not a Microsoft provider".into()));
    }
    provider.delete(&appstate.pool).await?;
    Ok(ApiResponse::with_status(StatusCode::OK))
}

pub(crate) async fn test_dirsync_connection(
    _admin: AdminRole,
    _session: SessionInfo,
    State(_appstate): State<AppState>,
) -> ApiResult {
    Ok(ApiResponse::json(
        json!({
            "success": false,
            "message": "Microsoft OIDC authentication is enabled independently of directory synchronization. Microsoft Graph synchronization is not configured in this implementation."
        }),
        StatusCode::OK,
    ))
}

fn http_client() -> Result<reqwest::Client, WebError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| WebError::Http(StatusCode::INTERNAL_SERVER_ERROR))
}

async fn oidc_client(
    provider: &OpenIdProvider<Id>,
    redirect_url: Url,
) -> Result<(
    ClientId,
    CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>,
), WebError> {
    if provider.kind != OpenIdProviderKind::Microsoft {
        return Err(WebError::Authorization("Configured external provider is not Microsoft 365".into()));
    }
    let issuer = IssuerUrl::new(provider.base_url.clone())
        .map_err(|_| WebError::BadRequest("Invalid Microsoft issuer URL".into()))?;
    let client = http_client()?;
    let metadata = CoreProviderMetadata::discover_async(issuer, &client)
        .await
        .map_err(|_| WebError::Authorization("Unable to discover Microsoft OpenID configuration".into()))?;
    let client_id = ClientId::new(provider.client_id.clone());
    let oidc = CoreClient::from_provider_metadata(
        metadata,
        client_id.clone(),
        Some(ClientSecret::new(provider.client_secret.clone())),
    )
    .set_redirect_uri(RedirectUrl::from_url(redirect_url));
    Ok((client_id, oidc))
}

fn private_cookie(name: &'static str, value: String, secure: bool) -> Cookie<'static> {
    let mut cookie = Cookie::build((name, value))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(OIDC_COOKIE_MAX_AGE);
    if let Some(domain) = cookie_domain() {
        cookie = cookie.domain(domain);
    }
    cookie.build()
}

pub async fn get_auth_info(
    mut private_cookies: PrivateCookieJar,
    State(appstate): State<AppState>,
) -> Result<(PrivateCookieJar, ApiResponse), WebError> {
    let provider = OpenIdProvider::get_current(&appstate.pool)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound("Microsoft OIDC provider is not configured".into()))?;
    if provider.kind != OpenIdProviderKind::Microsoft {
        return Err(WebError::ObjectNotFound("Microsoft OIDC provider is not configured".into()));
    }

    let settings = Settings::get_current_settings();
    let (_, client) = oidc_client(&provider, settings.callback_url()?).await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state, nonce) = client
        .authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .set_pkce_challenge(challenge)
        .add_scope(Scope::new("profile".into()))
        .add_scope(Scope::new("email".into()))
        .url();

    let config = server_config();
    let secure = config.cookie_insecure.map_or(settings.cookie_secure()?, |insecure| !insecure);
    private_cookies = private_cookies
        .add(private_cookie(OIDC_STATE_COOKIE, state.secret().clone(), secure))
        .add(private_cookie(OIDC_NONCE_COOKIE, nonce.secret().clone(), secure))
        .add(private_cookie(OIDC_PKCE_COOKIE, verifier.secret().clone(), secure));

    Ok((
        private_cookies,
        ApiResponse::json(
            json!({
                "url": url,
                "button_display_name": provider.display_name.or_else(|| Some("Sign in with Microsoft".into()))
            }),
            StatusCode::OK,
        ),
    ))
}

fn normalized_username(source: &str, handling: OpenIdUsernameHandling) -> String {
    let local = source.split('@').next().unwrap_or(source);
    let mut value = local.trim_start_matches(|c: char| !c.is_ascii_alphanumeric()).to_owned();
    let valid = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_');
    match handling {
        OpenIdUsernameHandling::RemoveForbidden => value.retain(valid),
        OpenIdUsernameHandling::ReplaceForbidden | OpenIdUsernameHandling::PruneEmailDomain => {
            value = value.chars().map(|c| if valid(c) { c } else { '_' }).collect();
        }
    }
    value.truncate(64);
    value
}

async fn resolve_user(
    pool: &sqlx::PgPool,
    sub: &str,
    email: &str,
    preferred_username: Option<&str>,
    given_name: Option<&str>,
    family_name: Option<&str>,
) -> Result<User<Id>, WebError> {
    if let Some(user) = User::find_by_sub(pool, sub).await? {
        if !user.is_active {
            return Err(WebError::Authorization("User is disabled".into()));
        }
        return Ok(user);
    }

    if let Some(mut user) = User::find_by_email(pool, email).await? {
        if !user.is_active {
            return Err(WebError::Authorization("User is disabled".into()));
        }
        user.openid_sub = Some(sub.to_owned());
        return Ok(user.save(pool).await?);
    }

    let settings = Settings::get_current_settings();
    if !settings.openid_create_account {
        return Err(WebError::Authorization(
            "No local account matches this Microsoft identity and automatic account creation is disabled".into(),
        ));
    }

    let source = preferred_username.unwrap_or(email);
    let username = normalized_username(source, settings.openid_username_handling);
    check_username(&username)?;
    if User::find_by_username(pool, &username).await?.is_some() {
        return Err(WebError::Authorization(format!("Username {username} already exists")));
    }

    let mut user = User::new(
        username,
        None,
        family_name.unwrap_or("").to_owned(),
        given_name.unwrap_or(source.split('@').next().unwrap_or(source)).to_owned(),
        email.to_owned(),
        None,
    );
    user.openid_sub = Some(sub.to_owned());
    Ok(user.save(pool).await?)
}

pub async fn auth_callback(
    cookies: CookieJar,
    mut private_cookies: PrivateCookieJar,
    user_agent: TypedHeader<UserAgent>,
    ClientIpAddr(ip_addr): ClientIpAddr,
    State(appstate): State<AppState>,
    Json(payload): Json<AuthenticationResponse>,
) -> Result<(CookieJar, PrivateCookieJar, ApiResponse), WebError> {
    let expected_state = private_cookies
        .get(OIDC_STATE_COOKIE)
        .ok_or_else(|| WebError::Authorization("OIDC state cookie is missing".into()))?
        .value()
        .to_owned();
    if payload.state.secret() != &expected_state {
        return Err(WebError::Authorization("OIDC state validation failed".into()));
    }
    let nonce = private_cookies
        .get(OIDC_NONCE_COOKIE)
        .ok_or_else(|| WebError::Authorization("OIDC nonce cookie is missing".into()))?
        .value()
        .to_owned();
    let pkce = private_cookies
        .get(OIDC_PKCE_COOKIE)
        .ok_or_else(|| WebError::Authorization("OIDC PKCE verifier cookie is missing".into()))?
        .value()
        .to_owned();

    private_cookies = private_cookies
        .remove(Cookie::from(OIDC_STATE_COOKIE))
        .remove(Cookie::from(OIDC_NONCE_COOKIE))
        .remove(Cookie::from(OIDC_PKCE_COOKIE));

    let provider = OpenIdProvider::get_current(&appstate.pool)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound("Microsoft OIDC provider is not configured".into()))?;
    let settings = Settings::get_current_settings();
    let (client_id, client) = oidc_client(&provider, settings.callback_url()?).await?;
    let http = http_client()?;
    let token = client
        .exchange_code(payload.code)
        .map_err(|_| WebError::Authorization("Microsoft authorization code was rejected".into()))?
        .set_pkce_verifier(PkceCodeVerifier::new(pkce))
        .request_async(&http)
        .await
        .map_err(|_| WebError::Authorization("Failed to exchange Microsoft authorization code".into()))?;
    let id_token = token
        .extra_fields()
        .id_token()
        .ok_or_else(|| WebError::Authorization("Microsoft did not return an ID token".into()))?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(nonce))
        .map_err(|_| WebError::Authorization("Microsoft ID token validation failed".into()))?;
    if !claims.audiences().iter().any(|aud| aud.as_str() == client_id.as_str()) {
        return Err(WebError::Authorization("Microsoft ID token audience does not match this application".into()));
    }

    let preferred = claims.preferred_username().map(|v| v.as_str().to_owned());
    let email = claims
        .email()
        .map(|v| v.as_str().to_owned())
        .or_else(|| preferred.clone())
        .ok_or_else(|| WebError::Authorization("Microsoft identity did not include an email or preferred username".into()))?;
    let given = claims.given_name().and_then(|v| v.get(None)).map(|v| v.as_str().to_owned());
    let family = claims.family_name().and_then(|v| v.get(None)).map(|v| v.as_str().to_owned());
    let sub = claims.subject().as_str().to_owned();

    let mut user = resolve_user(
        &appstate.pool,
        &sub,
        &email,
        preferred.as_deref(),
        given.as_deref(),
        family.as_deref(),
    )
    .await?;

    let (session, user_info, mfa_info) = create_session(
        &appstate.pool,
        ip_addr,
        user_agent.as_str(),
        &mut user,
    )
    .await?;

    let timeout = Settings::get_current_settings().authentication_timeout();
    let max_age = Duration::try_from(timeout)
        .map_err(|_| WebError::Http(StatusCode::INTERNAL_SERVER_ERROR))?;
    let config = server_config();
    let secure = config.cookie_insecure.map_or(settings.cookie_secure()?, |insecure| !insecure);
    let mut session_cookie = Cookie::build((SESSION_COOKIE_NAME, session.id))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(secure)
        .max_age(max_age);
    if let Some(domain) = cookie_domain() {
        session_cookie = session_cookie.domain(domain);
    }
    let cookies = cookies.add(session_cookie);

    if let Some(mfa) = mfa_info {
        return Ok((cookies, private_cookies, ApiResponse::json(mfa, StatusCode::CREATED)));
    }

    let user_info = user_info.ok_or_else(|| WebError::Http(StatusCode::INTERNAL_SERVER_ERROR))?;
    let url = private_cookies.get(SIGN_IN_COOKIE_NAME).map(|c| c.value().to_owned());
    if private_cookies.get(SIGN_IN_COOKIE_NAME).is_some() {
        private_cookies = private_cookies.remove(Cookie::from(SIGN_IN_COOKIE_NAME));
    }

    Ok((
        cookies,
        private_cookies,
        ApiResponse::json(AuthResponse { user: user_info, url }, StatusCode::OK),
    ))
}
