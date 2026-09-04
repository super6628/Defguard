use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use axum_extra::{
    TypedHeader,
    extract::{
        CookieJar, PrivateCookieJar,
        cookie::{Cookie, SameSite},
    },
    headers::UserAgent,
};
use defguard_common::{
    config::server_config,
    db::models::{Settings, User, settings::OpenIdUsernameHandling},
};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
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
    enterprise::db::models::smetric_oidc_provider::SMetricOidcProvider,
    error::WebError,
    handlers::{
        ApiResponse, ApiResult, AuthResponse, ClientIpAddr, SESSION_COOKIE_NAME,
        SIGN_IN_COOKIE_NAME,
        auth::create_session,
        cookie_domain,
        user::check_username,
    },
};

const OIDC_STATE_COOKIE: &str = "smetric_oidc_state";
const OIDC_NONCE_COOKIE: &str = "smetric_oidc_nonce";
const OIDC_PKCE_COOKIE: &str = "smetric_oidc_pkce";
const OIDC_PROVIDER_COOKIE: &str = "smetric_oidc_provider";
const OIDC_COOKIE_MAX_AGE: Duration = Duration::minutes(10);
const MICROSOFT_HOST: &str = "login.microsoftonline.com";

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct AddProviderData {
    pub name: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub base_url: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    pub display_name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub create_account: bool,
    #[serde(default)]
    pub username_handling: OpenIdUsernameHandling,
    #[serde(default)]
    pub disable_password_management: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationResponse {
    pub code: AuthorizationCode,
    pub state: CsrfToken,
}

#[derive(Debug, Default, Deserialize)]
pub struct AuthInfoQuery {
    pub provider_id: Option<i64>,
    pub provider: Option<String>,
}

#[derive(Serialize)]
struct PublicProvider {
    id: i64,
    name: String,
    display_name: String,
    is_default: bool,
}

fn username_handling_to_db(value: OpenIdUsernameHandling) -> &'static str {
    match value {
        OpenIdUsernameHandling::RemoveForbidden => "remove_forbidden",
        OpenIdUsernameHandling::ReplaceForbidden => "replace_forbidden",
        OpenIdUsernameHandling::PruneEmailDomain => "prune_email_domain",
    }
}

fn username_handling_from_db(value: &str) -> OpenIdUsernameHandling {
    match value {
        "replace_forbidden" => OpenIdUsernameHandling::ReplaceForbidden,
        "prune_email_domain" => OpenIdUsernameHandling::PruneEmailDomain,
        _ => OpenIdUsernameHandling::RemoveForbidden,
    }
}

fn normalize_tenant(tenant: &str) -> Result<String, WebError> {
    let tenant = tenant.trim();
    if tenant.is_empty() {
        return Err(WebError::BadRequest("Microsoft tenant ID is required".into()));
    }
    let lower = tenant.to_ascii_lowercase();
    if matches!(lower.as_str(), "common" | "organizations" | "consumers") {
        return Err(WebError::BadRequest(
            "Use a tenant-specific Microsoft Entra tenant ID for S-Metric Secure".into(),
        ));
    }
    Ok(tenant.to_owned())
}

fn microsoft_issuer(tenant_id: &str, base_url: &str) -> Result<String, WebError> {
    let tenant = normalize_tenant(tenant_id)?;
    if base_url.trim().is_empty() {
        return Ok(format!("https://{MICROSOFT_HOST}/{tenant}/v2.0"));
    }

    let url = Url::parse(base_url.trim())
        .map_err(|_| WebError::BadRequest("Invalid Microsoft issuer URL".into()))?;
    if url.scheme() != "https" || url.host_str() != Some(MICROSOFT_HOST) {
        return Err(WebError::BadRequest(
            "Microsoft issuer must use https://login.microsoftonline.com/<tenant-id>/v2.0".into(),
        ));
    }
    let parts: Vec<_> = url.path_segments().map(|p| p.collect()).unwrap_or_default();
    if parts.len() != 2 || parts[1] != "v2.0" || !parts[0].eq_ignore_ascii_case(&tenant) {
        return Err(WebError::BadRequest(
            "Microsoft issuer tenant must match the configured tenant ID".into(),
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn normalize_domains(domains: &[String]) -> Result<Vec<String>, WebError> {
    let mut result = Vec::new();
    for domain in domains {
        let normalized = domain.trim().trim_start_matches('@').to_ascii_lowercase();
        if normalized.is_empty()
            || normalized.contains('/')
            || normalized.contains(':')
            || normalized.contains(' ')
        {
            return Err(WebError::BadRequest(format!("Invalid allowed email domain: {domain}")));
        }
        if !result.contains(&normalized) {
            result.push(normalized);
        }
    }
    Ok(result)
}

fn provider_json(provider: &SMetricOidcProvider) -> serde_json::Value {
    json!({
        "id": provider.id,
        "name": provider.name,
        "tenant_id": provider.tenant_id,
        "base_url": provider.issuer,
        "client_id": provider.client_id,
        "client_secret": "",
        "display_name": provider.display_name,
        "enabled": provider.enabled,
        "is_default": provider.is_default,
        "allowed_domains": provider.allowed_domains,
        "create_account": provider.auto_create,
        "username_handling": username_handling_from_db(&provider.username_handling),
        "disable_password_management": provider.disable_password_management,
    })
}

fn public_provider(provider: SMetricOidcProvider) -> PublicProvider {
    PublicProvider {
        id: provider.id,
        display_name: provider
            .display_name
            .clone()
            .unwrap_or_else(|| "Sign in with Microsoft".to_owned()),
        name: provider.name,
        is_default: provider.is_default,
    }
}

pub async fn add_openid_provider(
    _admin: AdminRole,
    _session: SessionInfo,
    State(appstate): State<AppState>,
    Json(data): Json<AddProviderData>,
) -> ApiResult {
    if data.name.trim().is_empty() {
        return Err(WebError::BadRequest("Provider name is required".into()));
    }
    if data.client_id.trim().is_empty() || data.client_secret.trim().is_empty() {
        return Err(WebError::BadRequest("Microsoft client ID and client secret are required".into()));
    }

    let tenant_id = normalize_tenant(&data.tenant_id)?;
    let issuer = microsoft_issuer(&tenant_id, &data.base_url)?;
    let allowed_domains = normalize_domains(&data.allowed_domains)?;
    let provider = SMetricOidcProvider::create(
        &appstate.pool,
        data.name.trim(),
        &tenant_id,
        &issuer,
        data.client_id.trim(),
        data.client_secret.trim(),
        data.display_name.as_deref(),
        data.enabled,
        data.is_default,
        &allowed_domains,
        data.create_account,
        username_handling_to_db(data.username_handling),
        data.disable_password_management,
    )
    .await?;

    Ok(ApiResponse::json(provider_json(&provider), StatusCode::CREATED))
}

pub async fn modify_openid_provider(
    _admin: AdminRole,
    _session: SessionInfo,
    State(appstate): State<AppState>,
    Path(name): Path<String>,
    Json(data): Json<AddProviderData>,
) -> ApiResult {
    let existing = SMetricOidcProvider::find_by_name(&appstate.pool, &name)
        .await?
        .ok_or_else(|| WebError::ObjectNotFound("Microsoft OIDC provider not found".into()))?;
    let tenant_id = normalize_tenant(&data.tenant_id)?;
    let issuer = microsoft_issuer(&tenant_id, &data.base_url)?;
    let allowed_domains = normalize_domains(&data.allowed_domains)?;
    let secret = if data.client_secret.trim().is_empty() {
        existing.client_secret.clone()
    } else {
        data.client_secret.trim().to_owned()
    };
    if data.client_id.trim().is_empty() || secret.is_empty() {
        return Err(WebError::BadRequest("Microsoft client ID and client secret are required".into()));
    }

    let provider = SMetricOidcProvider::update(
        &appstate.pool,
        existing.id,
        data.name.trim(),
        &tenant_id,
        &issuer,
        data.client_id.trim(),
        &secret,
        data.display_name.as_deref(),
        data.enabled,
        data.is_default,
        &allowed_domains,
        data.create_account,
        username_handling_to_db(data.username_handling),
        data.disable_password_management,
    )
    .await?
    .ok_or_else(|| WebError::ObjectNotFound("Microsoft OIDC provider not found".into()))?;

    Ok(ApiResponse::json(provider_json(&provider), StatusCode::OK))
}

pub async fn get_openid_provider(
    _admin: AdminRole,
    State(appstate): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult {
    match SMetricOidcProvider::find_by_name(&appstate.pool, &name).await? {
        Some(provider) => Ok(ApiResponse::json(provider_json(&provider), StatusCode::OK)),
        None => Ok(ApiResponse::with_status(StatusCode::NOT_FOUND)),
    }
}

pub async fn get_current_openid_provider(
    _admin: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    match SMetricOidcProvider::default_enabled(&appstate.pool).await? {
        Some(provider) => Ok(ApiResponse::json(provider_json(&provider), StatusCode::OK)),
        None => Ok(ApiResponse::with_status(StatusCode::NO_CONTENT)),
    }
}

pub async fn list_openid_providers(
    _admin: AdminRole,
    State(appstate): State<AppState>,
) -> ApiResult {
    let providers = SMetricOidcProvider::all(&appstate.pool).await?;
    let response: Vec<_> = providers.iter().map(provider_json).collect();
    Ok(ApiResponse::json(response, StatusCode::OK))
}

pub async fn delete_openid_provider(
    _admin: AdminRole,
    _session: SessionInfo,
    State(appstate): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult {
    let Some(provider) = SMetricOidcProvider::find_by_name(&appstate.pool, &name).await? else {
        return Ok(ApiResponse::with_status(StatusCode::NOT_FOUND));
    };
    if SMetricOidcProvider::delete(&appstate.pool, provider.id).await? {
        Ok(ApiResponse::with_status(StatusCode::OK))
    } else {
        Ok(ApiResponse::with_status(StatusCode::NOT_FOUND))
    }
}

pub async fn test_dirsync_connection(
    _admin: AdminRole,
    _session: SessionInfo,
    State(_appstate): State<AppState>,
) -> ApiResult {
    Ok(ApiResponse::json(
        json!({
            "success": false,
            "message": "Microsoft OIDC authentication is independent of directory synchronization. Microsoft Graph synchronization is not enabled in this implementation."
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
    provider: &SMetricOidcProvider,
    redirect_url: Url,
) -> Result<(
    ClientId,
    CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>,
), WebError> {
    let issuer = IssuerUrl::new(provider.issuer.clone())
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

async fn select_provider(
    pool: &sqlx::PgPool,
    query: &AuthInfoQuery,
) -> Result<SMetricOidcProvider, WebError> {
    let provider = if let Some(id) = query.provider_id {
        SMetricOidcProvider::find_by_id(pool, id).await?
    } else if let Some(name) = query.provider.as_deref() {
        SMetricOidcProvider::find_by_name(pool, name).await?
    } else {
        SMetricOidcProvider::default_enabled(pool).await?
    };
    let provider = provider
        .ok_or_else(|| WebError::ObjectNotFound("Microsoft OIDC provider is not configured".into()))?;
    if !provider.enabled {
        return Err(WebError::Authorization("Selected Microsoft provider is disabled".into()));
    }
    Ok(provider)
}

pub async fn get_auth_info(
    mut private_cookies: PrivateCookieJar,
    State(appstate): State<AppState>,
    Query(query): Query<AuthInfoQuery>,
) -> Result<(PrivateCookieJar, ApiResponse), WebError> {
    let enabled = SMetricOidcProvider::enabled(&appstate.pool).await?;
    if enabled.is_empty() {
        return Err(WebError::ObjectNotFound("Microsoft OIDC provider is not configured".into()));
    }
    let provider = select_provider(&appstate.pool, &query).await?;
    let settings = Settings::get_current_settings();
    let (_, client) = oidc_client(&provider, settings.callback_url()?).await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge)
        .add_scope(Scope::new("profile".into()))
        .add_scope(Scope::new("email".into()))
        .url();

    let config = server_config();
    let secure = config
        .cookie_insecure
        .map_or(settings.cookie_secure()?, |insecure| !insecure);
    private_cookies = private_cookies
        .add(private_cookie(OIDC_STATE_COOKIE, state.secret().clone(), secure))
        .add(private_cookie(OIDC_NONCE_COOKIE, nonce.secret().clone(), secure))
        .add(private_cookie(OIDC_PKCE_COOKIE, verifier.secret().clone(), secure))
        .add(private_cookie(OIDC_PROVIDER_COOKIE, provider.id.to_string(), secure));

    let providers: Vec<_> = enabled.into_iter().map(public_provider).collect();
    Ok((
        private_cookies,
        ApiResponse::json(
            json!({
                "url": url,
                "provider_id": provider.id,
                "button_display_name": provider
                    .display_name
                    .clone()
                    .unwrap_or_else(|| "Sign in with Microsoft".to_owned()),
                "providers": providers,
            }),
            StatusCode::OK,
        ),
    ))
}

fn normalized_username(source: &str, handling: &str) -> String {
    let remove_domain = handling == "prune_email_domain";
    let source = if remove_domain {
        source.split('@').next().unwrap_or(source)
    } else {
        source
    };
    let mut value = source
        .trim_start_matches(|c: char| !c.is_ascii_alphanumeric())
        .to_owned();
    let valid = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_');
    match handling {
        "remove_forbidden" => value.retain(valid),
        _ => {
            value = value
                .chars()
                .map(|c| if valid(c) { c } else { '_' })
                .collect();
        }
    }
    value.truncate(64);
    value
}

fn validate_email_domain(provider: &SMetricOidcProvider, email: &str) -> Result<(), WebError> {
    if provider.allowed_domains.is_empty() {
        return Ok(());
    }
    let domain = email
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_ascii_lowercase())
        .ok_or_else(|| WebError::Authorization("Microsoft identity did not contain a valid email address".into()))?;
    if provider
        .allowed_domains
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&domain))
    {
        Ok(())
    } else {
        Err(WebError::Authorization(
            "This Microsoft account domain is not allowed for the selected organization".into(),
        ))
    }
}

async fn resolve_user(
    pool: &sqlx::PgPool,
    provider: &SMetricOidcProvider,
    sub: &str,
    email: &str,
    preferred_username: Option<&str>,
    given_name: Option<&str>,
    family_name: Option<&str>,
) -> Result<User<defguard_common::db::Id>, WebError> {
    validate_email_domain(provider, email)?;
    let provider_subject = format!("{}:{sub}", provider.tenant_id);

    if let Some(user) = User::find_by_sub(pool, &provider_subject).await? {
        if !user.is_active {
            return Err(WebError::Authorization("User is disabled".into()));
        }
        return Ok(user);
    }

    if let Some(mut user) = User::find_by_email(pool, email).await? {
        if !user.is_active {
            return Err(WebError::Authorization("User is disabled".into()));
        }
        user.openid_sub = Some(provider_subject);
        user.save(pool).await?;
        return Ok(user);
    }

    if !provider.auto_create {
        return Err(WebError::Authorization(
            "No local account matches this Microsoft identity and automatic account creation is disabled".into(),
        ));
    }

    let source = preferred_username.unwrap_or(email);
    let username = normalized_username(source, &provider.username_handling);
    check_username(&username)?;
    if User::find_by_username(pool, &username).await?.is_some() {
        return Err(WebError::Authorization(format!("Username {username} already exists")));
    }

    let mut user = User::new(
        username,
        None,
        family_name.unwrap_or("").to_owned(),
        given_name
            .unwrap_or(source.split('@').next().unwrap_or(source))
            .to_owned(),
        email.to_owned(),
        None,
    );
    user.openid_sub = Some(provider_subject);
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
    let provider_id = private_cookies
        .get(OIDC_PROVIDER_COOKIE)
        .ok_or_else(|| WebError::Authorization("OIDC provider cookie is missing".into()))?
        .value()
        .parse::<i64>()
        .map_err(|_| WebError::Authorization("OIDC provider cookie is invalid".into()))?;

    private_cookies = private_cookies
        .remove(Cookie::from(OIDC_STATE_COOKIE))
        .remove(Cookie::from(OIDC_NONCE_COOKIE))
        .remove(Cookie::from(OIDC_PKCE_COOKIE))
        .remove(Cookie::from(OIDC_PROVIDER_COOKIE));

    let provider = SMetricOidcProvider::find_by_id(&appstate.pool, provider_id)
        .await?
        .ok_or_else(|| WebError::Authorization("Selected Microsoft provider no longer exists".into()))?;
    if !provider.enabled {
        return Err(WebError::Authorization("Selected Microsoft provider is disabled".into()));
    }

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
    if !claims
        .audiences()
        .iter()
        .any(|aud| aud.as_str() == client_id.as_str())
    {
        return Err(WebError::Authorization(
            "Microsoft ID token audience does not match this application".into(),
        ));
    }

    let preferred = claims
        .preferred_username()
        .map(|value| value.as_str().to_owned());
    let email = claims
        .email()
        .map(|value| value.as_str().to_owned())
        .or_else(|| preferred.clone())
        .ok_or_else(|| {
            WebError::Authorization(
                "Microsoft identity did not include an email or preferred username".into(),
            )
        })?;
    let given = claims
        .given_name()
        .and_then(|value| value.get(None))
        .map(|value| value.as_str().to_owned());
    let family = claims
        .family_name()
        .and_then(|value| value.get(None))
        .map(|value| value.as_str().to_owned());
    let sub = claims.subject().as_str().to_owned();

    let mut user = resolve_user(
        &appstate.pool,
        &provider,
        &sub,
        &email,
        preferred.as_deref(),
        given.as_deref(),
        family.as_deref(),
    )
    .await?;

    let (session, user_info, mfa_info) =
        create_session(&appstate.pool, ip_addr, user_agent.as_str(), &mut user).await?;

    let timeout = Settings::get_current_settings().authentication_timeout();
    let max_age = Duration::try_from(timeout)
        .map_err(|_| WebError::Http(StatusCode::INTERNAL_SERVER_ERROR))?;
    let config = server_config();
    let secure = config
        .cookie_insecure
        .map_or(settings.cookie_secure()?, |insecure| !insecure);
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
        return Ok((
            cookies,
            private_cookies,
            ApiResponse::json(mfa, StatusCode::CREATED),
        ));
    }

    let user_info = user_info.ok_or_else(|| WebError::Http(StatusCode::INTERNAL_SERVER_ERROR))?;
    let url = private_cookies
        .get(SIGN_IN_COOKIE_NAME)
        .map(|cookie| cookie.value().to_owned());
    if private_cookies.get(SIGN_IN_COOKIE_NAME).is_some() {
        private_cookies = private_cookies.remove(Cookie::from(SIGN_IN_COOKIE_NAME));
    }

    Ok((
        cookies,
        private_cookies,
        ApiResponse::json(AuthResponse { user: user_info, url }, StatusCode::OK),
    ))
}
