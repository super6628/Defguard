use defguard_common::{db::models::settings::smtp::SmtpSettings, secret::SecretStringWrapper};
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SmtpOAuthError {
    #[error("missing SMTP OAuth setting: {0}")]
    Missing(&'static str),
    #[error("OAuth discovery request failed: {0}")]
    Discovery(#[source] reqwest::Error),
    #[error("OAuth token request failed: {0}")]
    TokenRequest(#[source] reqwest::Error),
    #[error("OAuth provider returned HTTP {status}: {body}")]
    Provider { status: reqwest::StatusCode, body: String },
    #[error("OAuth provider did not return an access token")]
    MissingAccessToken,
}

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    token_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
}

fn secret(value: &Option<SecretStringWrapper>, name: &'static str) -> Result<String, SmtpOAuthError> {
    value
        .as_ref()
        .map(|value| value.expose_secret().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(SmtpOAuthError::Missing(name))
}

fn required(value: &Option<String>, name: &'static str) -> Result<String, SmtpOAuthError> {
    value
        .as_ref()
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or(SmtpOAuthError::Missing(name))
}

/// Fetch an SMTP XOAUTH2 bearer token without using Defguard Enterprise OAuth code.
///
/// Supports standards-compliant OIDC providers, including Microsoft identity platform and Google.
/// The configured issuer is discovered via `/.well-known/openid-configuration` and the refresh
/// token grant is sent to its advertised token endpoint.
pub async fn access_token(settings: &SmtpSettings) -> Result<String, SmtpOAuthError> {
    let issuer = required(&settings.oauth_issuer_url, "smtp_oauth_issuer_url")?;
    let client_id = required(&settings.oauth_client_id, "smtp_oauth_client_id")?;
    let client_secret = secret(&settings.oauth_client_secret, "smtp_oauth_client_secret")?;
    let refresh_token = required(&settings.oauth_refresh_token, "smtp_oauth_refresh_token")?;

    let discovery_url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let client = Client::new();
    let discovery_response = client
        .get(discovery_url)
        .send()
        .await
        .map_err(SmtpOAuthError::Discovery)?;
    let status = discovery_response.status();
    if !status.is_success() {
        return Err(SmtpOAuthError::Provider {
            status,
            body: discovery_response.text().await.unwrap_or_default(),
        });
    }
    let discovery = discovery_response
        .json::<DiscoveryDocument>()
        .await
        .map_err(SmtpOAuthError::Discovery)?;

    let token_response = client
        .post(discovery.token_endpoint)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
            ("refresh_token", refresh_token.as_str()),
        ])
        .send()
        .await
        .map_err(SmtpOAuthError::TokenRequest)?;
    let status = token_response.status();
    if !status.is_success() {
        return Err(SmtpOAuthError::Provider {
            status,
            body: token_response.text().await.unwrap_or_default(),
        });
    }

    token_response
        .json::<TokenResponse>()
        .await
        .map_err(SmtpOAuthError::TokenRequest)?
        .access_token
        .filter(|token| !token.is_empty())
        .ok_or(SmtpOAuthError::MissingAccessToken)
}
