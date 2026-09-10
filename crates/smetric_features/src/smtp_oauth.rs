use std::time::Duration;

use defguard_common::{db::models::settings::smtp::SmtpSettings, secret::SecretStringWrapper};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use thiserror::Error;

const OAUTH_HTTP_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PROVIDER_ERROR_BYTES: usize = 2048;

#[derive(Debug, Error)]
pub enum SmtpOAuthError {
    #[error("missing SMTP OAuth setting: {0}")]
    Missing(&'static str),
    #[error("invalid SMTP OAuth issuer URL")]
    InvalidIssuer,
    #[error("unable to build OAuth HTTP client: {0}")]
    Client(#[source] reqwest::Error),
    #[error("OAuth discovery request failed: {0}")]
    Discovery(#[source] reqwest::Error),
    #[error("OAuth token request failed: {0}")]
    TokenRequest(#[source] reqwest::Error),
    #[error("OAuth provider returned HTTP {status}: {body}")]
    Provider { status: StatusCode, body: String },
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
        .map(|value| value.expose_secret().trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(SmtpOAuthError::Missing(name))
}

fn required(value: &Option<String>, name: &'static str) -> Result<String, SmtpOAuthError> {
    value
        .as_ref()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(SmtpOAuthError::Missing(name))
}

fn provider_body(body: String) -> String {
    body.chars().take(MAX_PROVIDER_ERROR_BYTES).collect()
}

async fn provider_error(status: StatusCode, response: reqwest::Response) -> SmtpOAuthError {
    SmtpOAuthError::Provider {
        status,
        body: provider_body(response.text().await.unwrap_or_default()),
    }
}

pub async fn access_token(settings: &SmtpSettings) -> Result<String, SmtpOAuthError> {
    let issuer = required(&settings.oauth_issuer_url, "smtp_oauth_issuer_url")?;
    let client_id = required(&settings.oauth_client_id, "smtp_oauth_client_id")?;
    let client_secret = secret(&settings.oauth_client_secret, "smtp_oauth_client_secret")?;
    let refresh_token = required(&settings.oauth_refresh_token, "smtp_oauth_refresh_token")?;

    let issuer_url = reqwest::Url::parse(&issuer).map_err(|_| SmtpOAuthError::InvalidIssuer)?;
    if issuer_url.scheme() != "https" || issuer_url.host_str().is_none() {
        return Err(SmtpOAuthError::InvalidIssuer);
    }

    let discovery_url = issuer_url
        .join(".well-known/openid-configuration")
        .map_err(|_| SmtpOAuthError::InvalidIssuer)?;
    let client = Client::builder()
        .timeout(OAUTH_HTTP_TIMEOUT)
        .build()
        .map_err(SmtpOAuthError::Client)?;

    let discovery_response = client
        .get(discovery_url)
        .send()
        .await
        .map_err(SmtpOAuthError::Discovery)?;
    let status = discovery_response.status();
    if !status.is_success() {
        return Err(provider_error(status, discovery_response).await);
    }
    let discovery = discovery_response
        .json::<DiscoveryDocument>()
        .await
        .map_err(SmtpOAuthError::Discovery)?;

    let token_endpoint = reqwest::Url::parse(&discovery.token_endpoint)
        .map_err(|_| SmtpOAuthError::InvalidIssuer)?;
    if token_endpoint.scheme() != "https" {
        return Err(SmtpOAuthError::InvalidIssuer);
    }

    let token_response = client
        .post(token_endpoint)
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
        return Err(provider_error(status, token_response).await);
    }

    token_response
        .json::<TokenResponse>()
        .await
        .map_err(SmtpOAuthError::TokenRequest)?
        .access_token
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
        .ok_or(SmtpOAuthError::MissingAccessToken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_errors_are_bounded() {
        let body = "x".repeat(MAX_PROVIDER_ERROR_BYTES + 100);
        assert_eq!(provider_body(body).len(), MAX_PROVIDER_ERROR_BYTES);
    }
}
