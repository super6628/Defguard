//! Compatibility bridge for legacy core call sites.
//!
//! SMTP XOAUTH2 is implemented by the S-Metric-owned `smetric_features` crate. This module keeps
//! the existing core import path stable while removing SMTP authentication from the Enterprise
//! license gate. Other Enterprise OAuth helpers may continue to live in their own modules.

pub mod microsoft;

use defguard_common::db::models::settings::smtp::SmtpSettings;
use smetric_features::smtp_oauth::{SmtpOAuthError, access_token};

#[derive(Debug, thiserror::Error)]
pub enum OAuth2Error {
    #[error(transparent)]
    Smtp(#[from] SmtpOAuthError),
}

/// Obtain an SMTP XOAUTH2 bearer token using the clean-room S-Metric implementation.
///
/// The mutable argument is retained for compatibility with the existing mailer API. Token refresh
/// does not mutate settings or log secrets.
pub async fn xoauth2_access_token(smtp_settings: &mut SmtpSettings) -> Result<String, OAuth2Error> {
    Ok(access_token(smtp_settings).await?)
}
