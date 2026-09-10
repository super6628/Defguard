use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use utoipa::ToSchema;

#[derive(Clone, Debug, Deserialize, FromRow, Serialize, ToSchema)]
pub struct SMetricOidcProvider {
    pub id: i64,
    pub name: String,
    pub tenant_id: String,
    pub issuer: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub is_default: bool,
    pub allowed_domains: Vec<String>,
    pub auto_create: bool,
    pub username_handling: String,
    pub disable_password_management: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SMetricOidcProvider {
    pub async fn all(pool: &PgPool) -> sqlx::Result<Vec<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT id, name, tenant_id, issuer, client_id, client_secret, display_name, enabled, \
             is_default, allowed_domains, auto_create, username_handling, disable_password_management, \
             created_at, updated_at FROM smetric_oidc_provider ORDER BY name",
        )
        .fetch_all(pool)
        .await
    }

    pub async fn enabled(pool: &PgPool) -> sqlx::Result<Vec<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT id, name, tenant_id, issuer, client_id, client_secret, display_name, enabled, \
             is_default, allowed_domains, auto_create, username_handling, disable_password_management, \
             created_at, updated_at FROM smetric_oidc_provider WHERE enabled = TRUE \
             ORDER BY is_default DESC, name",
        )
        .fetch_all(pool)
        .await
    }

    pub async fn find_by_id(pool: &PgPool, id: i64) -> sqlx::Result<Option<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT id, name, tenant_id, issuer, client_id, client_secret, display_name, enabled, \
             is_default, allowed_domains, auto_create, username_handling, disable_password_management, \
             created_at, updated_at FROM smetric_oidc_provider WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    pub async fn find_by_name(pool: &PgPool, name: &str) -> sqlx::Result<Option<Self>> {
        sqlx::query_as::<_, Self>(
            "SELECT id, name, tenant_id, issuer, client_id, client_secret, display_name, enabled, \
             is_default, allowed_domains, auto_create, username_handling, disable_password_management, \
             created_at, updated_at FROM smetric_oidc_provider WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// Select the implicit provider used by login when the caller did not choose one.
    ///
    /// An explicit enabled default wins. If no default is configured, a single enabled
    /// provider may be selected automatically. Multiple enabled providers with no default
    /// deliberately return `None` so login never silently chooses an organization.
    pub async fn default_enabled(pool: &PgPool) -> sqlx::Result<Option<Self>> {
        sqlx::query_as::<_, Self>(
            "WITH enabled AS ( \
                 SELECT id, name, tenant_id, issuer, client_id, client_secret, display_name, enabled, \
                        is_default, allowed_domains, auto_create, username_handling, \
                        disable_password_management, created_at, updated_at \
                 FROM smetric_oidc_provider WHERE enabled = TRUE \
             ), selected AS ( \
                 SELECT * FROM enabled WHERE is_default = TRUE \
                 UNION ALL \
                 SELECT * FROM enabled \
                 WHERE (SELECT COUNT(*) FROM enabled) = 1 \
                   AND NOT EXISTS (SELECT 1 FROM enabled WHERE is_default = TRUE) \
             ) \
             SELECT id, name, tenant_id, issuer, client_id, client_secret, display_name, enabled, \
                    is_default, allowed_domains, auto_create, username_handling, \
                    disable_password_management, created_at, updated_at \
             FROM selected ORDER BY is_default DESC, id ASC LIMIT 1",
        )
        .fetch_optional(pool)
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &PgPool,
        name: &str,
        tenant_id: &str,
        issuer: &str,
        client_id: &str,
        client_secret: &str,
        display_name: Option<&str>,
        enabled: bool,
        is_default: bool,
        allowed_domains: &[String],
        auto_create: bool,
        username_handling: &str,
        disable_password_management: bool,
    ) -> sqlx::Result<Self> {
        let mut tx = pool.begin().await?;
        if is_default {
            sqlx::query(
                "UPDATE smetric_oidc_provider SET is_default = FALSE WHERE is_default = TRUE",
            )
            .execute(&mut *tx)
            .await?;
        }
        let provider = sqlx::query_as::<_, Self>(
            "INSERT INTO smetric_oidc_provider \
             (name, tenant_id, issuer, client_id, client_secret, display_name, enabled, is_default, \
              allowed_domains, auto_create, username_handling, disable_password_management) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
             RETURNING id, name, tenant_id, issuer, client_id, client_secret, display_name, enabled, \
             is_default, allowed_domains, auto_create, username_handling, disable_password_management, \
             created_at, updated_at",
        )
        .bind(name)
        .bind(tenant_id)
        .bind(issuer)
        .bind(client_id)
        .bind(client_secret)
        .bind(display_name)
        .bind(enabled)
        .bind(is_default)
        .bind(allowed_domains)
        .bind(auto_create)
        .bind(username_handling)
        .bind(disable_password_management)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(provider)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn update(
        pool: &PgPool,
        id: i64,
        name: &str,
        tenant_id: &str,
        issuer: &str,
        client_id: &str,
        client_secret: &str,
        display_name: Option<&str>,
        enabled: bool,
        is_default: bool,
        allowed_domains: &[String],
        auto_create: bool,
        username_handling: &str,
        disable_password_management: bool,
    ) -> sqlx::Result<Option<Self>> {
        let mut tx = pool.begin().await?;
        if is_default {
            sqlx::query("UPDATE smetric_oidc_provider SET is_default = FALSE WHERE is_default = TRUE AND id <> $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        let provider = sqlx::query_as::<_, Self>(
            "UPDATE smetric_oidc_provider SET name=$2, tenant_id=$3, issuer=$4, client_id=$5, \
             client_secret=$6, display_name=$7, enabled=$8, is_default=$9, allowed_domains=$10, \
             auto_create=$11, username_handling=$12, disable_password_management=$13, updated_at=NOW() \
             WHERE id=$1 RETURNING id, name, tenant_id, issuer, client_id, client_secret, display_name, \
             enabled, is_default, allowed_domains, auto_create, username_handling, \
             disable_password_management, created_at, updated_at",
        )
        .bind(id)
        .bind(name)
        .bind(tenant_id)
        .bind(issuer)
        .bind(client_id)
        .bind(client_secret)
        .bind(display_name)
        .bind(enabled)
        .bind(is_default)
        .bind(allowed_domains)
        .bind(auto_create)
        .bind(username_handling)
        .bind(disable_password_management)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(provider)
    }

    pub async fn delete(pool: &PgPool, id: i64) -> sqlx::Result<bool> {
        Ok(
            sqlx::query("DELETE FROM smetric_oidc_provider WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await?
                .rows_affected()
                > 0,
        )
    }
}
