use defguard_common::db::{Id, models::User};
use sqlx::PgPool;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BulkUserAction {
    Enable,
    Disable,
    AddToGroups(Vec<Id>),
    RemoveFromGroups(Vec<Id>),
}

#[derive(Debug, Error)]
pub enum BulkUserError {
    #[error("bulk request contains no users")]
    EmptyUsers,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Apply one administrative action to many users in a single database transaction.
///
/// Group actions use IDs and `ON CONFLICT`/set deletion so the operation is idempotent.
/// The caller remains responsible for emitting audit events and synchronizing gateways/LDAP.
pub async fn apply(
    pool: &PgPool,
    user_ids: &[Id],
    action: &BulkUserAction,
) -> Result<u64, BulkUserError> {
    if user_ids.is_empty() {
        return Err(BulkUserError::EmptyUsers);
    }

    let mut tx = pool.begin().await?;
    let affected = match action {
        BulkUserAction::Enable => {
            sqlx::query("UPDATE \"user\" SET is_active = TRUE WHERE id = ANY($1)")
                .bind(user_ids)
                .execute(&mut *tx)
                .await?
                .rows_affected()
        }
        BulkUserAction::Disable => {
            sqlx::query("UPDATE \"user\" SET is_active = FALSE WHERE id = ANY($1)")
                .bind(user_ids)
                .execute(&mut *tx)
                .await?
                .rows_affected()
        }
        BulkUserAction::AddToGroups(group_ids) => {
            let mut affected = 0;
            for group_id in group_ids {
                affected += sqlx::query(
                    "INSERT INTO group_user (user_id, group_id) \
                     SELECT id, $2 FROM \"user\" WHERE id = ANY($1) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(user_ids)
                .bind(group_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            }
            affected
        }
        BulkUserAction::RemoveFromGroups(group_ids) => {
            sqlx::query("DELETE FROM group_user WHERE user_id = ANY($1) AND group_id = ANY($2)")
                .bind(user_ids)
                .bind(group_ids)
                .execute(&mut *tx)
                .await?
                .rows_affected()
        }
    };

    tx.commit().await?;
    Ok(affected)
}

/// Fetch the users targeted by a bulk action for audit/event/LDAP follow-up.
pub async fn targeted_users(pool: &PgPool, user_ids: &[Id]) -> Result<Vec<User<Id>>, sqlx::Error> {
    sqlx::query_as::<_, User<Id>>(
        "SELECT id, username, password_hash, last_name, first_name, email, phone, mfa_enabled, \
         totp_enabled, email_mfa_enabled, totp_secret, email_mfa_secret, mfa_method, \
         recovery_codes, is_active, openid_sub, from_ldap, ldap_pass_randomized, ldap_rdn, \
         ldap_user_path, ldap_remote_enrollment_completed, enrollment_pending \
         FROM \"user\" WHERE id = ANY($1)",
    )
    .bind(user_ids)
    .fetch_all(pool)
    .await
}
