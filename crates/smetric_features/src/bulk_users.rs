use std::collections::HashSet;

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
    #[error("bulk group request contains no groups")]
    EmptyGroups,
    #[error("bulk request contains one or more unknown user IDs")]
    UnknownUsers,
    #[error("bulk request contains one or more unknown group IDs")]
    UnknownGroups,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

fn unique_ids(ids: &[Id]) -> Vec<Id> {
    let mut seen = HashSet::with_capacity(ids.len());
    ids.iter().copied().filter(|id| seen.insert(*id)).collect()
}

pub async fn apply(
    pool: &PgPool,
    user_ids: &[Id],
    action: &BulkUserAction,
) -> Result<u64, BulkUserError> {
    let user_ids = unique_ids(user_ids);
    if user_ids.is_empty() {
        return Err(BulkUserError::EmptyUsers);
    }

    let group_ids = match action {
        BulkUserAction::AddToGroups(ids) | BulkUserAction::RemoveFromGroups(ids) => {
            let ids = unique_ids(ids);
            if ids.is_empty() {
                return Err(BulkUserError::EmptyGroups);
            }
            Some(ids)
        }
        BulkUserAction::Enable | BulkUserAction::Disable => None,
    };

    let mut tx = pool.begin().await?;

    let user_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM \"user\" WHERE id = ANY($1)",
    )
    .bind(&user_ids)
    .fetch_one(&mut *tx)
    .await?;
    if user_count != user_ids.len() as i64 {
        return Err(BulkUserError::UnknownUsers);
    }

    if let Some(group_ids) = &group_ids {
        let group_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM \"group\" WHERE id = ANY($1)",
        )
        .bind(group_ids)
        .fetch_one(&mut *tx)
        .await?;
        if group_count != group_ids.len() as i64 {
            return Err(BulkUserError::UnknownGroups);
        }
    }

    let affected = match action {
        BulkUserAction::Enable => {
            sqlx::query("UPDATE \"user\" SET is_active = TRUE WHERE id = ANY($1)")
                .bind(&user_ids)
                .execute(&mut *tx)
                .await?
                .rows_affected()
        }
        BulkUserAction::Disable => {
            sqlx::query("UPDATE \"user\" SET is_active = FALSE WHERE id = ANY($1)")
                .bind(&user_ids)
                .execute(&mut *tx)
                .await?
                .rows_affected()
        }
        BulkUserAction::AddToGroups(_) => {
            let mut affected = 0;
            for group_id in group_ids.as_ref().expect("group IDs validated above") {
                affected += sqlx::query(
                    "INSERT INTO group_user (user_id, group_id) \
                     SELECT id, $2 FROM \"user\" WHERE id = ANY($1) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(&user_ids)
                .bind(group_id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            }
            affected
        }
        BulkUserAction::RemoveFromGroups(_) => {
            sqlx::query("DELETE FROM group_user WHERE user_id = ANY($1) AND group_id = ANY($2)")
                .bind(&user_ids)
                .bind(group_ids.as_ref().expect("group IDs validated above"))
                .execute(&mut *tx)
                .await?
                .rows_affected()
        }
    };

    tx.commit().await?;
    Ok(affected)
}

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
