//! S-Metric location-level effective firewall compiler.
//!
//! Gateway firewall updates replace the complete firewall configuration for a location. This
//! module therefore owns the aggregation boundary: all enabled, published S-Metric policies
//! assigned to a location are rendered and combined into one deterministic FirewallConfig.

use defguard_common::gateway_types::{FirewallConfig, FirewallPolicy};
use sha256::digest;
use sqlx::PgPool;

use super::{
    DefaultAction, compile,
    gateway::{GatewayEnforcementError, resolve_snat_bindings, translate_policy_for_location},
    service::{ServiceError, load_policy},
};

#[derive(Clone, Debug)]
pub struct EffectiveLocationFirewall {
    pub location_id: i64,
    pub policy_ids: Vec<i64>,
    pub policy_revisions: Vec<(i64, u64)>,
    pub checksum: String,
    pub config: FirewallConfig,
}

pub async fn compile_location_firewall(
    pool: &PgPool,
    location_id: i64,
) -> Result<EffectiveLocationFirewall, GatewayEnforcementError> {
    compile_location_firewall_overrides(pool, location_id, None, None).await
}

/// Compile the effective location firewall while excluding one policy from consideration.
///
/// This is used by destructive/disable/unassign operations so the resulting gateway configuration
/// can be validated before the database mutation is committed.
pub async fn compile_location_firewall_without_policy(
    pool: &PgPool,
    location_id: i64,
    excluded_policy_id: i64,
) -> Result<EffectiveLocationFirewall, GatewayEnforcementError> {
    compile_location_firewall_overrides(pool, location_id, Some(excluded_policy_id), None).await
}

/// Compile the effective location firewall while force-including one published policy.
///
/// This supports prospective enable/assignment operations. The policy's current revision must
/// already be published, but the policy/assignment does not have to be enabled yet.
pub async fn compile_location_firewall_with_policy(
    pool: &PgPool,
    location_id: i64,
    included_policy_id: i64,
) -> Result<EffectiveLocationFirewall, GatewayEnforcementError> {
    compile_location_firewall_overrides(pool, location_id, None, Some(included_policy_id)).await
}

/// Compile one authoritative firewall configuration for a VPN location.
///
/// Policies are ordered by policy id for now. Rules retain each policy's compiled rule ordering.
/// A future explicit policy-priority field can replace policy-id ordering without changing this
/// aggregation boundary.
async fn compile_location_firewall_overrides(
    pool: &PgPool,
    location_id: i64,
    excluded_policy_id: Option<i64>,
    included_policy_id: Option<i64>,
) -> Result<EffectiveLocationFirewall, GatewayEnforcementError> {
    let policy_ids = sqlx::query_scalar::<_, i64>(
        "SELECT DISTINCT candidate.id \
         FROM ( \
             SELECT p.id \
             FROM smetric_acl_policy p \
             JOIN smetric_acl_policy_assignment a ON a.policy_id = p.id \
             WHERE a.location_id = $1 \
               AND a.enabled = TRUE \
               AND p.enabled = TRUE \
             UNION ALL \
             SELECT p.id \
             FROM smetric_acl_policy p \
             WHERE p.id = $3 \
         ) candidate \
         JOIN smetric_acl_policy p ON p.id = candidate.id \
         WHERE ($2::bigint IS NULL OR p.id <> $2) \
           AND EXISTS ( \
               SELECT 1 FROM smetric_acl_revision rev \
               WHERE rev.policy_id = p.id AND rev.revision = p.revision \
           ) \
         ORDER BY candidate.id",
    )
    .bind(location_id)
    .bind(excluded_policy_id)
    .bind(included_policy_id)
    .fetch_all(pool)
    .await?;

    let mut rules = Vec::new();
    let mut policy_revisions = Vec::with_capacity(policy_ids.len());
    let mut default_policy = FirewallPolicy::Allow;
    let mut snat_bindings = None;

    for policy_id in &policy_ids {
        let policy = compile(load_policy(pool, *policy_id).await?).map_err(ServiceError::Validation)?;
        if matches!(policy.default_action, DefaultAction::Deny) {
            default_policy = FirewallPolicy::Deny;
        }
        policy_revisions.push((*policy_id, policy.revision));

        let rendered = translate_policy_for_location(pool, &policy, location_id).await?;
        rules.extend(rendered.rules);
        if snat_bindings.is_none() {
            snat_bindings = Some(rendered.snat_bindings);
        }
    }

    let snat_bindings = match snat_bindings {
        Some(bindings) => bindings,
        None => resolve_snat_bindings(pool, location_id).await?,
    };
    let config = FirewallConfig {
        default_policy,
        rules,
        snat_bindings,
    };
    let checksum = digest(format!("{config:?}"));

    Ok(EffectiveLocationFirewall {
        location_id,
        policy_ids,
        policy_revisions,
        checksum,
        config,
    })
}
