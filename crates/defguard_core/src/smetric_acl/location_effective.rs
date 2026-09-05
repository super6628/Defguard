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

/// Compile one authoritative firewall configuration for a VPN location.
///
/// Policies are ordered by policy id for now. Rules retain each policy's compiled rule ordering.
/// A future explicit policy-priority field can replace policy-id ordering without changing this
/// aggregation boundary.
pub async fn compile_location_firewall(
    pool: &PgPool,
    location_id: i64,
) -> Result<EffectiveLocationFirewall, GatewayEnforcementError> {
    let policy_ids = sqlx::query_scalar::<_, i64>(
        "SELECT p.id \
         FROM smetric_acl_policy p \
         JOIN smetric_acl_policy_assignment a ON a.policy_id = p.id \
         WHERE a.location_id = $1 \
           AND a.enabled = TRUE \
           AND p.enabled = TRUE \
           AND EXISTS ( \
               SELECT 1 FROM smetric_acl_revision rev \
               WHERE rev.policy_id = p.id AND rev.revision = p.revision \
           ) \
         ORDER BY p.id",
    )
    .bind(location_id)
    .fetch_all(pool)
    .await?;

    let mut rules = Vec::new();
    let mut policy_revisions = Vec::with_capacity(policy_ids.len());
    let mut default_policy = FirewallPolicy::Allow;
    let mut snat_bindings = None;

    for policy_id in &policy_ids {
        let policy = compile(load_policy(pool, *policy_id).await?).map_err(ServiceError::Validation)?;
        if matches!(policy.default_action, DefaultAction::Deny) {
            // Conservative aggregate semantics: if any active policy requires a deny-by-default
            // posture, the location's effective default is deny.
            default_policy = FirewallPolicy::Deny;
        }
        policy_revisions.push((*policy_id, policy.revision));

        let rendered = translate_policy_for_location(pool, &policy, location_id).await?;
        rules.extend(rendered.rules);
        if snat_bindings.is_none() {
            snat_bindings = Some(rendered.snat_bindings);
        }
    }

    // SNAT belongs to the location rather than to an individual ACL policy. It must therefore be
    // present even when the last S-Metric ACL policy disappears: the resulting empty/ALLOW config
    // is the authoritative replacement that clears stale ACL rules without clearing SNAT.
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
