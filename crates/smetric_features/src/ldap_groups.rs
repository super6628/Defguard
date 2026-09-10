use std::collections::{HashMap, HashSet, VecDeque};

use thiserror::Error;

pub const DEFAULT_MAX_NESTED_GROUPS: usize = 10_000;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NestedGroupError {
    #[error("nested LDAP group traversal exceeded the configured limit of {0} groups")]
    LimitExceeded(usize),
}

/// Resolve nested LDAP group membership without recursion or provider-specific matching rules.
///
/// `parents_by_member` maps a member DN (user or group) to the group DNs that directly contain it.
/// The returned set contains every directly or transitively containing group. Cycles are safe.
/// A traversal bound prevents malformed or unexpectedly huge directory graphs from consuming
/// unbounded memory during synchronization.
pub fn transitive_parent_groups_with_limit(
    member_dn: &str,
    parents_by_member: &HashMap<String, Vec<String>>,
    max_groups: usize,
) -> Result<HashSet<String>, NestedGroupError> {
    let mut result = HashSet::new();
    let mut queue = VecDeque::from([member_dn.to_owned()]);
    let mut visited_members = HashSet::new();

    while let Some(member) = queue.pop_front() {
        if !visited_members.insert(member.clone()) {
            continue;
        }
        if let Some(parents) = parents_by_member.get(&member) {
            for parent in parents {
                if result.insert(parent.clone()) {
                    if result.len() > max_groups {
                        return Err(NestedGroupError::LimitExceeded(max_groups));
                    }
                    queue.push_back(parent.clone());
                }
            }
        }
    }
    Ok(result)
}

pub fn transitive_parent_groups(
    member_dn: &str,
    parents_by_member: &HashMap<String, Vec<String>>,
) -> Result<HashSet<String>, NestedGroupError> {
    transitive_parent_groups_with_limit(member_dn, parents_by_member, DEFAULT_MAX_NESTED_GROUPS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_nested_groups_and_cycles() {
        let user = "uid=alice,ou=users,dc=example,dc=com".to_owned();
        let dev = "cn=dev,ou=groups,dc=example,dc=com".to_owned();
        let vpn = "cn=vpn,ou=groups,dc=example,dc=com".to_owned();
        let all = "cn=all,ou=groups,dc=example,dc=com".to_owned();
        let mut graph = HashMap::new();
        graph.insert(user.clone(), vec![dev.clone()]);
        graph.insert(dev.clone(), vec![vpn.clone()]);
        graph.insert(vpn.clone(), vec![all.clone()]);
        graph.insert(all.clone(), vec![dev.clone()]);

        let groups = transitive_parent_groups(&user, &graph).unwrap();
        assert_eq!(groups.len(), 3);
        assert!(groups.contains(&dev));
        assert!(groups.contains(&vpn));
        assert!(groups.contains(&all));
    }

    #[test]
    fn traversal_limit_is_enforced() {
        let user = "uid=alice".to_owned();
        let group_a = "cn=a".to_owned();
        let group_b = "cn=b".to_owned();
        let mut graph = HashMap::new();
        graph.insert(user.clone(), vec![group_a.clone()]);
        graph.insert(group_a, vec![group_b]);

        assert_eq!(
            transitive_parent_groups_with_limit(&user, &graph, 1),
            Err(NestedGroupError::LimitExceeded(1))
        );
    }
}
