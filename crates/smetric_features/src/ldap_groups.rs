use std::collections::{HashMap, HashSet, VecDeque};

/// Resolve nested LDAP group membership without recursion or provider-specific matching rules.
///
/// `parents_by_member` maps a member DN (user or group) to the group DNs that directly contain it.
/// The returned set contains every directly or transitively containing group. Cycles are safe.
#[must_use]
pub fn transitive_parent_groups(
    member_dn: &str,
    parents_by_member: &HashMap<String, Vec<String>>,
) -> HashSet<String> {
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
                    queue.push_back(parent.clone());
                }
            }
        }
    }
    result
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

        let groups = transitive_parent_groups(&user, &graph);
        assert_eq!(groups.len(), 3);
        assert!(groups.contains(&dev));
        assert!(groups.contains(&vpn));
        assert!(groups.contains(&all));
    }
}
