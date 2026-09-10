use std::collections::HashSet;

/// Configuration for restricting Microsoft directory synchronization to selected groups.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MicrosoftGroupScope {
    /// Microsoft Entra group object IDs. Empty means no restriction.
    group_ids: HashSet<String>,
}

impl MicrosoftGroupScope {
    #[must_use]
    pub fn new<I, S>(group_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            group_ids: group_ids
                .into_iter()
                .map(Into::into)
                .filter(|id| !id.trim().is_empty())
                .collect(),
        }
    }

    #[must_use]
    pub fn is_unrestricted(&self) -> bool {
        self.group_ids.is_empty()
    }

    #[must_use]
    pub fn includes_group(&self, group_id: &str) -> bool {
        self.is_unrestricted() || self.group_ids.contains(group_id)
    }

    /// Returns true when at least one of a user's transitive/direct Entra group IDs is in scope.
    #[must_use]
    pub fn includes_user<'a, I>(&self, group_ids: I) -> bool
    where
        I: IntoIterator<Item = &'a str>,
    {
        self.is_unrestricted() || group_ids.into_iter().any(|id| self.group_ids.contains(id))
    }

    #[must_use]
    pub fn ids(&self) -> &HashSet<String> {
        &self.group_ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scope_allows_everyone() {
        let scope = MicrosoftGroupScope::default();
        assert!(scope.includes_user(std::iter::empty()));
        assert!(scope.includes_group("anything"));
    }

    #[test]
    fn scoped_users_need_matching_membership() {
        let scope = MicrosoftGroupScope::new(["engineering", "vpn"]);
        assert!(scope.includes_user(["vpn"].into_iter()));
        assert!(!scope.includes_user(["sales"].into_iter()));
    }
}
