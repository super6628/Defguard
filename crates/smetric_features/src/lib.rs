//! S-Metric-owned implementations of administrative and directory features.
//!
//! This crate intentionally lives outside `defguard_core::enterprise` and does not depend on
//! Defguard Enterprise implementation modules.

pub mod bulk_users;
pub mod ldap_groups;
pub mod microsoft_directory;
pub mod smtp_oauth;
