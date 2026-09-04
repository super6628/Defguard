//! Defguard version information handling for gRPC communications.
//!
//! This crate provides utilities for embedding and extracting version and system information
//! in gRPC communications between Defguard components. It supports both client-side and
//! server-side middleware for automatic version header management.
//!
//! # Headers
//!
//! The crate defines two compatibility headers used across internal gRPC communications:
//!
//! - `defguard-component-version`: Semantic version string
//! - `defguard-component-system`: System information
//!
//! Public HTTP responses use the S-Metric-branded version header instead, while the legacy
//! internal metadata names are retained for compatibility with existing Edge/Gateway clients.

use std::{cmp::Ordering, fmt, str::FromStr};

use ::tracing::warn;
pub use semver::{BuildMetadata, Error as SemverError, Prerelease, Version};
use serde::Serialize;
use thiserror::Error;
use tonic::metadata::MetadataMap;

pub mod client;
pub mod server;
pub mod tracing;

/// Compatibility metadata header used for component-to-component version exchange.
pub static VERSION_HEADER: &str = "defguard-component-version";

/// Compatibility metadata header used for component-to-component system information.
pub static SYSTEM_INFO_HEADER: &str = "defguard-component-system";

/// Customer-visible HTTP response header for the S-Metric component version.
pub static PUBLIC_VERSION_HEADER: &str = "smetric-component-version";

#[derive(Debug, Error)]
pub enum DefguardVersionError {
    #[error(transparent)]
    SemverError(#[from] semver::Error),

    #[error("Failed to parse SystemInfo header: {0}")]
    SystemInfoParseError(String),

    #[error("Invalid component: {0}")]
    InvalidDefguardComponent(String),
}

/// Represents the different types of components that can communicate via gRPC.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub enum DefguardComponent {
    Core,
    Proxy,
    Gateway,
}

impl FromStr for DefguardComponent {
    type Err = DefguardVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "core" => Ok(Self::Core),
            "proxy" => Ok(Self::Proxy),
            "gateway" => Ok(Self::Gateway),
            _ => Err(Self::Err::InvalidDefguardComponent(s.to_owned())),
        }
    }
}

impl fmt::Display for DefguardComponent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Core => "core",
            Self::Proxy => "proxy",
            Self::Gateway => "gateway",
        })
    }
}

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub os_type: String,
    pub os_version: String,
    pub architecture: String,
}

impl fmt::Display for SystemInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.os_type, self.os_version, self.architecture)
    }
}

impl SystemInfo {
    #[must_use]
    pub fn get() -> Self {
        Self::from(os_info::get())
    }

    fn as_header_value(&self) -> String {
        format!("{};{};{}", self.os_type, self.os_version, self.architecture)
    }

    fn try_from_header_value(header_value: &str) -> Result<Self, DefguardVersionError> {
        let parts = header_value.split(';').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(DefguardVersionError::SystemInfoParseError(header_value.to_owned()));
        }

        Ok(Self {
            os_type: parts[0].to_owned(),
            os_version: parts[1].to_owned(),
            architecture: parts[2].to_owned(),
        })
    }
}

impl From<os_info::Info> for SystemInfo {
    fn from(info: os_info::Info) -> Self {
        Self {
            os_type: info.os_type().to_string(),
            os_version: info.version().to_string(),
            architecture: info.architecture().unwrap_or("?").to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ComponentInfo {
    pub version: Version,
    pub system: SystemInfo,
}

impl ComponentInfo {
    #[must_use]
    pub fn new(version: Version) -> Self {
        let info = os_info::get();
        Self {
            version,
            system: info.into(),
        }
    }

    pub fn from_metadata(metadata: &MetadataMap) -> Option<Self> {
        let Some(version) = metadata.get(VERSION_HEADER) else {
            warn!("Missing version header");
            return None;
        };
        let Some(system) = metadata.get(SYSTEM_INFO_HEADER) else {
            warn!("Missing system info header");
            return None;
        };
        let (Ok(version), Ok(system)) = (version.to_str(), system.to_str()) else {
            warn!("Failed to stringify version or system info header value");
            return None;
        };
        let Ok(version) = Version::from_str(version) else {
            warn!("Failed to parse version: {version}");
            return None;
        };
        let Ok(system) = SystemInfo::try_from_header_value(system) else {
            warn!("Failed to parse system info: {system}");
            return None;
        };

        Some(Self { version, system })
    }
}

#[must_use]
pub fn version_info_from_metadata(metadata: &MetadataMap) -> (Version, String) {
    ComponentInfo::from_metadata(metadata)
        .map_or((Version::new(0, 0, 0), String::from("?")), |info| {
            (info.version, info.system.to_string())
        })
}

#[must_use]
pub fn get_tracing_variables(info: &Option<ComponentInfo>) -> (Version, String) {
    let version = info
        .as_ref()
        .map_or(Version::new(0, 0, 0), |info| info.version.clone());
    let info = info
        .as_ref()
        .map_or(String::from("?"), |info| info.system.to_string());

    (version, info)
}

#[must_use]
pub fn is_version_lower(v1: &Version, v2: &Version) -> bool {
    let (mut v1, mut v2) = (v1.clone(), v2.clone());
    v1.pre = Prerelease::EMPTY;
    v2.pre = Prerelease::EMPTY;
    v1.cmp_precedence(&v2) == Ordering::Less
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_version_comparison() {
        let v1 = Version::parse("1.5.0").unwrap();
        let v2 = Version::parse("1.6.0").unwrap();
        assert!(is_version_lower(&v1, &v2));

        let v1 = Version::parse("1.5.0-alpha1").unwrap();
        let v2 = Version::parse("1.5.0").unwrap();
        assert!(!is_version_lower(&v1, &v2));

        let v1 = Version::parse("1.5.0").unwrap();
        let v2 = Version::parse("1.5.0-alpha1").unwrap();
        assert!(!is_version_lower(&v1, &v2));

        let v1 = Version::parse("1.5.0").unwrap();
        let v2 = Version::parse("1.6.0-rc1").unwrap();
        assert!(is_version_lower(&v1, &v2));

        let v1 = Version::parse("1.5.0-rc1").unwrap();
        let v2 = Version::parse("1.6.0").unwrap();
        assert!(is_version_lower(&v1, &v2));

        let v1 = Version::parse("1.5.0-alpha1+2").unwrap();
        let v2 = Version::parse("1.5.0-alpha2+1").unwrap();
        assert!(!is_version_lower(&v1, &v2));
    }
}
