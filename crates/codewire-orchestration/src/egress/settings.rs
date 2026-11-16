//! The deployment settings for hosted egress (#4000). Both are read once at
//! startup; a value that does not parse fails startup.

/// Serves `EgressService` when `true`. Off unless a deployment turns it on.
pub const SWITCH: &str = "CODEWIRE_HOSTED_EGRESS_ENABLED";
/// Destinations every broker-mode sandbox would reach whatever its policy.
/// No deployment sets one: a broker-mode daemon reaches the platform's own
/// services inside the cluster (decided 2026-11-15 on #4000). Nothing
/// enforces an entry yet, so while hosted egress is on a non-empty list stops
/// startup rather than look configured and do nothing.
pub const PLATFORM_ALLOWS: &str = "CODEWIRE_EGRESS_PLATFORM_ALLOWS";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressSettings {
    pub enabled: bool,
}

impl EgressSettings {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_values(
            crate::confidential_storage::env_setting(SWITCH)?.as_deref(),
            crate::confidential_storage::env_setting(PLATFORM_ALLOWS)?.as_deref(),
        )
    }

    fn from_values(enabled: Option<&str>, platform: Option<&str>) -> anyhow::Result<Self> {
        let enabled = crate::confidential_storage::parse_bool(SWITCH, enabled, false)?;
        if !enabled {
            // The list is read only where it is used: a deployment with hosted
            // egress off never fails on it.
            return Ok(Self::default());
        }
        let named = platform
            .unwrap_or_default()
            .split(',')
            .any(|entry| !entry.trim().is_empty());
        if named {
            anyhow::bail!(
                "{PLATFORM_ALLOWS} names a destination, but platform allows are not enforced yet; leave it unset"
            );
        }
        Ok(Self { enabled })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_by_default_and_on_with_no_platform_allow() {
        assert_eq!(
            EgressSettings::from_values(None, None).unwrap(),
            EgressSettings::default()
        );
        for empty in [None, Some(""), Some(" , ")] {
            assert_eq!(
                EgressSettings::from_values(Some("true"), empty).unwrap(),
                EgressSettings { enabled: true },
                "{empty:?}"
            );
        }
        assert!(EgressSettings::from_values(Some("maybe"), None).is_err());
    }

    #[test]
    fn a_platform_allow_stops_startup_while_nothing_enforces_it() {
        for named in [
            "control.example.com:443",
            " , derp.example.com:443",
            "no-port",
        ] {
            assert!(
                EgressSettings::from_values(Some("true"), Some(named)).is_err(),
                "{named}"
            );
        }
    }

    #[test]
    fn the_list_is_not_read_while_hosted_egress_is_off() {
        assert_eq!(
            EgressSettings::from_values(Some("false"), Some("control.example.com:443")).unwrap(),
            EgressSettings::default()
        );
    }
}
