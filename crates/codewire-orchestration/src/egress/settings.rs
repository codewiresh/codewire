//! The deployment settings for hosted egress (#4000). Both are read once at
//! startup; a value that does not parse fails startup.

use super::service::PlatformDestination;

/// Serves `EgressService` when `true`. Off unless a deployment turns it on.
pub const SWITCH: &str = "CODEWIRE_HOSTED_EGRESS_ENABLED";
/// Comma-separated `host:port` destinations every broker-mode sandbox may
/// reach whatever its policy: the control plane, DERP and Mesh. Only this
/// setting adds them; no user policy can.
pub const PLATFORM_ALLOWS: &str = "CODEWIRE_EGRESS_PLATFORM_ALLOWS";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EgressSettings {
    pub enabled: bool,
    pub platform: Vec<PlatformDestination>,
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
        let platform = platform
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(parse_destination)
            .collect::<anyhow::Result<Vec<_>>>()?;
        if platform.is_empty() {
            anyhow::bail!("{SWITCH} is on but {PLATFORM_ALLOWS} names no destination");
        }
        Ok(Self { enabled, platform })
    }
}

fn parse_destination(entry: &str) -> anyhow::Result<PlatformDestination> {
    let (host, port) = entry
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("{PLATFORM_ALLOWS}: {entry:?} is not host:port"))?;
    let port: u16 = port
        .parse()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| anyhow::anyhow!("{PLATFORM_ALLOWS}: {entry:?} has no valid port"))?;
    let host = host.trim().to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-');
    if !valid {
        anyhow::bail!("{PLATFORM_ALLOWS}: {entry:?} has no valid host name");
    }
    Ok(PlatformDestination { host, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_by_default_and_on_only_with_a_destination() {
        assert_eq!(
            EgressSettings::from_values(None, None).unwrap(),
            EgressSettings::default()
        );
        assert!(EgressSettings::from_values(Some("true"), None).is_err());
        assert!(EgressSettings::from_values(Some("maybe"), Some("a.example:443")).is_err());
    }

    #[test]
    fn destinations_parse_as_host_and_port() {
        let settings = EgressSettings::from_values(
            Some("true"),
            Some(" codewire-dev.sh:443, DERP.codewire-dev.sh:443 ,"),
        )
        .unwrap();
        assert!(settings.enabled);
        assert_eq!(
            settings.platform,
            [
                PlatformDestination {
                    host: "codewire-dev.sh".into(),
                    port: 443
                },
                PlatformDestination {
                    host: "derp.codewire-dev.sh".into(),
                    port: 443
                },
            ]
        );
    }

    #[test]
    fn the_list_is_not_read_while_hosted_egress_is_off() {
        assert_eq!(
            EgressSettings::from_values(Some("false"), Some("no-port")).unwrap(),
            EgressSettings::default()
        );
    }

    #[test]
    fn a_malformed_destination_fails_startup() {
        for bad in [
            "no-port",
            "host:0",
            "host:99999",
            ":443",
            "a b:443",
            "10.0.0.0/8:443",
        ] {
            assert!(
                EgressSettings::from_values(Some("true"), Some(bad)).is_err(),
                "{bad}"
            );
        }
    }
}
