//! The Hosts page's reads (#3609): the organization's hosts through
//! `HostService`, as the signed-in member, shaped for the page.

use axum::http::HeaderValue;
use codewire_proto::codewire::v1::{
    Host, HostPlatform, HostServiceClient, HostState, ListHostsRequest,
};
use connectrpc::{ConnectError, client::ClientConfig};

use crate::{organization_connect::past_time, state::AppState, transport::BrowserTransport};

/// One host as the page shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostRow {
    pub(crate) id: String,
    pub(crate) name: String,
    /// The owner's name, or their user ID when they are no longer a member.
    pub(crate) owner: String,
    pub(crate) platform: &'static str,
    /// Online, Offline or Revoked.
    pub(crate) state: &'static str,
    /// The badge tone for the state: `success`, or empty for neutral.
    pub(crate) tone: &'static str,
    /// "2m ago", or "Never" when the host has not connected.
    pub(crate) last_seen: String,
    /// What the host offers, such as "Up to 2 VMs · 8 GiB memory".
    pub(crate) provides: String,
}

fn transport(state: &AppState, cookie: HeaderValue) -> BrowserTransport {
    BrowserTransport {
        http: state.http.clone(),
        cookie: Some(cookie),
        origin: None,
    }
}

fn client_config(state: &AppState) -> ClientConfig {
    ClientConfig::new(state.api_origin.clone())
        .with_default_timeout(std::time::Duration::from_secs(10))
}

/// The organization's hosts, live ones first, then by name. `owner_name`
/// names a user ID, or returns None for someone no longer a member.
pub(crate) async fn hosts(
    state: &AppState,
    cookie: HeaderValue,
    org_id: &str,
    owner_name: impl Fn(&str) -> Option<String>,
) -> Result<Vec<HostRow>, ConnectError> {
    let response = HostServiceClient::new(transport(state, cookie), client_config(state))
        .list_hosts(ListHostsRequest {
            org_id: org_id.to_owned(),
            ..Default::default()
        })
        .await?
        .into_owned();
    let mut rows: Vec<HostRow> = response
        .hosts
        .iter()
        .map(|host| host_row(host, &owner_name))
        .collect();
    rows.sort_by(|a, b| (a.state == "Revoked", &a.name).cmp(&(b.state == "Revoked", &b.name)));
    Ok(rows)
}

pub(crate) fn host_row(host: &Host, owner_name: impl Fn(&str) -> Option<String>) -> HostRow {
    let (state, tone) = match host.state.as_known() {
        Some(HostState::HOST_STATE_ONLINE) => ("Online", "success"),
        Some(HostState::HOST_STATE_REVOKED) => ("Revoked", ""),
        _ => ("Offline", ""),
    };
    let platform = match host.platform.as_known() {
        Some(HostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM) => "Linux x86-64",
        Some(HostPlatform::HOST_PLATFORM_DARWIN_ARM64_VZ) => "macOS Apple silicon",
        _ => "Unknown",
    };
    let last_seen = host
        .last_seen_at
        .as_option()
        .map_or_else(|| "Never".to_owned(), |seen| past_time(seen.seconds));
    HostRow {
        id: host.id.clone(),
        name: host.name.clone(),
        owner: owner_name(&host.owner_user_id).unwrap_or_else(|| host.owner_user_id.clone()),
        platform,
        state,
        tone,
        last_seen,
        provides: provides(host),
    }
}

fn provides(host: &Host) -> String {
    let limits = host.limits.as_option().filter(|_| host.provide);
    let Some(limits) = limits else {
        return "Not offering VMs".to_owned();
    };
    let mut parts = vec![format!(
        "Up to {} VM{}",
        limits.max_vms,
        if limits.max_vms == 1 { "" } else { "s" }
    )];
    if let Some(vcpus) = limits.max_vcpus {
        parts.push(format!("{vcpus} vCPU"));
    }
    if let Some(memory) = limits.max_memory_mib {
        parts.push(format!("{} memory", size(memory)));
    }
    if let Some(disk) = limits.max_disk_gib {
        parts.push(format!("{} disk", size(disk * 1024)));
    }
    parts.join(" · ")
}

/// A size in MiB as GiB or TiB when whole, else MiB.
fn size(mib: u64) -> String {
    if mib.is_multiple_of(1024 * 1024) {
        format!("{} TiB", mib / (1024 * 1024))
    } else if mib.is_multiple_of(1024) {
        format!("{} GiB", mib / 1024)
    } else {
        format!("{mib} MiB")
    }
}

#[cfg(test)]
mod tests {
    use codewire_proto::codewire::v1::HostLimits;

    use super::*;

    fn host(state: HostState, provide: bool) -> Host {
        Host {
            id: "host-1".into(),
            name: "build-box".into(),
            owner_user_id: "user-1".into(),
            platform: HostPlatform::HOST_PLATFORM_LINUX_X86_64_KVM.into(),
            state: state.into(),
            provide,
            limits: Some(HostLimits {
                max_vms: 2,
                max_memory_mib: Some(8192),
                max_disk_gib: Some(1024),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_row_names_state_platform_owner_and_what_it_offers() {
        let row = host_row(&host(HostState::HOST_STATE_ONLINE, true), |id| {
            (id == "user-1").then(|| "Ada".to_owned())
        });
        assert_eq!(row.state, "Online");
        assert_eq!(row.tone, "success");
        assert_eq!(row.platform, "Linux x86-64");
        assert_eq!(row.owner, "Ada");
        assert_eq!(row.last_seen, "Never");
        assert_eq!(row.provides, "Up to 2 VMs · 8 GiB memory · 1 TiB disk");
    }

    #[test]
    fn a_host_not_providing_says_so_and_a_departed_owner_shows_their_id() {
        let row = host_row(&host(HostState::HOST_STATE_REVOKED, false), |_| None);
        assert_eq!(row.state, "Revoked");
        assert_eq!(row.tone, "");
        assert_eq!(row.owner, "user-1");
        assert_eq!(row.provides, "Not offering VMs");
        let offline = host_row(&host(HostState::HOST_STATE_OFFLINE, true), |_| None);
        assert_eq!(offline.state, "Offline");
    }

    #[test]
    fn sizes_read_in_whole_units() {
        assert_eq!(size(512), "512 MiB");
        assert_eq!(size(8192), "8 GiB");
        assert_eq!(size(1024 * 1024), "1 TiB");
        assert_eq!(size(1536), "1536 MiB");
    }
}
