//! `cw __hosted-egress-tun --owner-uid UID`: a hosted Sandbox's init
//! container makes the guest's egress path before the workload starts (#4000;
//! `designs/hosted-egress.md`, "The Sandbox side").
//!
//! It makes `/dev/net/tun` afresh in the Pod's memory-backed `egress-devnet`
//! volume, since a Kata container has none, and checks the opened node is the
//! TUN (`codewire_vmm_guest_probe::tun`). It then creates the persistent TUN
//! `cwegress0`, owned by the workspace user so the daemon attaches it without
//! privilege, then makes the routing and reads
//! it back (`codewire_network_session::hosted::routing::configure`: IPv6 off,
//! the TUN's address and link, the Pod table and its three rules, and the main
//! default into the TUN). It fails on the first error, so a wrong rule is
//! never a silent success.
//!
//! It resolves no names and takes nothing but the owner, so its exact command
//! is the whole of what the Pod's admission checks. A second run changes
//! nothing.

use std::ffi::OsString;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HostedTunError {
    #[error("usage: cw __hosted-egress-tun --owner-uid UID")]
    Usage,
    #[error("create the egress TUN")]
    Tun(#[source] codewire_vmm_guest_probe::tun::TunError),
    #[error("make the egress routing")]
    Routing(#[source] codewire_network_session::hosted::routing::RoutingError),
}

/// `error` and its causes, for the init container's log.
pub fn describe(error: &HostedTunError) -> String {
    let mut text = error.to_string();
    let mut cause = std::error::Error::source(error);
    while let Some(next) = cause {
        text.push_str(": ");
        text.push_str(&next.to_string());
        cause = next.source();
    }
    text
}

/// Run the command from its whole argument list, program name first.
pub fn run_from<I, T>(args: I) -> Result<(), HostedTunError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let owner = owner_from(args)?;
    codewire_vmm_guest_probe::tun::create_persistent(
        codewire_network_session::hosted::HOSTED_TUN_NAME,
        owner,
    )
    .map_err(HostedTunError::Tun)?;
    codewire_network_session::hosted::routing::configure().map_err(HostedTunError::Routing)
}

/// The owner from exactly `cw __hosted-egress-tun --owner-uid UID`. Root is
/// refused: the TUN belongs to the unprivileged workspace user.
fn owner_from<I, T>(args: I) -> Result<u32, HostedTunError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let [_, command, flag, uid] = args.as_slice() else {
        return Err(HostedTunError::Usage);
    };
    if command != "__hosted-egress-tun" || flag != "--owner-uid" {
        return Err(HostedTunError::Usage);
    }
    uid.to_str()
        .filter(|uid| !uid.is_empty() && uid.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|uid| uid.parse().ok())
        .filter(|uid| *uid != 0)
        .ok_or(HostedTunError::Usage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(args: &[&str]) -> Result<u32, HostedTunError> {
        owner_from(args.iter().copied())
    }

    #[test]
    fn exactly_the_owner_and_nothing_else() {
        assert_eq!(
            owner(&["cw", "__hosted-egress-tun", "--owner-uid", "1000"]).unwrap(),
            1000
        );
        for args in [
            &["cw", "__hosted-egress-tun"][..],
            &["cw", "__hosted-egress-tun", "--owner-uid"],
            &["cw", "__hosted-egress-tun", "--owner-uid", "1000", "extra"],
            &["cw", "__hosted-egress-tun", "--owner", "1000"],
            &["cw", "__other", "--owner-uid", "1000"],
            &["cw", "__hosted-egress-tun", "--owner-uid", "-1"],
            &["cw", "__hosted-egress-tun", "--owner-uid", "+1000"],
            &["cw", "__hosted-egress-tun", "--owner-uid", "1000x"],
            &["cw", "__hosted-egress-tun", "--owner-uid", ""],
            &["cw", "__hosted-egress-tun", "--owner-uid", "4294967296"],
            &["cw", "__hosted-egress-tun", "--owner-uid", "0"],
            &["cw", "__hosted-egress-tun", "--owner-uid", "00"],
        ] {
            assert!(
                matches!(owner(args), Err(HostedTunError::Usage)),
                "{args:?}"
            );
        }
    }
}
