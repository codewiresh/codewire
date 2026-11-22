//! Confidential Sandboxes held while hosted egress is on (#4000).
//!
//! A confidential guest's data hub resolves the in-cluster key broker before
//! its first in-guest image pull. Broker mode gives the Pod only the broker's
//! TUN as its nameserver, which doesn't exist yet at that point, and the
//! broker refuses cluster names anyway, so the guest never boots. Until it
//! can, every action that would boot one is refused with the switch on,
//! before anything is recorded, rendered or changed: the API refuses a
//! create, and a start, setup retry, resize or repair; the worker refuses
//! every confidential runtime it authorizes, for any path the API missed. The
//! tier is orchestration's own record of the environment, or at create the
//! request's, which is what create records. A warm pool never holds a
//! confidential member, whatever the switch
//! (`sandbox::warm_pool::validate_pool_template_opts`).
//!
//! This module and every use of it go when confidential guests reach the key
//! broker and the registry by the fixed route (private-docs design
//! `sandbox-registry-access`, step 7; #4000).

use std::borrow::Cow;

use axum::http::StatusCode;
use codewire_server_core::AppError;

use crate::runtime::Isolation;
use crate::worker::create::SandboxWorkerCfg;

/// A confidential environment refused while hosted egress is on. The message
/// is what the user reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "Confidential sandboxes are unavailable on this deployment while its network change completes."
)]
pub struct ConfidentialHeld;

/// The API's code for the refusal, beside confidential storage's own.
pub const CODE: &str = "CONFIDENTIAL_UNAVAILABLE";

impl From<ConfidentialHeld> for AppError {
    fn from(held: ConfidentialHeld) -> Self {
        AppError::Coded {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: CODE,
            detail: Cow::Owned(held.to_string()),
        }
    }
}

/// Refuses a confidential environment while `cfg` has hosted egress on.
pub fn check(cfg: &SandboxWorkerCfg, isolation: Isolation) -> Result<(), ConfidentialHeld> {
    if cfg.hosted_egress.is_some() && isolation == Isolation::Confidential {
        return Err(ConfidentialHeld);
    }
    Ok(())
}

/// [`check`] for a tier as an environment's row or a create names it. With
/// hosted egress on, a value that is no tier is held too, so the hold never
/// depends on another check refusing it; with it off, the tier's own parse
/// decides, as before.
pub fn check_tier(cfg: &SandboxWorkerCfg, tier: &str) -> Result<(), ConfidentialHeld> {
    match Isolation::of_tier(tier) {
        Ok(isolation) => check(cfg, isolation),
        Err(_) if cfg.hosted_egress.is_some() => Err(ConfidentialHeld),
        Err(_) => Ok(()),
    }
}

/// A deployment's configuration with hosted egress on or off.
#[cfg(test)]
pub(crate) fn test_cfg(hosted_egress: bool) -> SandboxWorkerCfg {
    use crate::sandbox::template::{GatewayPeer, HostedEgressTemplate};
    SandboxWorkerCfg {
        hosted_egress: hosted_egress.then(|| HostedEgressTemplate {
            stream_addr: "10.44.0.89:8089".into(),
            binding_addr: "10.44.0.87:8087".into(),
            fence_revision: "4".into(),
            gateway: GatewayPeer {
                namespace: "gateway-proxies".into(),
                gateway_name: "public".into(),
                gateway_namespace: "gateway".into(),
                port: 10443,
            },
            derp_tls_port: 8443,
            gateway_addr: "10.44.0.43:443".into(),
            derp_addr: "derp.example.test=10.44.0.84:8443".into(),
            cluster_dns_ip: "10.44.0.10".into(),
        }),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_confidential_environment_is_held_and_only_with_the_switch_on() {
        let (on, off) = (test_cfg(true), test_cfg(false));
        assert_eq!(check(&on, Isolation::Confidential), Err(ConfidentialHeld));
        assert_eq!(check(&on, Isolation::Standard), Ok(()));
        assert_eq!(check(&off, Isolation::Confidential), Ok(()));
        assert_eq!(check(&off, Isolation::Standard), Ok(()));
        assert_eq!(check_tier(&on, "confidential"), Err(ConfidentialHeld));
        assert_eq!(check_tier(&on, "standard"), Ok(()));
        assert_eq!(check_tier(&off, "confidential"), Ok(()));
        for unknown in ["", "Confidential", "secret"] {
            assert_eq!(check_tier(&on, unknown), Err(ConfidentialHeld));
            assert_eq!(check_tier(&off, unknown), Ok(()));
        }
    }

    #[test]
    fn the_user_reads_one_plain_sentence_with_a_code_to_branch_on() {
        let AppError::Coded {
            status,
            code,
            detail,
        } = AppError::from(ConfidentialHeld)
        else {
            panic!("not a coded refusal");
        };
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "CONFIDENTIAL_UNAVAILABLE");
        assert_eq!(
            detail,
            "Confidential sandboxes are unavailable on this deployment while its network change completes."
        );
    }
}
