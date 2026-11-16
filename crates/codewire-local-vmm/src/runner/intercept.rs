//! What a boot intercepts through its TLS front door (#3999), off unless the
//! supervisor switches it on for the VM.
//!
//! The bound names are the front door's own route hosts on 443, so the
//! broker never sends it a host it has no route for. The front door makes
//! the boot's CA in its own memory, constrained to those names, and only the
//! certificate reaches the guest, in the seed.

use codewire_egress_front_door_bridge::RouteTable;
use codewire_egress_policy::intercept::{InterceptBinding, InterceptSet};
use codewire_vmm_guest_probe::EgressCaCertificate;

use super::RunnerError;

/// A boot the egress-intercept switch refuses (#3999). Each is fixed with the
/// switch file, so each has its own code for the user's message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InterceptRefusal {
    #[error(
        "agent interception is switched on (the egress-intercept file in the local VM state root, ~/.codewire/native-v1 by default), but this cw cannot start the TLS front door yet; remove that file to start the VM"
    )]
    FrontDoorUnavailable,
    #[error(
        "this VM checkpoint was taken with agent interception switched off and the switch is now on; the switch applies on a stop and start, not a restore"
    )]
    RestoreSwitchedOn,
    #[error(
        "this VM checkpoint was taken with agent interception switched on and the switch is now off; the switch applies on a stop and start, not a restore"
    )]
    RestoreSwitchedOff,
}

impl InterceptRefusal {
    const ALL: [Self; 3] = [
        Self::FrontDoorUnavailable,
        Self::RestoreSwitchedOn,
        Self::RestoreSwitchedOff,
    ];

    /// The runner error code, one per fix.
    pub fn code(self) -> &'static str {
        match self {
            Self::FrontDoorUnavailable => "intercept_unavailable",
            Self::RestoreSwitchedOn => "restore_interception_switched_on",
            Self::RestoreSwitchedOff => "restore_interception_switched_off",
        }
    }

    /// The refusal a runner error code names, for the supervisor.
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|refusal| refusal.code() == code)
    }

    /// The code of a create that failed with this refusal.
    pub fn create_code(self) -> &'static str {
        match self {
            Self::FrontDoorUnavailable => "create_intercept_unavailable",
            Self::RestoreSwitchedOn => "create_restore_interception_switched_on",
            Self::RestoreSwitchedOff => "create_restore_interception_switched_off",
        }
    }
}

const HTTPS_PORT: u16 = 443;

/// The names a boot binds: none unless `intercept`, else every host the
/// front door routes, on 443.
pub(crate) fn boot_intercepts(intercept: bool) -> InterceptSet {
    if !intercept {
        return InterceptSet::default();
    }
    let routes = RouteTable::defaults();
    let bindings = routes.hosts().into_iter().map(|host| {
        InterceptBinding::new(host, HTTPS_PORT).expect("the front door routes canonical hosts")
    });
    InterceptSet::new(bindings).expect("the front door routes at most MAX_ROUTES hosts")
}

/// The CA certificate the guest trusts this boot, or none when it intercepts
/// nothing. The front door that generates it is not started by this runner
/// yet, so a boot that intercepts is refused rather than started without
/// the CA its agents would need.
pub(super) fn boot_egress_ca(
    intercepts: &InterceptSet,
) -> Result<Option<EgressCaCertificate>, RunnerError> {
    if intercepts.is_empty() {
        return Ok(None);
    }
    Err(InterceptRefusal::FrontDoorUnavailable.into())
}

/// A restore keeps the trust its captured boot set up: the restored guest's
/// workload already runs with that boot's `NODE_EXTRA_CA_CERTS`, or without
/// it. So the switch's state must match the captured boot's; it applies on a
/// stop and start, never on a restore.
#[cfg(target_os = "linux")]
pub(super) fn admit_restored_interception(
    captured: bool,
    intercepts: &InterceptSet,
) -> Result<(), RunnerError> {
    match (captured, intercepts.is_empty()) {
        (true, true) => Err(InterceptRefusal::RestoreSwitchedOff.into()),
        (false, false) => Err(InterceptRefusal::RestoreSwitchedOn.into()),
        (true, false) | (false, true) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_refusal_round_trips_through_its_code() {
        for refusal in InterceptRefusal::ALL {
            assert_eq!(InterceptRefusal::from_code(refusal.code()), Some(refusal));
            assert_eq!(refusal.create_code(), format!("create_{}", refusal.code()));
        }
        assert_eq!(InterceptRefusal::from_code("prepare_failed"), None);
    }

    #[test]
    fn a_boot_intercepts_nothing_unless_switched_on() {
        assert!(boot_intercepts(false).is_empty());
        assert!(matches!(boot_egress_ca(&boot_intercepts(false)), Ok(None)));
    }

    #[test]
    fn switched_on_it_binds_every_front_door_host_on_443() {
        let intercepts = boot_intercepts(true);
        for host in ["api.anthropic.com", "api.openai.com", "chatgpt.com"] {
            assert!(intercepts.binds(host, 443), "{host}");
            assert!(!intercepts.binds(host, 80), "{host}");
        }
        assert_eq!(intercepts.len(), RouteTable::defaults().hosts().len());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_restore_must_match_the_captured_boots_interception() {
        assert!(admit_restored_interception(false, &boot_intercepts(false)).is_ok());
        assert!(admit_restored_interception(true, &boot_intercepts(true)).is_ok());
        assert!(matches!(
            admit_restored_interception(true, &boot_intercepts(false)),
            Err(RunnerError::Interception(
                InterceptRefusal::RestoreSwitchedOff
            ))
        ));
        assert!(matches!(
            admit_restored_interception(false, &boot_intercepts(true)),
            Err(RunnerError::Interception(
                InterceptRefusal::RestoreSwitchedOn
            ))
        ));
    }

    #[test]
    fn switched_on_without_a_front_door_the_boot_is_refused() {
        let error = boot_egress_ca(&boot_intercepts(true)).unwrap_err();
        assert!(matches!(
            error,
            RunnerError::Interception(InterceptRefusal::FrontDoorUnavailable)
        ));
        assert!(
            error
                .to_string()
                .contains("cannot start the TLS front door yet"),
            "{error}"
        );
    }
}
