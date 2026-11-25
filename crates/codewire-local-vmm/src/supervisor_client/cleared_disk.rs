//! A boot that may intercept, through a supervisor too old to clear the VM's
//! state disk first (#6277; docs/dev/SECRETS-AND-CREDENTIALS.md, "Clearing a
//! local VM's state disk").
//!
//! A supervisor below protocol 27 ignores `start_with_uncleared_disk` and
//! never clears, and a cw update replaces it only once no VM runs. So this cw
//! refuses a start, restore or fork that may intercept through one, and says
//! how to have it replaced. A boot with no credential profile or secrets has
//! no local credential broker, so it never intercepts and is never refused.

use crate::supervisor_config::SupervisorFeature;

/// The lifecycle command a refusal names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnclearedBootKind {
    Start,
    /// `cw restart`, which takes no override: its way out is a stop, then a
    /// start with it.
    Restart,
    Restore,
    Fork,
}

impl UnclearedBootKind {
    fn verb(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Restart => "restart",
            Self::Restore => "restore",
            Self::Fork => "fork",
        }
    }
}

/// The boot being admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnclearedBoot {
    pub kind: UnclearedBootKind,
    /// It has a credential profile or secrets, so a local credential broker,
    /// so it may intercept.
    pub may_intercept: bool,
    /// Its credentials come from the platform.
    pub platform: bool,
    /// This one command passed `--start-with-uncleared-disk`.
    pub start_with_uncleared_disk: bool,
}

/// How a boot may go ahead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnclearedBootAdmission {
    /// The supervisor clears the disk itself, or the boot can't intercept.
    Admitted,
    /// An older supervisor, passed by the override: the command says so.
    Overridden { protocol: u32 },
}

/// A boot that may intercept, refused because the supervisor that would
/// start it doesn't clear the VM's disk first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OlderSupervisorRefusal {
    pub protocol: u32,
    pub kind: UnclearedBootKind,
    pub platform: bool,
}

impl std::fmt::Display for OlderSupervisorRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the local VM supervisor running your VMs is an older one (protocol {}), which doesn't clear a VM's disk of earlier sign-ins before agent interception starts; stop the local VMs it serves (`cw --local ls`, then `cw --local stop NAME`) so this cw replaces it, then {} this again",
            self.protocol,
            self.kind.verb()
        )?;
        match (self.platform, self.kind) {
            (true, _) => Ok(()),
            (false, UnclearedBootKind::Restart) => f.write_str(
                ", or sign the provider out, stop it, and start it with --start-with-uncleared-disk",
            ),
            (false, _) => {
                f.write_str(", or sign the provider out and pass --start-with-uncleared-disk")
            }
        }
    }
}

impl std::error::Error for OlderSupervisorRefusal {}

/// Whether `boot` may go ahead through a supervisor of `protocol`.
pub fn admit_uncleared_boot(
    protocol: u32,
    boot: UnclearedBoot,
) -> Result<UnclearedBootAdmission, OlderSupervisorRefusal> {
    if protocol >= SupervisorFeature::ClearedStateDisk.since() || !boot.may_intercept {
        return Ok(UnclearedBootAdmission::Admitted);
    }
    if boot.start_with_uncleared_disk && !boot.platform {
        return Ok(UnclearedBootAdmission::Overridden { protocol });
    }
    Err(OlderSupervisorRefusal {
        protocol,
        kind: boot.kind,
        platform: boot.platform,
    })
}

impl super::NativeSupervisorClient {
    /// [`admit_uncleared_boot`] for the supervisor this client admitted.
    pub fn admit_uncleared_boot(
        &self,
        boot: UnclearedBoot,
    ) -> Result<UnclearedBootAdmission, OlderSupervisorRefusal> {
        admit_uncleared_boot(self.protocol(), boot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot(kind: UnclearedBootKind) -> UnclearedBoot {
        UnclearedBoot {
            kind,
            may_intercept: true,
            platform: false,
            start_with_uncleared_disk: false,
        }
    }

    const KINDS: [UnclearedBootKind; 4] = [
        UnclearedBootKind::Start,
        UnclearedBootKind::Restart,
        UnclearedBootKind::Restore,
        UnclearedBootKind::Fork,
    ];

    #[test]
    fn a_protocol_26_supervisor_refuses_a_boot_that_may_intercept_and_names_the_way_out() {
        for kind in KINDS {
            let refusal = admit_uncleared_boot(26, boot(kind)).unwrap_err();
            let text = refusal.to_string();
            assert!(text.contains("protocol 26"), "{text}");
            assert!(text.contains("cw --local stop NAME"), "{text}");
            assert!(
                text.contains(&format!("then {} this again", kind.verb())),
                "{text}"
            );
            assert!(text.contains("--start-with-uncleared-disk"), "{text}");
            // Restart takes no override, so it points to a stop and a start.
            assert_eq!(
                text.contains("stop it, and start it with --start-with-uncleared-disk"),
                kind == UnclearedBootKind::Restart,
                "{text}"
            );
        }
    }

    #[test]
    fn the_override_passes_a_protocol_26_supervisor_once_and_never_on_the_platform() {
        for kind in KINDS {
            let overridden = UnclearedBoot {
                start_with_uncleared_disk: true,
                ..boot(kind)
            };
            assert_eq!(
                admit_uncleared_boot(26, overridden),
                Ok(UnclearedBootAdmission::Overridden { protocol: 26 })
            );
            let platform = UnclearedBoot {
                platform: true,
                ..overridden
            };
            let text = admit_uncleared_boot(26, platform).unwrap_err().to_string();
            assert!(!text.contains("--start-with-uncleared-disk"), "{text}");
        }
    }

    #[test]
    fn a_current_supervisor_or_a_boot_that_cannot_intercept_is_admitted() {
        for kind in KINDS {
            assert_eq!(
                admit_uncleared_boot(27, boot(kind)),
                Ok(UnclearedBootAdmission::Admitted)
            );
            let unbrokered = UnclearedBoot {
                may_intercept: false,
                ..boot(kind)
            };
            assert_eq!(
                admit_uncleared_boot(26, unbrokered),
                Ok(UnclearedBootAdmission::Admitted)
            );
        }
    }
}
