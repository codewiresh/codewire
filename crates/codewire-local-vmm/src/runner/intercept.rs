//! What a boot intercepts through its TLS front door (#3999), off unless the
//! supervisor switches it on for the VM.
//!
//! The bound names are the front door's own route hosts on 443, so the
//! broker never sends it a host it has no route for. The front door makes
//! the boot's CA in its own memory, constrained to those names, and only the
//! certificate reaches the guest, in the seed.

use codewire_access::CredentialPlaceholder;
use codewire_egress_front_door_bridge::RouteTable;
use codewire_egress_policy::intercept::{InterceptBinding, InterceptSet};
use codewire_vmm_guest_probe::{EgressCaCertificate, PlaceholderSlot, SeedPlaceholders};

use super::RunnerError;
#[cfg(target_os = "linux")]
use super::front_door::{FrontDoorProcess, RunningFrontDoor};

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

/// The length of each boot secret.
pub(crate) const BOOT_SECRET_BYTES: usize = 32;

/// An intercepting boot's secrets (#3999): random, minted when its front
/// door starts, and held only in the runner's memory. They leave it only
/// through `GetBootSecrets`, never in the seed, the state file, the published
/// generation access or a log. The pairing secret is what each credential
/// broker presents on the pairing socket, so the daemon token, which the
/// guest knows, never pairs.
pub(crate) struct BootSecrets {
    pairing: zeroize::Zeroizing<[u8; BOOT_SECRET_BYTES]>,
}

impl BootSecrets {
    #[cfg_attr(
        not(target_os = "linux"),
        expect(
            dead_code,
            reason = "only a Linux boot starts a front door to pair with (#3999)"
        )
    )]
    pub(crate) fn mint() -> Self {
        use rand::RngCore as _;
        let mut pairing = zeroize::Zeroizing::new([0_u8; BOOT_SECRET_BYTES]);
        rand::rngs::OsRng.fill_bytes(pairing.as_mut());
        Self { pairing }
    }

    #[cfg_attr(
        not(target_os = "linux"),
        expect(
            dead_code,
            reason = "only a Linux boot starts a front door to pair with (#3999)"
        )
    )]
    pub(crate) fn pairing(&self) -> &[u8] {
        self.pairing.as_ref()
    }

    /// Each secret with its purpose, for the supervisor.
    pub(crate) fn to_proto(&self) -> Vec<crate::control::v1::BootSecret> {
        vec![crate::control::v1::BootSecret {
            purpose: crate::control::v1::BootSecretPurpose::FrontDoorPairing as i32,
            value: self.pairing.to_vec(),
        }]
    }
}

impl std::fmt::Debug for BootSecrets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BootSecrets([REDACTED])")
    }
}

impl super::RunningVm {
    /// The boot's secrets when it intercepts; none otherwise.
    pub(crate) fn boot_secrets(&self) -> Option<&BootSecrets> {
        #[cfg(target_os = "linux")]
        return self.front_door.as_ref().map(RunningFrontDoor::secrets);
        #[cfg(not(target_os = "linux"))]
        None
    }
}

/// The stage at which a boot's front door failed. Every one fails the boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrontDoorFailure {
    #[error("front door process spawn failed")]
    Spawn,
    #[error("front door did not report its CA before the startup deadline")]
    StartTimeout,
    #[error("front door startup failed")]
    Startup,
    #[error("front door reported a CA certificate the seed cannot carry")]
    Certificate,
    #[error("front door sockets could not be passed")]
    Sockets,
    #[error("wait for front door failed")]
    Wait,
}

impl FrontDoorFailure {
    /// The stable code the smoke harness reports.
    pub fn code(self) -> &'static str {
        match self {
            Self::Spawn => "front-door-spawn",
            Self::StartTimeout => "front-door-start-timeout",
            Self::Startup => "front-door-startup",
            Self::Certificate => "front-door-certificate",
            Self::Sockets => "front-door-sockets",
            Self::Wait => "front-door-wait",
        }
    }

    /// The runner error code the supervisor sees.
    pub(crate) fn runner_error_code(self) -> &'static str {
        match self {
            Self::Spawn => "front_door_spawn",
            Self::StartTimeout => "front_door_start_timeout",
            Self::Startup => "front_door_startup",
            Self::Certificate => "front_door_certificate",
            Self::Sockets => "front_door_sockets",
            Self::Wait => "front_door_wait",
        }
    }
}

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

/// The boot's front door and the CA certificate the guest trusts, or
/// neither when it intercepts nothing. The front door starts here, before
/// the seed is written, because the certificate goes into the seed; any
/// failure fails the boot, so no guest boots without the CA its agents need.
#[cfg(target_os = "linux")]
pub(super) async fn boot_front_door(
    request: &super::CreateVmRequest,
    paths: &crate::state::VmPaths,
) -> Result<Option<(RunningFrontDoor, EgressCaCertificate)>, RunnerError> {
    if request.intercepts.is_empty() {
        return Ok(None);
    }
    // The front door is a role of this same cw, as the network stack is.
    let executable = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| FrontDoorFailure::Spawn)?;
    let process = FrontDoorProcess::spawn(
        &executable,
        &paths.vm_dir,
        request.vm_id,
        request.generation,
        &request.intercepts,
    )
    .await?;
    let certificate = EgressCaCertificate::from_der(process.ca_certificate_der().to_vec())
        .map_err(|_| FrontDoorFailure::Certificate)?;
    let front_door =
        RunningFrontDoor::listen(process, &paths.front_door_socket, BootSecrets::mint())?;
    Ok(Some((front_door, certificate)))
}

/// Darwin has no front door yet, so a boot that intercepts is refused rather
/// than started without the CA its agents would need.
#[cfg(not(target_os = "linux"))]
pub(super) fn boot_egress_ca(
    intercepts: &InterceptSet,
) -> Result<Option<EgressCaCertificate>, RunnerError> {
    if intercepts.is_empty() {
        return Ok(None);
    }
    Err(InterceptRefusal::FrontDoorUnavailable.into())
}

/// The seed's placeholders, from the supervisor's request: none unless the
/// boot intercepts, and then each a known Anthropic form at most once with a
/// well-formed placeholder. Anything else is refused.
pub(crate) fn boot_placeholders(
    intercept: bool,
    entries: Vec<crate::control::v1::SeedCredentialPlaceholder>,
) -> Result<SeedPlaceholders, RunnerError> {
    if !intercept && !entries.is_empty() {
        return Err(RunnerError::InvalidRequest);
    }
    let entries = entries
        .into_iter()
        .map(|entry| {
            let slot = match entry.slot {
                1 => PlaceholderSlot::AnthropicApiKey,
                2 => PlaceholderSlot::AnthropicSubscriptionToken,
                _ => return Err(RunnerError::InvalidRequest),
            };
            let placeholder = CredentialPlaceholder::parse(&entry.placeholder)
                .map_err(|_| RunnerError::InvalidRequest)?;
            Ok((slot, placeholder))
        })
        .collect::<Result<Vec<_>, _>>()?;
    SeedPlaceholders::new(entries).map_err(|_| RunnerError::InvalidRequest)
}

/// A restore across a change of the switch is refused: the restored
/// workload runs with or without `NODE_EXTRA_CA_CERTS` as its captured boot
/// did, so the switch applies on a stop and start. With the switch on at
/// both ends the restored boot starts its own front door, whose CA goes in
/// its seed, and the guest replaces its trust files from that seed before
/// the workload thaws. Placeholders follow the binding, so they are kept;
/// an agent running at the checkpoint loaded the captured CA and fails its
/// intercepted requests until it restarts (#3999).
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

    /// A VM's layout under a private state root, as `prepare()` makes it.
    #[cfg(target_os = "linux")]
    fn vm_paths(
        request: &super::super::CreateVmRequest,
    ) -> (tempfile::TempDir, crate::state::VmPaths) {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let state = directory.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = crate::host::path::PrivateRoot::open(&state).unwrap();
        let paths = crate::state::VmPaths::create(&root, request.vm_id).unwrap();
        (directory, paths)
    }

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

    #[cfg(not(target_os = "linux"))]
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
                .contains("cannot start the TLS front door on macOS yet"),
            "{error}"
        );
    }

    fn entry(slot: u32, placeholder: &str) -> crate::control::v1::SeedCredentialPlaceholder {
        crate::control::v1::SeedCredentialPlaceholder {
            slot,
            placeholder: placeholder.into(),
        }
    }

    fn placeholder() -> String {
        format!("cwp1_{}A", "D".repeat(42))
    }

    /// The seed's placeholders come only with interception, each a known
    /// Anthropic form at most once with a well-formed value.
    #[test]
    fn boot_placeholders_are_refused_unless_well_formed_and_intercepted() {
        let decoded = boot_placeholders(true, vec![entry(1, &placeholder())]).unwrap();
        let [(slot, value)] = decoded.entries() else {
            panic!("one placeholder");
        };
        assert_eq!(*slot, PlaceholderSlot::AnthropicApiKey);
        assert_eq!(value.as_str(), placeholder());
        assert!(boot_placeholders(false, Vec::new()).unwrap().is_empty());
        for (intercept, entries) in [
            (false, vec![entry(1, &placeholder())]),
            (true, vec![entry(3, &placeholder())]),
            (true, vec![entry(1, "codewire-managed")]),
            (
                true,
                vec![entry(1, &placeholder()), entry(1, &placeholder())],
            ),
        ] {
            assert!(
                matches!(
                    boot_placeholders(intercept, entries),
                    Err(RunnerError::InvalidRequest)
                ),
                "{intercept}"
            );
        }
    }

    /// Off, the default: no front door is started and the seed carries no
    /// CA.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_boot_that_intercepts_nothing_starts_no_front_door() {
        let request = super::super::tests::request(2, 1024);
        assert!(request.intercepts.is_empty());
        let (_directory, paths) = vm_paths(&request);
        assert!(matches!(boot_front_door(&request, &paths).await, Ok(None)));
    }

    /// A front door that does not start fails the boot: the test binary is
    /// not `cw`, so it never answers as a front door.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_front_door_that_does_not_start_fails_the_boot() {
        let mut request = super::super::tests::request(2, 1024);
        request.intercepts = boot_intercepts(true);
        let (_directory, paths) = vm_paths(&request);
        assert!(matches!(
            boot_front_door(&request, &paths).await,
            Err(RunnerError::FrontDoor(FrontDoorFailure::Startup)
                | RunnerError::FrontDoor(FrontDoorFailure::StartTimeout))
        ));
        assert!(!paths.front_door_socket.exists(), "nothing is bound");
    }
}
