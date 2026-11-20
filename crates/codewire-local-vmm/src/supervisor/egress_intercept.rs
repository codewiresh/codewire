//! The temporary per-host switch for intercepting agent hosts in local VMs
//! (#3999), until interception becomes the default (D3, #3997).
//!
//! The file `egress-intercept` in the native root turns it on for every boot
//! the supervisor starts while its whole content is exactly `on`, with an
//! optional trailing newline. A missing file is off. Anything else, an empty
//! or stray file, a symlink, a FIFO or other non-regular file, or something
//! unreadable, is also off and logged,
//! so nothing half-enables it. The supervisor reads it once per boot and logs
//! what the boot was started with.

use std::fs::OpenOptions;
use std::io::{self, Read as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::control::v1;
use crate::diagnostic_log::{self, DiagnosticLog, LogField};
use crate::supervisor_config::EGRESS_INTERCEPT_SWITCH;
/// Enough to tell `on\n` from anything longer.
const MAX_READ: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InterceptSwitch {
    On,
    Off,
    /// A file that is not exactly `on`: off.
    Unrecognized,
}

impl InterceptSwitch {
    pub(crate) fn intercepts(self) -> bool {
        self == Self::On
    }

    fn name(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Off => "off",
            Self::Unrecognized => "unrecognized",
        }
    }
}

/// The switch in `root` now. The file is never followed through a symlink,
/// and the open never waits, so a FIFO there cannot hold up a boot.
pub(crate) fn read_switch(root: &Path) -> InterceptSwitch {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join(EGRESS_INTERCEPT_SWITCH));
    let mut file = match file {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return InterceptSwitch::Off,
        Err(_) => return InterceptSwitch::Unrecognized,
    };
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return InterceptSwitch::Unrecognized;
    }
    let mut content = Vec::new();
    if (&mut file)
        .take(MAX_READ)
        .read_to_end(&mut content)
        .is_err()
    {
        return InterceptSwitch::Unrecognized;
    }
    match content.as_slice() {
        b"on" | b"on\n" => InterceptSwitch::On,
        _ => InterceptSwitch::Unrecognized,
    }
}

/// Whether this supervisor has warned about an unrecognized switch file: once
/// is enough, every boot still records what it used.
static WARNED_UNRECOGNIZED: AtomicBool = AtomicBool::new(false);

/// Why a switched-on boot does not intercept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Skipped {
    NoCredentialBroker,
    PlatformCredentials,
    AuthorityPredatesBootSecrets,
}

impl Skipped {
    /// Its name in the supervisor's log.
    fn name(self) -> &'static str {
        match self {
            Self::NoCredentialBroker => "no_credential_broker",
            Self::PlatformCredentials => "platform_credentials",
            Self::AuthorityPredatesBootSecrets => "authority_predates_boot_secrets",
        }
    }

    fn reason(self) -> v1::InterceptionReason {
        match self {
            Self::NoCredentialBroker => v1::InterceptionReason::NoCredentials,
            Self::PlatformCredentials => v1::InterceptionReason::PlatformCredentials,
            Self::AuthorityPredatesBootSecrets => v1::InterceptionReason::CredentialServiceOutdated,
        }
    }
}

/// What one boot starts with (#4912): its runner reports it while the boot
/// runs, so `cw info` and the start result can say it.
fn interception(switch: InterceptSwitch, skipped: Option<Skipped>) -> v1::Interception {
    let (state, reason) = match (switch.intercepts(), skipped) {
        (false, _) => (
            v1::InterceptionState::Off,
            v1::InterceptionReason::Unspecified,
        ),
        (true, None) => (
            v1::InterceptionState::Intercepted,
            v1::InterceptionReason::Unspecified,
        ),
        (true, Some(skipped)) => (v1::InterceptionState::NotIntercepted, skipped.reason()),
    };
    v1::Interception {
        state: state as i32,
        reason: reason as i32,
    }
}

/// Read the switch for one boot of `broker`'s environment, log what the boot
/// starts with, and say what it starts with. The front door serves only
/// through the boot's local credential broker, so a boot with no broker, or
/// one whose credentials come from the platform, whose relay does not pair
/// yet, does not intercept: its agent hosts are reached as they would be with
/// the switch off, and the log and the boot's report say why.
pub(super) fn for_boot(
    root: &Path,
    log: Option<&DiagnosticLog>,
    broker: &super::CredentialBrokerEnsureRequest,
    authority_carries_boot_secrets: bool,
) -> v1::Interception {
    let switch = read_switch(root);
    if switch == InterceptSwitch::Unrecognized && !WARNED_UNRECOGNIZED.swap(true, Ordering::Relaxed)
    {
        diagnostic_log::record(log, "egress_intercept_file_unrecognized", &[]);
    }
    let skipped = skipped(
        switch,
        broker.enabled,
        broker.platform.is_some(),
        authority_carries_boot_secrets,
    );
    let generation = ("generation", LogField::Count(broker.environment_generation));
    let switch_name = ("switch", LogField::Name(switch.name()));
    match skipped {
        Some(reason) => diagnostic_log::record(
            log,
            "egress_intercept",
            &[
                generation,
                switch_name,
                ("skipped", LogField::Name(reason.name())),
            ],
        ),
        None => diagnostic_log::record(log, "egress_intercept", &[generation, switch_name]),
    }
    interception(switch, skipped)
}

/// Why a switched-on boot does not intercept, if it doesn't. A boot whose
/// running authority predates boot secrets would get brokers that can never
/// pair, so it starts as with the switch off instead (#3999).
fn skipped(
    switch: InterceptSwitch,
    has_broker: bool,
    platform: bool,
    authority_carries_boot_secrets: bool,
) -> Option<Skipped> {
    if !switch.intercepts() {
        None
    } else if !has_broker {
        Some(Skipped::NoCredentialBroker)
    } else if platform {
        Some(Skipped::PlatformCredentials)
    } else if !authority_carries_boot_secrets {
        Some(Skipped::AuthorityPredatesBootSecrets)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_boot_intercepts_only_through_a_local_credential_broker() {
        use InterceptSwitch::{Off, On, Unrecognized};
        let name = |skipped: Option<Skipped>| skipped.map(Skipped::name);
        assert_eq!(skipped(On, true, false, true), None);
        assert_eq!(
            name(skipped(On, false, false, true)),
            Some("no_credential_broker")
        );
        assert_eq!(
            name(skipped(On, false, true, true)),
            Some("no_credential_broker")
        );
        assert_eq!(
            name(skipped(On, true, true, true)),
            Some("platform_credentials")
        );
        assert_eq!(
            name(skipped(On, true, false, false)),
            Some("authority_predates_boot_secrets")
        );
        for switch in [Off, Unrecognized] {
            for (has_broker, platform) in [(true, false), (false, false), (true, true)] {
                assert_eq!(skipped(switch, has_broker, platform, false), None);
            }
        }
    }

    /// The boot's report says what its log says (#4912): off for an
    /// unrecognized switch too, and each skip as its reason.
    #[test]
    fn a_boot_reports_what_it_starts_with() {
        use InterceptSwitch::{Off, On, Unrecognized};
        use v1::{InterceptionReason as Reason, InterceptionState as State};
        let report = |switch, skipped| {
            let interception = interception(switch, skipped);
            (
                State::try_from(interception.state).unwrap(),
                Reason::try_from(interception.reason).unwrap(),
            )
        };
        assert_eq!(report(Off, None), (State::Off, Reason::Unspecified));
        assert_eq!(
            report(Unrecognized, None),
            (State::Off, Reason::Unspecified)
        );
        assert_eq!(report(On, None), (State::Intercepted, Reason::Unspecified));
        for (skip, reason) in [
            (Skipped::NoCredentialBroker, Reason::NoCredentials),
            (Skipped::PlatformCredentials, Reason::PlatformCredentials),
            (
                Skipped::AuthorityPredatesBootSecrets,
                Reason::CredentialServiceOutdated,
            ),
        ] {
            assert_eq!(report(On, Some(skip)), (State::NotIntercepted, reason));
        }
    }

    fn switch_with(content: Option<&[u8]>) -> InterceptSwitch {
        let root = tempfile::tempdir().unwrap();
        if let Some(content) = content {
            std::fs::write(root.path().join(EGRESS_INTERCEPT_SWITCH), content).unwrap();
        }
        read_switch(root.path())
    }

    #[test]
    fn only_exactly_on_switches_it_on() {
        assert_eq!(switch_with(Some(b"on")), InterceptSwitch::On);
        assert_eq!(switch_with(Some(b"on\n")), InterceptSwitch::On);
        assert!(switch_with(Some(b"on")).intercepts());
    }

    #[test]
    fn a_missing_file_is_off() {
        assert_eq!(switch_with(None), InterceptSwitch::Off);
        assert!(!InterceptSwitch::Off.intercepts());
    }

    #[test]
    fn any_other_content_is_off_and_unrecognized() {
        for content in [
            &b""[..],
            b"\n",
            b"ON",
            b"on\n\n",
            b" on",
            b"on ",
            b"yes",
            b"1",
            b"off",
            b"on\non",
        ] {
            let switch = switch_with(Some(content));
            assert_eq!(switch, InterceptSwitch::Unrecognized, "{content:?}");
            assert!(!switch.intercepts());
        }
    }

    #[test]
    fn a_symlink_is_never_followed() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        std::fs::write(&target, b"on").unwrap();
        std::os::unix::fs::symlink(&target, root.path().join(EGRESS_INTERCEPT_SWITCH)).unwrap();
        assert_eq!(read_switch(root.path()), InterceptSwitch::Unrecognized);
    }

    #[test]
    fn a_fifo_is_unrecognized_without_waiting_for_a_writer() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(EGRESS_INTERCEPT_SWITCH);
        let fifo =
            std::ffi::CString::new(path.clone().into_os_string().into_encoded_bytes()).unwrap();
        // SAFETY: `fifo` is a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(read_switch(root.path()), InterceptSwitch::Unrecognized);

        // Even a FIFO whose writer has sent exactly `on` is off.
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut writer, b"on").unwrap();
        assert_eq!(read_switch(root.path()), InterceptSwitch::Unrecognized);
    }
}
