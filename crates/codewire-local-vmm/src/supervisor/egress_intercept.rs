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

/// Read the switch for one boot and log what it starts with.
pub(crate) fn switch_for_boot(
    root: &Path,
    log: Option<&DiagnosticLog>,
    generation: u64,
) -> InterceptSwitch {
    let switch = read_switch(root);
    if switch == InterceptSwitch::Unrecognized && !WARNED_UNRECOGNIZED.swap(true, Ordering::Relaxed)
    {
        diagnostic_log::record(log, "egress_intercept_file_unrecognized", &[]);
    }
    diagnostic_log::record(
        log,
        "egress_intercept",
        &[
            ("generation", LogField::Count(generation)),
            ("switch", LogField::Name(switch.name())),
        ],
    );
    switch
}

#[cfg(test)]
mod tests {
    use super::*;

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
