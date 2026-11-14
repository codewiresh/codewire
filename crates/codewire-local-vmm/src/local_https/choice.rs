//! The port this user chose for the router, kept beside the CA.

use std::fs;
use std::io;
use std::path::Path;

use super::DEFAULT_PORT;
use super::ca::{CA_DIRECTORY, ensure_private_directory, write_once};

const CHOICE_FILE: &str = "port";
const CHOICE_MODE: u32 = 0o600;
const OFF: &str = "off";

/// Where the router listens, as the user chose it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PortChoice {
    Port(u16),
    Off,
}

/// The stored choice; [`DEFAULT_PORT`] when none is stored or it is
/// unreadable.
pub(crate) fn read(state_root: &Path) -> PortChoice {
    let stored = fs::read_to_string(state_root.join(CA_DIRECTORY).join(CHOICE_FILE));
    match stored.as_deref().map(str::trim) {
        Ok(OFF) => PortChoice::Off,
        Ok(port) => port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .map_or(PortChoice::Port(DEFAULT_PORT), PortChoice::Port),
        Err(_) => PortChoice::Port(DEFAULT_PORT),
    }
}

pub(crate) fn write(state_root: &Path, choice: PortChoice) -> io::Result<()> {
    let directory = state_root.join(CA_DIRECTORY);
    ensure_private_directory(&directory)?;
    let text = match choice {
        PortChoice::Port(port) => format!("{port}\n"),
        PortChoice::Off => format!("{OFF}\n"),
    };
    write_once(&directory.join(CHOICE_FILE), text.as_bytes(), CHOICE_MODE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_choice_is_remembered_and_the_default_is_443() {
        let state = tempfile::tempdir().unwrap();
        assert_eq!(read(state.path()), PortChoice::Port(443));
        write(state.path(), PortChoice::Port(8443)).unwrap();
        assert_eq!(read(state.path()), PortChoice::Port(8443));
        write(state.path(), PortChoice::Off).unwrap();
        assert_eq!(read(state.path()), PortChoice::Off);
        fs::write(state.path().join(CA_DIRECTORY).join(CHOICE_FILE), "junk").unwrap();
        assert_eq!(read(state.path()), PortChoice::Port(443));
    }
}
