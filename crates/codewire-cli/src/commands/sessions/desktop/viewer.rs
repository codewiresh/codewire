//! Opening the computer's own VNC viewer on a forwarded desktop, and giving
//! it the viewer password where that can be done privately
//! (`docs/dev/SANDBOX-DESKTOP.md`, "The viewer password").
//!
//! The password never goes into an argument of a process or into a file,
//! where other users of the computer could read it. On macOS the address
//! with the password is written to the standard input of the system's script
//! runner, which opens it. Anywhere else a registered viewer is started with
//! the address as its own argument, so the address is opened without the
//! password and the user types it.

use super::state::ViewerPassword;

/// What became of the viewer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Opened {
    /// The viewer has the password and asks for nothing.
    WithPassword,
    /// The viewer opens and asks for the password.
    AskingForPassword,
    /// No viewer is registered for the address.
    NoViewer,
}

/// The address a viewer on this computer connects to. It names no password.
pub(super) fn address(port: u16) -> String {
    format!("vnc://127.0.0.1:{port}")
}

/// Opens the desktop behind loopback `port` in the system's viewer.
pub(super) async fn open(port: u16, password: &ViewerPassword) -> Opened {
    #[cfg(target_os = "macos")]
    if hand_over(port, password.reveal()).await {
        return Opened::WithPassword;
    }
    #[cfg(not(target_os = "macos"))]
    let _ = password; // Only macOS has a private way to give it to a viewer.
    open_without_password(port).await
}

/// The script that opens the desktop with its password, for the script
/// runner's standard input.
///
/// The password is the environment's daemon's, and here it becomes script
/// text on the user's computer. The shape check is therefore made here, at
/// the one place that builds the text, whatever a caller checked before:
/// eight lowercase letters or digits can end neither the string nor the
/// address. The port is this command's own number.
#[cfg(any(target_os = "macos", test))]
fn opener_script(port: u16, password: &str) -> Option<String> {
    codewire_daemon_proto::is_desktop_viewer_password(password)
        .then(|| format!("open location \"vnc://:{password}@127.0.0.1:{port}\"\n"))
}

/// How long the script runner may take to hand the address to the viewer.
#[cfg(target_os = "macos")]
const HAND_OVER_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Gives the built-in viewer the address with the password. False when it
/// could not, and the caller then opens the address without the password.
#[cfg(target_os = "macos")]
async fn hand_over(port: u16, password: &str) -> bool {
    use tokio::io::AsyncWriteExt as _;

    let Some(script) = opener_script(port, password) else {
        return false;
    };
    // By absolute path and with an empty environment, so nothing on PATH or
    // in the environment chooses what reads the script.
    let spawned = crate::process::tokio_command("/usr/bin/osascript", &[])
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let Ok(mut runner) = spawned else {
        return false;
    };
    let ran = async {
        let mut input = runner.stdin.take()?;
        input.write_all(script.as_bytes()).await.ok()?;
        drop(input);
        runner.wait().await.ok()
    };
    matches!(
        tokio::time::timeout(HAND_OVER_WAIT, ran).await,
        Ok(Some(status)) if status.success()
    )
}

async fn open_without_password(port: u16) -> Opened {
    if !viewer_is_registered().await {
        return Opened::NoViewer;
    }
    match crate::commands::open_browser(&address(port)) {
        Ok(()) => Opened::AskingForPassword,
        Err(_) => Opened::NoViewer,
    }
}

/// macOS always has its built-in viewer.
#[cfg(target_os = "macos")]
async fn viewer_is_registered() -> bool {
    true
}

/// How long the desktop's own lookup may take.
#[cfg(all(unix, not(target_os = "macos")))]
const LOOKUP_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// Whether the desktop has a handler for `vnc://` addresses. The opener
/// would otherwise hand the address to a browser, or fail without a word.
#[cfg(all(unix, not(target_os = "macos")))]
async fn viewer_is_registered() -> bool {
    let lookup = crate::process::tokio_command("xdg-mime", &[])
        .args(["query", "default", "x-scheme-handler/vnc"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(LOOKUP_WAIT, lookup).await {
        Ok(Ok(found)) => found.status.success() && names_a_handler(&found.stdout),
        _ => false,
    }
}

/// Nowhere else is a registered viewer looked for: the address is printed.
#[cfg(not(unix))]
async fn viewer_is_registered() -> bool {
    false
}

#[cfg(any(all(unix, not(target_os = "macos")), test))]
fn names_a_handler(lookup_output: &[u8]) -> bool {
    !lookup_output.trim_ascii().is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_address_names_loopback_and_the_port_and_no_password() {
        assert_eq!(address(49_152), "vnc://127.0.0.1:49152");
    }

    #[test]
    fn the_script_is_built_only_from_a_password_in_the_daemons_shape() {
        assert_eq!(
            opener_script(49_152, "a1b2c3d4").as_deref(),
            Some("open location \"vnc://:a1b2c3d4@127.0.0.1:49152\"\n")
        );
        // What an environment might answer to run script on the computer
        // that views it, or to send the viewer elsewhere.
        for hostile in [
            "",
            "a1b2c3d",
            "a1b2c3d4e",
            "A1B2C3D4",
            "a1b2c3d\"",
            "\"&do shell script \"id\"&\"",
            "a1b2\"\ndo",
            "a1b2c3\\\"",
            "a@evil.x",
            "a1b2c3d/",
            "a1b2c3d#",
            "a1b2 c3d",
            "a1b2c3d\u{e9}",
            "\u{ff41}1b2c3d4",
        ] {
            assert_eq!(opener_script(49_152, hostile), None, "{hostile:?}");
        }
    }

    #[test]
    fn a_handler_is_a_lookup_that_names_one() {
        assert!(names_a_handler(b"vnc-viewer.desktop\n"));
        assert!(!names_a_handler(b""));
        assert!(!names_a_handler(b"\n"));
    }
}
