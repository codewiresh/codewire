pub const DAEMON_AUTH_TOKEN_HEADER: &str = "x-codewire-daemon-token";
pub const DAEMON_PROTOCOL_VERSION: u32 = 1;
pub const DAEMON_MINIMUM_PROTOCOL_VERSION: u32 = 1;
pub const DAEMON_CAPABILITY_EXEC: &str = "exec.v1";
pub const DAEMON_CAPABILITY_PTY: &str = "pty.v1";
pub const DAEMON_CAPABILITY_FILES: &str = "files.v1";
pub const DAEMON_CAPABILITY_HEALTH: &str = "health.v1";
pub const DAEMON_CAPABILITY_SESSIONS: &str = "sessions.v1";
pub const DAEMON_CAPABILITY_ATTACH: &str = "attach.v1";
pub const DAEMON_CAPABILITIES: &[&str] = &[
    DAEMON_CAPABILITY_EXEC,
    DAEMON_CAPABILITY_PTY,
    DAEMON_CAPABILITY_FILES,
    DAEMON_CAPABILITY_HEALTH,
    DAEMON_CAPABILITY_SESSIONS,
    DAEMON_CAPABILITY_ATTACH,
];

pub mod daemon {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/daemon.v1.rs"));
    }
}
