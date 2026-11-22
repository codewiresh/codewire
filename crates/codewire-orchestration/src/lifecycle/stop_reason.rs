/// Why a sandbox was stopped, as `environments.stop_reason` (#3384). A stop
/// records it with desired state `stopped`; a start clears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// A person stopped it.
    User,
    /// Its organization ran out of credit.
    Credit,
    /// It had no activity for its idle timeout.
    Idle,
    /// It is a systemd workspace whose bring-up its checks refused
    /// (docs/dev/SYSTEMD-WORKSPACE.md, "Where it is checked").
    SystemdRefused,
}

impl StopReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Credit => "credit",
            Self::Idle => "idle",
            Self::SystemdRefused => "systemd_refused",
        }
    }
}
