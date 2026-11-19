//! Test-only hosted guest for the hosted egress Kind walk (#4000): the
//! daemon's own egress loop (`codewire_cli::hosted_egress`) with nothing of
//! the daemon around it. It reads the values the Pod template renders
//! (`CODEWIRE_EGRESS_STREAM_ADDR`, `CODEWIRE_POD_UID`,
//! `CODEWIRE_CLUSTER_DNS_IP`) and the projected egress token, so a fixture Pod
//! differs from a real one only in its entry point.
//!
//! Unlike the daemon, which goes round again, it exits 1 with the reason when
//! a round ends before the first passed self-check, so the stream not being
//! admitted or the lockdown not enforcing is a Pod that never becomes ready.
//! Once the self-check has passed it writes `/tmp/hosted-guest-ready` for the readiness
//! probe and keeps the stream up as the daemon does.
//!
//! This example is not installed as part of `cw`. Build it explicitly with:
//! `cargo build --locked -p codewire-cli-bin --example hosted_guest`.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the hosted guest fixture is only available on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    if let Err(error) = linux::run().await {
        eprintln!("hosted guest: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context as _, anyhow};
    use codewire_cli::hosted_egress::{EgressSettings, LoggedEvents, spawn};
    use codewire_daemon_proto::WORKSPACE_POD_UID_ENV;
    use codewire_network_session::EgressTrust;
    use codewire_network_session::guest::hosted::{EgressEvents, RoundEnd};

    /// Written once the first self-check has passed.
    pub(super) const READY_FILE: &str = "/tmp/hosted-guest-ready";

    pub(super) async fn run() -> anyhow::Result<()> {
        let pod_uid = std::env::var(WORKSPACE_POD_UID_ENV)
            .with_context(|| format!("{WORKSPACE_POD_UID_ENV} is required"))?;
        let settings = EgressSettings::from_lookup(&pod_uid, |name| std::env::var(name).ok())?
            .ok_or_else(|| anyhow!("no egress stream address is set"))?;
        spawn(
            settings,
            FixtureEvents {
                logged: LoggedEvents::new(None),
                ready: false,
            },
        )?;
        std::future::pending().await
    }

    struct FixtureEvents {
        logged: LoggedEvents,
        ready: bool,
    }

    impl EgressEvents for FixtureEvents {
        fn egress_trust(&mut self, trust: &EgressTrust) {
            self.logged.egress_trust(trust);
        }

        fn ready(&mut self) {
            self.logged.ready();
            if !self.ready {
                self.ready = true;
                if let Err(error) = std::fs::write(READY_FILE, b"") {
                    eprintln!("hosted guest: write {READY_FILE}: {error}");
                    std::process::exit(1);
                }
            }
        }

        fn round_ended(&mut self, end: &RoundEnd) {
            self.logged.round_ended(end);
            if !self.ready {
                eprintln!("hosted guest: the first round ended before a passed self-check");
                std::process::exit(1);
            }
        }
    }
}
