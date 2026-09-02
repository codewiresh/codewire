use std::ffi::OsStr;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::path::Path;

use anyhow::Context as _;
use codewire_access::{CredentialAuthKind, EnvironmentId};
#[cfg(not(feature = "local-broker-synthetic-smoke"))]
use codewire_credential_broker::OpenAiHttpsTransport;
#[cfg(feature = "local-broker-synthetic-smoke")]
use codewire_credential_broker::SyntheticOpenAiSmokeTransport;
use codewire_credential_broker::{
    OpenAiBroker, admit_credential_bridge, run_admitted_credential_bridge,
};
use codewire_local_credentials::{
    AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES, LocalCredentialBrokerLeaseClient,
};
use codewire_local_vmm::control::v1::EnvironmentState;
use codewire_local_vmm::hybrid_vsock::connect_daemon;
use codewire_local_vmm::supervisor::NativeSupervisorClient;
use codewire_protected_store::ConnectedOsProtectedStore;
use uuid::Uuid;

use super::LocalCredentialBrokerArgs;
use super::credential_broker_confinement::{
    apply_broker_landlock_confinement, apply_broker_seccomp_confinement,
};

pub(crate) async fn run_local_credential_broker(
    args: LocalCredentialBrokerArgs,
) -> anyhow::Result<()> {
    verify_broker_process_confinement()?;
    anyhow::ensure!(args.authority_fd == 3, "invalid broker authority channel");
    let environment_id = EnvironmentId::parse(args.environment_id.clone())
        .map_err(|_| anyhow::anyhow!("invalid broker environment identity"))?;
    let environment_uuid = Uuid::parse_str(&args.environment_id)
        .map_err(|_| anyhow::anyhow!("invalid broker environment identity"))?;
    anyhow::ensure!(
        !environment_uuid.is_nil() && args.environment_generation > 0,
        "invalid broker environment identity"
    );
    let _credential_authentication_kind = match args.credential_authentication_kind.as_str() {
        "api-key" => CredentialAuthKind::ApiKey,
        "oauth" => CredentialAuthKind::OAuth,
        _ => anyhow::bail!("invalid broker credential authentication kind"),
    };
    anyhow::ensure!(
        args.supervisor_socket.is_absolute()
            && args.supervisor_socket.file_name().and_then(OsStr::to_str)
                == Some("supervisor.sock"),
        "invalid broker supervisor endpoint"
    );

    // SAFETY: FD 3 is created by the authority immediately before exec and is
    // the only descriptor deliberately retained across that exec. Ownership is
    // transferred exactly once into this process.
    let authority_fd = unsafe { OwnedFd::from_raw_fd(args.authority_fd) };
    let authority_stream = std::os::unix::net::UnixStream::from(authority_fd);
    authority_stream
        .set_nonblocking(true)
        .context("prepare broker authority channel")?;
    let authority_stream = tokio::net::UnixStream::from_std(authority_stream)
        .context("admit broker authority channel")?;
    let mut supervisor = NativeSupervisorClient::connect(&args.supervisor_socket)
        .await
        .context("connect broker to local supervisor")?;
    let environment = supervisor
        .get(&args.environment_name)
        .await
        .context("resolve broker environment")?;
    anyhow::ensure!(
        environment.id == args.environment_id
            && environment.generation == args.environment_generation
            && environment.state == EnvironmentState::Running as i32,
        "broker environment generation is unavailable"
    );
    let access = supervisor
        .daemon_access(&args.environment_name)
        .await
        .context("resolve broker daemon transport")?;
    let daemon = connect_daemon(
        Path::new(&access.hybrid_socket),
        access.guest_port,
        &access.generation_capability,
    )
    .await
    .context("connect broker to guest daemon")?;
    let bridge = daemon
        .open_credential_bridge(environment_uuid, args.environment_generation)
        .await
        .context("open guest credential bridge")?;
    let bridge = admit_credential_bridge(bridge, environment_uuid, args.environment_generation)
        .await
        .context("authenticate guest credential bridge")?;
    // The broker needs only the admitted bridge from this point onward. Do not
    // retain general supervisor or daemon clients inside the credential-bearing
    // runtime domain.
    drop(daemon);
    drop(supervisor);
    #[cfg(not(feature = "local-broker-synthetic-smoke"))]
    let upstream = OpenAiHttpsTransport::resolve(_credential_authentication_kind)
        .await
        .context("resolve credential broker provider endpoint")?;
    #[cfg(feature = "local-broker-synthetic-smoke")]
    let upstream = SyntheticOpenAiSmokeTransport;
    apply_broker_landlock_confinement().context("confine credential broker filesystem")?;
    let protected_store =
        ConnectedOsProtectedStore::connect().context("connect broker protected store")?;
    let mut leases = LocalCredentialBrokerLeaseClient::connect(
        authority_stream,
        protected_store,
        environment_id,
        args.environment_generation,
    )
    .await
    .context("connect broker lease authority")?;
    apply_broker_seccomp_confinement().context("seal credential broker runtime")?;
    leases
        .report_ready()
        .await
        .context("complete broker launch handshake")?;
    let broker = OpenAiBroker::new(leases, upstream)
        .map_err(|_| anyhow::anyhow!("initialize broker provider policy"))?;
    run_admitted_credential_bridge(broker, bridge)
        .await
        .context("run guest credential bridge")
}

fn verify_broker_process_confinement() -> anyhow::Result<()> {
    anyhow::ensure!(
        rustix::thread::no_new_privs().unwrap_or(false),
        "local credential broker is not confined"
    );
    let capabilities = rustix::thread::capabilities(None)
        .map_err(|_| anyhow::anyhow!("local credential broker is not confined"))?;
    anyhow::ensure!(
        capabilities.effective.is_empty()
            && capabilities.permitted.is_empty()
            && capabilities.inheritable.is_empty(),
        "local credential broker is not confined"
    );
    let pid = rustix::process::getpid();
    anyhow::ensure!(
        rustix::process::getsid(None).ok() == Some(pid),
        "local credential broker is not confined"
    );
    for (name, _) in std::env::vars_os() {
        anyhow::ensure!(
            AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES
                .iter()
                .any(|allowed| name == OsStr::new(allowed)),
            "local credential broker inherited an ambient environment"
        );
    }
    let mut parent_death_signal = 0_i32;
    // SAFETY: both operations use scalar arguments except PR_GET_PDEATHSIG,
    // which writes exactly one initialized i32 owned by this stack frame.
    let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    let death_signal_result = unsafe {
        libc::prctl(
            libc::PR_GET_PDEATHSIG,
            std::ptr::addr_of_mut!(parent_death_signal),
            0,
            0,
            0,
        )
    };
    anyhow::ensure!(
        dumpable == 0 && death_signal_result == 0 && parent_death_signal == libc::SIGKILL,
        "local credential broker is not confined"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn broker_environment_allowlist_excludes_provider_and_platform_values() {
        let ambient = BTreeMap::from([
            ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("OPENAI_API_KEY", "synthetic-provider-value"),
            ("CODEWIRE_API_KEY", "synthetic-platform-value"),
            ("SSH_AUTH_SOCK", "/tmp/synthetic-agent"),
        ]);
        let inherited = AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES
            .into_iter()
            .filter_map(|name| ambient.get(name).map(|value| (name, *value)))
            .collect::<Vec<_>>();
        assert_eq!(
            inherited,
            vec![
                ("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus"),
                ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ]
        );
    }
}
