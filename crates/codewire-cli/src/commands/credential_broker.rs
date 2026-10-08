use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::path::Path;

use anyhow::Context as _;
use codewire_access::{EnvironmentId, HttpProvider};
#[cfg(not(feature = "local-broker-synthetic-smoke"))]
use codewire_credential_broker::ProviderHttpsTransport;
#[cfg(feature = "local-broker-synthetic-smoke")]
use codewire_credential_broker::SyntheticOpenAiSmokeTransport;
#[cfg(target_os = "linux")]
use codewire_credential_broker::{
    BrokerBridgeError, CredentialBridgeRelayOutput, run_admitted_credential_bridge_relay,
};
use codewire_credential_broker::{
    OpenAiBroker, admit_credential_bridge, run_admitted_credential_bridge,
};
use codewire_local_credentials::LocalCredentialBrokerLeaseClient;
#[cfg(target_os = "linux")]
use codewire_local_credentials::{
    AUTHORITY_ALLOWED_ENVIRONMENT_VARIABLES, LocalCredentialDelegationClient,
};
use codewire_local_vmm::hybrid_vsock::{HybridVsockError, HybridVsockTarget};
use codewire_local_vmm::runner_service::RunnerClient;
#[cfg(target_os = "linux")]
use codewire_protected_store::ConnectedOsProtectedStore;
#[cfg(target_os = "linux")]
use futures::StreamExt as _;
use uuid::Uuid;

use super::LocalCredentialBrokerArgs;
#[cfg(target_os = "linux")]
use super::credential_broker_confinement::{
    apply_broker_landlock_confinement, apply_broker_seccomp_confinement,
};

#[cfg(target_os = "macos")]
mod darwin;

pub(crate) async fn run_local_credential_broker(
    args: LocalCredentialBrokerArgs,
) -> anyhow::Result<()> {
    verify_broker_process_confinement()?;
    // Validate the store selection before any channel or provider effect.
    #[cfg(target_os = "macos")]
    let store = super::credential_darwin::ChildStore::from_args(&args.store)?;
    anyhow::ensure!(args.authority_fd == 3, "invalid broker authority channel");
    let environment_id = EnvironmentId::parse(args.environment_id.clone())
        .map_err(|_| anyhow::anyhow!("invalid broker environment identity"))?;
    let environment_uuid = Uuid::parse_str(&args.environment_id)
        .map_err(|_| anyhow::anyhow!("invalid broker environment identity"))?;
    anyhow::ensure!(
        !environment_uuid.is_nil() && args.environment_generation > 0,
        "invalid broker environment identity"
    );
    let mut http_providers = BTreeSet::new();
    for name in &args.http_providers {
        let provider = HttpProvider::parse(name).context("invalid broker HTTP provider")?;
        anyhow::ensure!(
            http_providers.insert(provider),
            "duplicate broker HTTP provider"
        );
    }
    anyhow::ensure!(
        !args.platform_delegated || http_providers.is_empty(),
        "platform relay cannot select local provider transport"
    );
    anyhow::ensure!(
        args.runner_socket.is_absolute()
            && args.runner_socket.file_name().and_then(OsStr::to_str)
                == Some(format!("{environment_uuid}.sock").as_str()),
        "invalid broker runner endpoint"
    );

    // SAFETY: FD 3 is created by the authority immediately before exec and is
    // the only descriptor deliberately retained across that exec. Ownership is
    // transferred exactly once into this process.
    let authority_fd = unsafe { OwnedFd::from_raw_fd(args.authority_fd) };
    // The macOS broker runs Apple's security tool for keychain reads; that
    // child must not inherit the authority channel.
    #[cfg(target_os = "macos")]
    rustix::io::fcntl_setfd(&authority_fd, rustix::io::FdFlags::CLOEXEC)
        .context("prepare broker authority channel")?;
    let authority_stream = std::os::unix::net::UnixStream::from(authority_fd);
    authority_stream
        .set_nonblocking(true)
        .context("prepare broker authority channel")?;
    let authority_stream = tokio::net::UnixStream::from_std(authority_stream)
        .context("admit broker authority channel")?;
    let mut runner = RunnerClient::connect(&args.runner_socket)
        .await
        .context("connect broker to private runner")?;
    let access = runner
        .generation_daemon_access(environment_uuid, args.environment_generation)
        .await
        .context("resolve broker daemon transport")?;
    // The supervisor observed authenticated runc-launching progress, which
    // follows spawning the early daemon. Its listener may still be binding.
    // Keep one exact socket identity and one deadline across transport-only
    // retries; no provider material or authenticated Open has been used yet.
    let target = HybridVsockTarget::new(
        Path::new(&access.hybrid_socket).to_owned(),
        access.guest_port,
    )
    .context("admit broker daemon endpoint")?;
    let daemon = tokio::time::timeout(std::time::Duration::from_secs(7), async {
        loop {
            match target.connect_daemon(&access.generation_capability).await {
                Ok(daemon) => break Ok(daemon),
                Err(HybridVsockError::Channel) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(error) => break Err(error),
            }
        }
    })
    .await
    .context("broker daemon transport readiness timed out")?
    .context("connect broker to guest daemon")?;
    let bridge = daemon
        .open_credential_bridge(environment_uuid, args.environment_generation)
        .await
        .context("open guest credential bridge")?;
    let bridge = admit_credential_bridge(bridge, environment_uuid, args.environment_generation)
        .await
        .context("authenticate guest credential bridge")?;
    // The broker needs only the admitted bridge from this point onward. Do not
    // retain general runner or daemon clients inside the credential-bearing
    // runtime domain.
    drop(daemon);
    drop(runner);
    #[cfg(target_os = "macos")]
    anyhow::ensure!(
        !args.platform_delegated,
        "platform credential relay is not available on macOS"
    );
    #[cfg(target_os = "linux")]
    if args.platform_delegated {
        // The original guest Ready is retained in `bridge`. This branch has
        // no provider DNS, protected-store connection, or raw lease provider.
        // The only authority endpoint is the parent's inherited FD3 channel.
        apply_broker_landlock_confinement().context("confine platform credential relay")?;
        let mut delegation = LocalCredentialDelegationClient::connect(
            authority_stream,
            environment_id,
            args.environment_generation,
        )
        .await
        .context("connect platform credential relay authority")?;
        apply_broker_seccomp_confinement().context("seal platform credential relay")?;
        return run_admitted_credential_bridge_relay(bridge, move |ready, input| async move {
            let output = delegation
                .delegate_credentials(ready, input)
                .await
                .map_err(|_| BrokerBridgeError::Unavailable)?;
            // The exact private admission was consumed only after the parent
            // verified the exact public selection echo. HTTP headers alone
            // never make this native broker ready.
            delegation
                .report_ready()
                .await
                .map_err(|_| BrokerBridgeError::Unavailable)?;
            Ok(
                Box::pin(output.map(|frame| frame.map_err(|_| BrokerBridgeError::Unavailable)))
                    as CredentialBridgeRelayOutput,
            )
        })
        .await
        .context("run platform credential relay");
    }
    #[cfg(not(feature = "local-broker-synthetic-smoke"))]
    let upstream = if http_providers.is_empty() {
        None
    } else {
        Some(
            ProviderHttpsTransport::resolve(&http_providers)
                .await
                .context("resolve credential broker provider endpoint")?,
        )
    };
    #[cfg(feature = "local-broker-synthetic-smoke")]
    let upstream = (!http_providers.is_empty()).then_some(SyntheticOpenAiSmokeTransport);
    #[cfg(target_os = "linux")]
    let protected_store = {
        apply_broker_landlock_confinement().context("confine credential broker filesystem")?;
        ConnectedOsProtectedStore::connect().context("connect broker protected store")?
    };
    // One Seatbelt profile replaces Landlock and seccomp: provider HTTPS to
    // the addresses resolved above, and reads of exactly the selected store.
    #[cfg(target_os = "macos")]
    let protected_store = {
        darwin::confine(&store, !http_providers.is_empty()).context("confine credential broker")?;
        store.open().context("open broker protected store")?
    };
    let mut leases = LocalCredentialBrokerLeaseClient::connect(
        authority_stream,
        protected_store,
        environment_id,
        args.environment_generation,
    )
    .await
    .context("connect broker lease authority")?;
    #[cfg(target_os = "linux")]
    apply_broker_seccomp_confinement().context("seal credential broker runtime")?;
    leases
        .report_ready(bridge.ready().clone())
        .await
        .context("complete broker launch handshake")?;
    let broker = OpenAiBroker::new(leases, upstream)
        .map_err(|_| anyhow::anyhow!("initialize broker provider policy"))?;
    run_admitted_credential_bridge(broker, bridge)
        .await
        .context("run guest credential bridge")
}

#[cfg(target_os = "macos")]
fn verify_broker_process_confinement() -> anyhow::Result<()> {
    darwin::verify_process()
}

#[cfg(target_os = "linux")]
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

#[cfg(all(test, target_os = "linux"))]
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
