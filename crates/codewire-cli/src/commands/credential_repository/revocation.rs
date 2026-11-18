//! The one-shot provider revocation executor (#4717). The local credential
//! authority starts it, confined as the repository executor is, with its
//! lease stream on FD 3 after it has revoked the credential. It reads the one
//! leased generation from the OS store, asks OpenAI to revoke the Codex
//! refresh token over a transport that admits only that request, and reports
//! only the outcome class. The token is never printed, kept or sent back.

use std::os::fd::{FromRawFd as _, OwnedFd};
use std::sync::Arc;

use anyhow::Context as _;
use codewire_credential_broker::BrokerUpstreamTransport;
use codewire_credential_broker::provider_oauth::{ProviderRevocation, RevocationFailure, codex};
use codewire_local_credentials::{
    LocalProviderRevocation, LocalProviderRevocationFailure, LocalProviderRevocationOutcome,
    LocalRevocationLeaseClient, run_revocation_executor,
};
use uuid::Uuid;

use super::super::credential_child_store::{ChildStore, ChildStoreArgs};
use super::verify_repository_executor_confinement;

#[derive(Debug, clap::Args)]
pub(crate) struct LocalProviderRevocationExecutorArgs {
    #[arg(long)]
    pub(crate) authority_fd: i32,
    #[arg(long)]
    pub(crate) request_id: String,
    /// The authority's store: the executor reads the selected backend.
    #[command(flatten)]
    pub(crate) store: ChildStoreArgs,
}

pub(crate) async fn run_local_provider_revocation_executor(
    args: LocalProviderRevocationExecutorArgs,
) -> anyhow::Result<()> {
    verify_repository_executor_confinement()?;
    let store = ChildStore::from_args(&args.store)?;
    let request_id = executor_request_id(args.authority_fd, &args.request_id)?;
    // SAFETY: FD 3 is created by the authority immediately before exec and is
    // the only descriptor deliberately retained across that exec. Ownership is
    // transferred exactly once into this process.
    let authority_fd = unsafe { OwnedFd::from_raw_fd(args.authority_fd) };
    rustix::io::fcntl_setfd(&authority_fd, rustix::io::FdFlags::CLOEXEC)
        .context("confine revocation authority channel")?;
    let authority_stream = std::os::unix::net::UnixStream::from(authority_fd);
    authority_stream
        .set_nonblocking(true)
        .context("prepare revocation lease channel")?;
    let authority_stream = tokio::net::UnixStream::from_std(authority_stream)
        .context("admit revocation lease channel")?;
    let mut client = LocalRevocationLeaseClient::connect(authority_stream, request_id)
        .await
        .context("connect revocation lease channel")?;
    let store = store.open().ok();
    run_revocation_executor(&mut client, store.as_ref(), |material| async move {
        match codex_revocation_transport().await {
            Ok(transport) => {
                local_outcome(codex::revoke_stored(&transport, material.expose_secret()).await)
            }
            Err(_) => local_outcome(ProviderRevocation::Failed(RevocationFailure::Unavailable)),
        }
    })
    .await
    .context("run the provider revocation")
}

/// The executor's launch arguments: its lease channel must be FD 3, and its
/// request identity a canonical, non-nil UUID.
fn executor_request_id(authority_fd: i32, request_id: &str) -> anyhow::Result<Uuid> {
    anyhow::ensure!(authority_fd == 3, "invalid revocation lease channel");
    Uuid::parse_str(request_id)
        .ok()
        .filter(|parsed| !parsed.is_nil() && parsed.to_string() == request_id)
        .ok_or_else(|| anyhow::anyhow!("invalid revocation request identity"))
}

/// The one route a revocation may use: OpenAI's RFC 7009 endpoint.
#[cfg(not(feature = "local-broker-synthetic-smoke"))]
async fn codex_revocation_transport() -> anyhow::Result<Arc<dyn BrokerUpstreamTransport>> {
    Ok(Arc::new(
        codewire_credential_broker::ProviderHttpsTransport::resolve(
            &std::collections::BTreeSet::from([
                codewire_access::HttpProvider::CodexTokenRevocation,
            ]),
        )
        .await?,
    ))
}

/// The non-shipping product smoke answers in process.
#[cfg(feature = "local-broker-synthetic-smoke")]
async fn codex_revocation_transport() -> anyhow::Result<Arc<dyn BrokerUpstreamTransport>> {
    Ok(Arc::new(
        codewire_credential_broker::SyntheticOpenAiSmokeTransport,
    ))
}

fn local_outcome(revocation: ProviderRevocation) -> LocalProviderRevocation {
    use LocalProviderRevocationFailure as Failure;
    let (outcome, failure, http_status) = match revocation {
        ProviderRevocation::Confirmed => (
            LocalProviderRevocationOutcome::Confirmed,
            Failure::Unspecified,
            0,
        ),
        ProviderRevocation::Failed(failure) => (
            LocalProviderRevocationOutcome::Failed,
            match failure {
                RevocationFailure::Unavailable => Failure::Unavailable,
                RevocationFailure::Refused(_) => Failure::Refused,
                RevocationFailure::Unreadable => Failure::Unreadable,
                RevocationFailure::Expired => Failure::Expired,
            },
            match failure {
                RevocationFailure::Refused(status) => u32::from(status),
                _ => 0,
            },
        ),
    };
    LocalProviderRevocation {
        outcome: outcome.into(),
        failure: failure.into(),
        http_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fd_3_and_a_canonical_request_id_are_accepted() {
        let id = Uuid::new_v4().to_string();
        assert_eq!(executor_request_id(3, &id).unwrap().to_string(), id);
        assert!(executor_request_id(4, &id).is_err(), "another descriptor");
        assert!(
            executor_request_id(3, &Uuid::nil().to_string()).is_err(),
            "the nil UUID"
        );
        assert!(
            executor_request_id(3, &id.to_uppercase()).is_err(),
            "a non-canonical form"
        );
        assert!(executor_request_id(3, "not-a-request").is_err());
    }
}
