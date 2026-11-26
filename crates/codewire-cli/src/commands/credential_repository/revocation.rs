//! The one-shot provider revocation executor (#4717). The local credential
//! authority starts it, confined as the repository executor is, with its
//! lease stream on FD 3 after it has revoked the credential. Its one lease
//! carries the revoked generation's value, and it opens no store (#4984). It
//! asks OpenAI to revoke the Codex refresh token over a transport that admits
//! only that request, and reports only the outcome class. The token is never
//! printed, kept or sent back.

use std::os::fd::{FromRawFd as _, OwnedFd};
use std::sync::Arc;

use anyhow::Context as _;
use codewire_credential_broker::BrokerUpstreamTransport;
use codewire_credential_broker::provider_oauth::{
    ProviderRevocation, RevocationFailure, antigravity, codex,
};
use codewire_local_credentials::{
    LocalProviderRevocation, LocalProviderRevocationFailure, LocalProviderRevocationOutcome,
    LocalRevocationLeaseClient, run_revocation_executor,
};
use uuid::Uuid;

use super::verify_repository_executor_confinement;

#[derive(Debug, clap::Args)]
pub(crate) struct LocalProviderRevocationExecutorArgs {
    #[arg(long)]
    pub(crate) authority_fd: i32,
    #[arg(long)]
    pub(crate) request_id: String,
}

pub(crate) async fn run_local_provider_revocation_executor(
    args: LocalProviderRevocationExecutorArgs,
) -> anyhow::Result<()> {
    verify_repository_executor_confinement()?;
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
    // The value is dropped, and so zeroized, as soon as the revoke returns.
    run_revocation_executor(&mut client, |material| async move {
        let is_antigravity = antigravity::is_stored_bundle(material.expose_secret());
        let family = if is_antigravity {
            codewire_access::HttpProvider::AntigravityTokenRevocation
        } else {
            codewire_access::HttpProvider::CodexTokenRevocation
        };
        match revocation_transport(family).await {
            Ok(transport) if is_antigravity => local_outcome(
                antigravity::revoke_stored(&transport, material.expose_secret()).await,
            ),
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

/// The one route a revocation may use: OpenAI's or Google's RFC 7009 endpoint.
#[cfg(not(feature = "local-broker-synthetic-smoke"))]
async fn revocation_transport(
    family: codewire_access::HttpProvider,
) -> anyhow::Result<Arc<dyn BrokerUpstreamTransport>> {
    Ok(Arc::new(
        codewire_credential_broker::ProviderHttpsTransport::resolve(
            &std::collections::BTreeSet::from([family]),
        )
        .await?,
    ))
}

/// The non-shipping product smoke answers in process.
#[cfg(feature = "local-broker-synthetic-smoke")]
async fn revocation_transport(
    _family: codewire_access::HttpProvider,
) -> anyhow::Result<Arc<dyn BrokerUpstreamTransport>> {
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

    /// #4984: both executors open no store, so each refuses to start when a
    /// caller still names one.
    #[test]
    fn both_executors_refuse_a_store_argument() {
        use clap::Parser as _;

        #[derive(clap::Parser)]
        struct Revocation {
            #[command(flatten)]
            args: LocalProviderRevocationExecutorArgs,
        }
        #[derive(clap::Parser)]
        struct Repository {
            #[command(flatten)]
            args: crate::commands::LocalGitRepositoryExecutorArgs,
        }
        let id = Uuid::new_v4().to_string();
        let revocation = ["cw", "--authority-fd", "3", "--request-id", id.as_str()];
        let repository = [
            "cw",
            "--transport",
            "github-oauth",
            "--authority-fd",
            "3",
            "--request-id",
            id.as_str(),
            "--staging-directory",
            "/synthetic/staging",
        ];
        assert!(Revocation::try_parse_from(revocation).is_ok());
        assert!(Repository::try_parse_from(repository).is_ok());
        for store in [
            &["--protected-store", "secret-service"][..],
            &[
                "--protected-store",
                "file",
                "--protected-store-directory",
                "/synthetic",
            ],
            &["--keychain", "/synthetic/login.keychain-db"],
        ] {
            assert!(
                Revocation::try_parse_from(revocation.iter().chain(store)).is_err(),
                "{store:?}"
            );
            assert!(
                Repository::try_parse_from(repository.iter().chain(store)).is_err(),
                "{store:?}"
            );
        }
    }
}
