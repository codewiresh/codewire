//! Codewire's own provider device logins for `cw credentials --local connect`.
//!
//! No provider CLI runs. This process speaks the provider's OAuth device flow
//! over a pinned provider transport, and the issued tokens go straight to the
//! local credential authority's protected store. Nothing is written to disk
//! before that, so a cancelled or failed login leaves nothing to clean up.

#[cfg(not(feature = "local-broker-synthetic-smoke"))]
use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::Context as _;
use codewire_access::HttpProvider;
#[cfg(not(feature = "local-broker-synthetic-smoke"))]
use codewire_credential_broker::ProviderHttpsTransport;
#[cfg(feature = "local-broker-synthetic-smoke")]
use codewire_credential_broker::SyntheticOpenAiSmokeTransport;
use codewire_credential_broker::provider_oauth::codex::CodexDeviceLogin;
#[cfg(test)]
use codewire_credential_broker::provider_oauth::github::GitHubDeviceLoginConfig;
use codewire_credential_broker::provider_oauth::github::{
    GitHubDeviceLogin, codewire_github_app, codewire_github_app_install_url,
};
use codewire_credential_broker::provider_oauth::{DeviceChallenge, DeviceLoginError};
use codewire_credential_broker::{
    BrokerUpstreamTransport, CodexOAuthImport, GitHubAppAuthorizationImport,
};

use super::credential_input::CODEX_DEVICE_AUTHORIZATION_GUIDANCE;

const CANCELLED: &str = "login cancelled; no credential was changed";

/// Log in to ChatGPT for Codex over the Codex device-enrollment routes.
pub(crate) async fn codex_device_login() -> anyhow::Result<CodexOAuthImport> {
    eprintln!("{CODEX_DEVICE_AUTHORIZATION_GUIDANCE}");
    let upstream = resolve(HttpProvider::CodexDeviceEnrollment)
        .await
        .context("resolve the Codex login endpoint")?;
    codex_device_login_with(upstream, cancelled()).await
}

/// Authorize the Codewire GitHub App for this GitHub account.
pub(crate) async fn github_device_login() -> anyhow::Result<GitHubAppAuthorizationImport> {
    let upstream = resolve(HttpProvider::GitHubAppAuthorization)
        .await
        .context("resolve the GitHub login endpoint")?;
    github_device_login_with(codewire_github_app(), upstream, cancelled()).await
}

async fn codex_device_login_with(
    upstream: Arc<dyn BrokerUpstreamTransport>,
    cancel: impl Future<Output = ()>,
) -> anyhow::Result<CodexOAuthImport> {
    let login = CodexDeviceLogin::new(upstream);
    tokio::select! {
        biased;
        () = cancel => anyhow::bail!(CANCELLED),
        result = async {
            let pending = login.start().await.context("start the Codex device login")?;
            show_challenge("Codex", pending.challenge());
            login.complete(pending).await.context("complete the Codex device login")
        } => result,
    }
}

async fn github_device_login_with(
    app: codewire_credential_broker::provider_oauth::github::GitHubDeviceLoginConfig,
    upstream: Arc<dyn BrokerUpstreamTransport>,
    cancel: impl Future<Output = ()>,
) -> anyhow::Result<GitHubAppAuthorizationImport> {
    let login = GitHubDeviceLogin::new(app, upstream);
    tokio::select! {
        biased;
        () = cancel => anyhow::bail!(CANCELLED),
        result = async {
            let pending = login.start().await.context("start the GitHub device login")?;
            show_challenge("GitHub", pending.challenge());
            match login.complete(pending).await {
                Err(DeviceLoginError::InstallationRequired) => Err(anyhow::anyhow!(
                    "the Codewire GitHub App is not installed on any account this GitHub login can use; \
                     install it, choose the accounts and repositories, then connect again: {}",
                    codewire_github_app_install_url()
                )),
                result => result.context("complete the GitHub device login"),
            }
        } => result,
    }
}

#[cfg(not(feature = "local-broker-synthetic-smoke"))]
async fn resolve(provider: HttpProvider) -> anyhow::Result<Arc<dyn BrokerUpstreamTransport>> {
    Ok(Arc::new(
        ProviderHttpsTransport::resolve(&BTreeSet::from([provider])).await?,
    ))
}

/// The non-shipping product smoke answers both device logins in process.
#[cfg(feature = "local-broker-synthetic-smoke")]
async fn resolve(_: HttpProvider) -> anyhow::Result<Arc<dyn BrokerUpstreamTransport>> {
    Ok(Arc::new(SyntheticOpenAiSmokeTransport))
}

async fn cancelled() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Only the fixed provider page and the one-time code are shown.
fn show_challenge(provider: &str, challenge: &DeviceChallenge) {
    eprintln!(
        "Open {} and enter this one-time code: {}\nContinue only if you started this {provider} login in Codewire.",
        challenge.verification_url(),
        challenge.user_code(),
    );
}

#[cfg(test)]
mod tests;
