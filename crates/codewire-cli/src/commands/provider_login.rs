//! Codewire's own provider logins for `cw credentials --local connect`: the
//! Codex and GitHub device logins and the Claude sign-in.
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
use codewire_credential_broker::provider_oauth::claude::{
    CLAUDE_SIGN_IN_CODE_INVALID, CLAUDE_SIGN_IN_EXPIRED, ClaudeSignIn, ClaudeSignInError,
};
use codewire_credential_broker::provider_oauth::codex::CodexDeviceLogin;
#[cfg(test)]
use codewire_credential_broker::provider_oauth::github::GitHubDeviceLoginConfig;
use codewire_credential_broker::provider_oauth::github::{
    GitHubDeviceLogin, codewire_github_app, codewire_github_app_install_url,
};
use codewire_credential_broker::provider_oauth::{DeviceChallenge, DeviceLoginError};
use codewire_credential_broker::{
    BrokerUpstreamTransport, ClaudeOAuthImport, CodexOAuthImport, GitHubAppAuthorizationImport,
};

use super::credential_input::CODEX_DEVICE_AUTHORIZATION_GUIDANCE;
use super::credential_input::connect::Interrupt;
use super::login_screen::SignInScreen;

const CANCELLED: &str = "login cancelled; no credential was changed";

/// Log in to ChatGPT for Codex over the Codex device-enrollment routes.
pub(crate) async fn codex_device_login(
    sign_in: SignInScreen<'_>,
    interrupt: &mut Interrupt,
) -> anyhow::Result<CodexOAuthImport> {
    eprintln!("{CODEX_DEVICE_AUTHORIZATION_GUIDANCE}");
    let upstream = resolve(HttpProvider::CodexDeviceEnrollment)
        .await
        .context("resolve the Codex login endpoint")?;
    codex_device_login_with(sign_in, upstream, interrupt.pressed()).await
}

/// Authorize the Codewire GitHub App for this GitHub account.
pub(crate) async fn github_device_login(
    sign_in: SignInScreen<'_>,
    interrupt: &mut Interrupt,
) -> anyhow::Result<GitHubAppAuthorizationImport> {
    let upstream = resolve(HttpProvider::GitHubAppAuthorization)
        .await
        .context("resolve the GitHub login endpoint")?;
    github_device_login_with(
        sign_in,
        codewire_github_app(),
        upstream,
        interrupt.pressed(),
    )
    .await
}

/// Sign in to Claude for Claude Code: the same sign-in the platform service
/// runs, here in the host CLI, which alone holds this sign-in's verifier.
/// The person opens the authorize page and pastes back the code Claude shows.
pub(crate) async fn claude_sign_in(
    sign_in: SignInScreen<'_>,
    interrupt: &mut Interrupt,
) -> anyhow::Result<ClaudeOAuthImport> {
    let upstream = resolve(HttpProvider::ClaudeSignInEnrollment)
        .await
        .context("resolve the Claude sign-in endpoint")?;
    let login = ClaudeSignIn::new(upstream);
    let started = login.start().map_err(claude_sign_in_error)?;
    let pasted = super::login_screen::claude_sign_in_code(sign_in, started.authorize_url())?;
    let pasted = std::str::from_utf8(pasted.expose_secret())
        .map_err(|_| anyhow::anyhow!(CLAUDE_SIGN_IN_CODE_INVALID))?;
    tokio::select! {
        biased;
        () = interrupt.pressed() => anyhow::bail!(CANCELLED),
        result = login.complete(started.handle(), pasted) => {
            result.map_err(claude_sign_in_error)
        }
    }
}

/// The same words the platform service uses for the same outcome.
fn claude_sign_in_error(error: ClaudeSignInError) -> anyhow::Error {
    match error {
        ClaudeSignInError::InvalidCode => anyhow::anyhow!(CLAUDE_SIGN_IN_CODE_INVALID),
        ClaudeSignInError::Expired => anyhow::anyhow!(CLAUDE_SIGN_IN_EXPIRED),
        error @ (ClaudeSignInError::Denied
        | ClaudeSignInError::Unavailable
        | ClaudeSignInError::InvalidResponse) => {
            anyhow::Error::new(error).context("complete the Claude sign-in")
        }
    }
}

async fn codex_device_login_with(
    sign_in: SignInScreen<'_>,
    upstream: Arc<dyn BrokerUpstreamTransport>,
    cancel: impl Future<Output = ()>,
) -> anyhow::Result<CodexOAuthImport> {
    let login = CodexDeviceLogin::new(upstream);
    tokio::select! {
        biased;
        () = cancel => anyhow::bail!(CANCELLED),
        result = async {
            let pending = login.start().await.context("start the Codex device login")?;
            show_challenge(sign_in, pending.challenge());
            login.complete(pending).await.context("complete the Codex device login")
        } => result,
    }
}

async fn github_device_login_with(
    sign_in: SignInScreen<'_>,
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
            show_challenge(sign_in, pending.challenge());
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

/// The link screen for the fixed provider page, then the one-time code: the
/// same screen the cloud shows. Nothing else of the challenge is shown.
fn show_challenge(sign_in: SignInScreen<'_>, challenge: &DeviceChallenge) {
    super::login_screen::open_sign_in_link(sign_in, challenge.verification_url());
    let style =
        crate::output::Capabilities::from_process(crate::output::OutputMode::Text).stderr_style();
    eprint!(
        "{}",
        super::login_screen::device_code_lines(sign_in, challenge.user_code(), style)
    );
}

#[cfg(test)]
mod tests;
