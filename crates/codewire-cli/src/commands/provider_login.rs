//! Codewire's own provider logins for `cw credentials --local connect`: the
//! Codex and GitHub device logins and the Claude sign-in.
//!
//! No provider CLI runs. This process speaks the provider's OAuth device flow
//! over a pinned provider transport, and the issued tokens go straight to the
//! local credential authority's protected store. Nothing is written to disk
//! before that, so a cancelled or failed login leaves nothing to clean up on
//! disk; a Codex sign-in cancelled after OpenAI approved it is revoked there.

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
use codewire_credential_broker::provider_oauth::codex::{self, CodexDeviceLogin};
#[cfg(test)]
use codewire_credential_broker::provider_oauth::github::GitHubDeviceLoginConfig;
use codewire_credential_broker::provider_oauth::github::{
    GitHubDeviceLogin, codewire_github_app, codewire_github_app_install_url,
};
use codewire_credential_broker::provider_oauth::{
    DeviceChallenge, DeviceLoginError, ProviderRevocation, RevocationFailure,
};
use codewire_credential_broker::{
    BrokerUpstreamTransport, ClaudeOAuthImport, CodexOAuthImport, GitHubAppAuthorizationImport,
};
use codewire_protected_store::ProtectedValue;

use super::credential_input::connect::Interrupt;
use super::login_screen::SignInScreen;

const CANCELLED: &str = "login cancelled; no credential was changed";

/// How long a cancel waits for OpenAI to revoke the unsaved sign-in: the
/// lookup and the request together.
const UNSAVED_REVOCATION_BOUND: std::time::Duration = std::time::Duration::from_secs(8);

/// Asks OpenAI, once, to revoke a Codex sign-in it approved that this
/// process will not save (#4904), over the one revocation route. `material`
/// is the bundle the login produced.
pub(crate) async fn revoke_unsaved_codex(material: ProtectedValue) -> ProviderRevocation {
    revoke_unsaved_codex_over(
        resolve(HttpProvider::CodexTokenRevocation),
        material,
        UNSAVED_REVOCATION_BOUND,
    )
    .await
}

async fn revoke_unsaved_codex_over(
    upstream: impl Future<Output = anyhow::Result<Arc<dyn BrokerUpstreamTransport>>> + Send + 'static,
    material: ProtectedValue,
    bound: std::time::Duration,
) -> ProviderRevocation {
    // The resolver's address lookup blocks its thread and can outlast the
    // bound, so it runs on a thread of its own. Unlike a blocking task, a
    // detached thread never holds the runtime's shutdown, so `cw` exits at
    // the bound whatever the resolver does (cw-network on #4991).
    let runtime = tokio::runtime::Handle::current();
    let (resolved, lookup) = tokio::sync::oneshot::channel();
    // A thread that can't start drops `resolved`, which reads as unavailable.
    let _detached = std::thread::Builder::new()
        .name("cw-revocation-lookup".into())
        .spawn(move || {
            let _ = resolved.send(runtime.block_on(upstream));
        });
    let ask = async move {
        match lookup.await {
            Ok(Ok(transport)) => codex::revoke_stored(&transport, material.expose_secret()).await,
            _ => ProviderRevocation::Failed(RevocationFailure::Unavailable),
        }
    };
    tokio::time::timeout(bound, ask)
        .await
        .unwrap_or(ProviderRevocation::Failed(RevocationFailure::Unavailable))
}

/// A login's error after the provider issued the sign-in, so the connect can
/// say what the provider still holds. It reads as the error it carries.
#[derive(Debug)]
pub(crate) struct IssuedButNotSaved(pub(crate) anyhow::Error);

impl std::fmt::Display for IssuedButNotSaved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for IssuedButNotSaved {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// Log in to ChatGPT for Codex over the Codex device-enrollment routes.
pub(crate) async fn codex_device_login(
    sign_in: SignInScreen<'_>,
    interrupt: &mut Interrupt,
) -> anyhow::Result<CodexOAuthImport> {
    let upstream = resolve(HttpProvider::CodexDeviceEnrollment)
        .await
        .context("resolve the Codex login endpoint")?;
    codex_device_login_with(sign_in, upstream, interrupt.pressed(), interrupt).await
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
        interrupt,
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
    // The code is exchanged to the end even after a Ctrl-C: Claude may issue
    // the sign-in once it is sent, and the connect reads the press from the
    // sticky flag and says what Claude holds.
    interrupt.listen();
    login
        .complete(started.handle(), pasted)
        .await
        .map_err(claude_sign_in_error)
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
    keys: &Interrupt,
) -> anyhow::Result<CodexOAuthImport> {
    let login = CodexDeviceLogin::new(upstream);
    // Only the wait for approval is cancelled; nothing is issued before it.
    // The exchange after it runs to its end, and a Ctrl-C meanwhile reaches
    // the connect through the sticky flag, which revokes what it returns.
    let approved = tokio::select! {
        biased;
        () = cancel => Err(anyhow::anyhow!(CANCELLED)),
        result = async {
            let pending = login.start().await.context("start the Codex device login")?;
            show_challenge(sign_in, pending.challenge(), keys);
            login.approve(pending).await.context("complete the Codex device login")
        } => result,
    };
    // The terminal is given back before the exchange, so a Ctrl-C during it
    // arrives as the signal the connect reads afterwards.
    keys.stop_keys();
    login
        .finish(approved?)
        .await
        .context("complete the Codex device login")
}

async fn github_device_login_with(
    sign_in: SignInScreen<'_>,
    app: codewire_credential_broker::provider_oauth::github::GitHubDeviceLoginConfig,
    upstream: Arc<dyn BrokerUpstreamTransport>,
    cancel: impl Future<Output = ()>,
    keys: &Interrupt,
) -> anyhow::Result<GitHubAppAuthorizationImport> {
    let login = GitHubDeviceLogin::new(app, upstream);
    // GitHub issues the user token with the approval, so only the wait for it
    // is cancelled; the checks after it run to their end.
    let approved = tokio::select! {
        biased;
        () = cancel => Err(anyhow::anyhow!(CANCELLED)),
        result = async {
            let pending = login.start().await.context("start the GitHub device login")?;
            show_challenge(sign_in, pending.challenge(), keys);
            login.approve(pending).await.context("complete the GitHub device login")
        } => result,
    };
    // The terminal is given back before the checks, so a Ctrl-C during them
    // arrives as the signal the connect reads afterwards.
    keys.stop_keys();
    login.finish(approved?).await.map_err(|error| {
        let error = match error {
            DeviceLoginError::InstallationRequired => {
                let install_url =
                    codewire_client::GithubAppInstallUrl::parse(&codewire_github_app_install_url());
                anyhow::anyhow!(codewire_client::github_app_not_installed(
                    install_url.as_ref()
                ))
            }
            error => anyhow::Error::new(error).context("complete the GitHub device login"),
        };
        anyhow::Error::new(IssuedButNotSaved(error))
    })
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
/// While the login waits, `c` copies the link and the waiting line shows.
fn show_challenge(sign_in: SignInScreen<'_>, challenge: &DeviceChallenge, keys: &Interrupt) {
    super::login_screen::open_sign_in_link(sign_in, challenge.verification_url());
    let style =
        crate::output::Capabilities::from_process(crate::output::OutputMode::Text).stderr_style();
    eprint!(
        "{}",
        super::login_screen::device_code_lines(challenge.user_code(), style)
    );
    keys.watch_keys(challenge.verification_url());
}

#[cfg(test)]
mod tests;
