//! Background keep-alive for idle rotating OAuth credentials.
//!
//! On-demand refresh runs only when a request finds an access token about to
//! expire. A credential nobody uses can therefore sit until its provider
//! retires the refresh token; the first later refresh is then rejected and the
//! owner must reconnect. Codex CLI refreshes once its last refresh is older
//! than 8 days. This owner refreshes an idle platform credential once its
//! protected material is older than a provider-specific keep-alive age. A
//! Claude sign-in is kept alive the same way; a Claude subscription token,
//! which has no refresh, is a different credential kind and is never selected.
//!
//! Each sweep reads only metadata to select candidates, then decides from the
//! protected material's own refresh time. A due credential is refreshed through
//! the same durable attempt journal, provider exchange, rotated-material
//! validation, publication and closed failure logging as an on-demand refresh.
//! PostgreSQL serializes it with other replicas and with on-demand refreshes:
//! a credential with a live reservation or a started, staged or unknown attempt
//! is never selected, and a lost race ends at `begin` without a provider
//! request. Every failure after durable Start is terminal, exactly as on
//! demand: the previous refresh token is never replayed and the credential
//! needs reconnecting. Once Start commits, the exchange and its publication are
//! never cancelled; shutdown waits for that terminal outcome.
//!
//! No material, token or provider response leaves this module. Logs carry only
//! the provider, closed failure classes and counts.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codewire_access::{CredentialAuthKind, CredentialId, ProviderId};
use codewire_platform_credentials::{
    CredentialVersion, OAuthKeepAliveCandidate, OAuthKeepAliveForm, PlatformCredentialStore,
};
use codewire_protected_store::ProtectedValue;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use uuid::Uuid;

use super::{publish_started_refresh, refresh_store_error};
use crate::claude_oauth::ClaudeOAuthCredential;
use crate::codex_oauth::CodexOAuthCredential;
use crate::github_app::{GitHubAppUserOAuthBundle, GitHubOAuthCredential};
use crate::refresh_failure::RefreshFailure;
use crate::runtime::{
    exchange_claude_oauth_refresh, exchange_codex_oauth_refresh, exchange_github_app_refresh,
};
use crate::{BrokerRefreshError, BrokerUpstreamTransport, GitHubAppAuthorizationOwner};

const CODEX_PROVIDER: &str = "openai";
const GITHUB_PROVIDER: &str = "github";
const CLAUDE_PROVIDER: &str = "anthropic";
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// Metadata page size for one candidate query.
const PAGE_SIZE: u32 = 64;
/// Protected-material reads (one KEK unwrap each) per sweep. Decisions are
/// cached per exact credential version, so steady state reads almost nothing.
const MAX_MATERIAL_READS_PER_SWEEP: usize = 32;
/// Provider exchanges per sweep; the rest wait for the next sweep.
const MAX_REFRESHES_PER_SWEEP: usize = 8;
/// Pause before each further material read once a sweep has refreshed one.
const REFRESH_SPACING: Duration = Duration::from_secs(2);

/// Metadata selection age of a Claude sign-in: the configuration's floor, so a
/// sign-in whose refresh token is due at half its lifetime is not missed.
const MIN_CLAUDE_SELECTION_AGE: Duration = Duration::from_secs(60);

/// Default sweep interval; each wait is jittered by a quarter either way.
pub const DEFAULT_OAUTH_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30 * 60);
/// OpenAI (Codex) material older than this is refreshed: inside the 8-day
/// last-refresh habit of Codex CLI, whose refresh-token lifetime is unpublished.
pub const DEFAULT_CODEX_KEEPALIVE_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// GitHub App user tokens are refreshed after this age, far inside GitHub's
/// documented six-month refresh-token lifetime.
pub const DEFAULT_GITHUB_KEEPALIVE_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Claude sign-in material older than this is refreshed, or sooner at half of
/// the refresh token's lifetime when Claude reports it. Claude publishes no
/// refresh-token lifetime, so the default follows Codex's.
pub const DEFAULT_CLAUDE_KEEPALIVE_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Keep-alive timing. Ages are measured from the material's own refresh time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OAuthKeepAliveConfig {
    pub interval: Duration,
    pub codex_age: Duration,
    pub github_age: Duration,
    pub claude_age: Duration,
}

impl Default for OAuthKeepAliveConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_OAUTH_KEEPALIVE_INTERVAL,
            codex_age: DEFAULT_CODEX_KEEPALIVE_AGE,
            github_age: DEFAULT_GITHUB_KEEPALIVE_AGE,
            claude_age: DEFAULT_CLAUDE_KEEPALIVE_AGE,
        }
    }
}

impl OAuthKeepAliveConfig {
    /// Accepted ranges: interval 10 s to 1 day; Codex age 1 minute to 8 days
    /// (never later than Codex CLI's own habit); GitHub age 1 minute to 90 days;
    /// Claude age 1 minute to 8 days. Short values exist for local
    /// observation, not production tuning.
    pub fn validate(self) -> Result<Self, OAuthKeepAliveConfigError> {
        let minute = Duration::from_secs(60);
        if !(Duration::from_secs(10)..=DAY).contains(&self.interval) {
            return Err(OAuthKeepAliveConfigError::Interval);
        }
        if !(minute..=8 * DAY).contains(&self.codex_age) {
            return Err(OAuthKeepAliveConfigError::CodexAge);
        }
        if !(minute..=90 * DAY).contains(&self.github_age) {
            return Err(OAuthKeepAliveConfigError::GitHubAge);
        }
        if !(minute..=8 * DAY).contains(&self.claude_age) {
            return Err(OAuthKeepAliveConfigError::ClaudeAge);
        }
        Ok(self)
    }
}

/// Which keep-alive setting is out of range.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OAuthKeepAliveConfigError {
    #[error("OAuth keep-alive interval is out of range")]
    Interval,
    #[error("OAuth keep-alive Codex age is out of range")]
    CodexAge,
    #[error("OAuth keep-alive GitHub age is out of range")]
    GitHubAge,
    #[error("OAuth keep-alive Claude age is out of range")]
    ClaudeAge,
}

/// One owner per credential-service process. It holds the trusted store and
/// provider transports already held by that process; it opens no listener.
pub struct OAuthKeepAlive {
    store: Arc<PlatformCredentialStore>,
    upstream: Arc<dyn BrokerUpstreamTransport>,
    github_app: Option<Arc<GitHubAppAuthorizationOwner>>,
    config: OAuthKeepAliveConfig,
    decisions: Mutex<HashMap<CredentialId, Cached>>,
    started: AtomicBool,
    stop: CancellationToken,
    tasks: TaskTracker,
}

/// The material-derived decision for one exact version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Decision {
    /// Refresh now.
    Due,
    /// Not due before this Unix second.
    NotBefore(u64),
    /// This exact version is never kept alive here: non-rotating or
    /// unparseable material, an expired refresh token, or no App owner.
    Never,
}

#[derive(Clone, Copy)]
struct Cached {
    version: CredentialVersion,
    decision: Decision,
}

enum Plan {
    Codex(CodexOAuthCredential),
    GitHub(Arc<GitHubAppAuthorizationOwner>, GitHubAppUserOAuthBundle),
    Claude(ClaudeOAuthCredential),
}

enum Outcome {
    Refreshed,
    Failed,
    Decided(Decision),
    Skipped,
}

/// Counts for one sweep, for logs and tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OAuthKeepAliveSweep {
    pub(crate) refreshed: usize,
    pub(crate) failed: usize,
    pub(crate) not_due: usize,
    pub(crate) skipped: usize,
    pub(crate) material_reads: usize,
    pub(crate) complete: bool,
}

impl OAuthKeepAlive {
    /// `upstream` is the broker's provider transport; `github_app` is the
    /// private App owner when one is configured. Without it, GitHub
    /// credentials are not selected.
    pub fn new(
        store: Arc<PlatformCredentialStore>,
        upstream: Arc<dyn BrokerUpstreamTransport>,
        github_app: Option<Arc<GitHubAppAuthorizationOwner>>,
        config: OAuthKeepAliveConfig,
    ) -> Self {
        Self {
            store,
            upstream,
            github_app,
            config,
            decisions: Mutex::new(HashMap::new()),
            started: AtomicBool::new(false),
            stop: CancellationToken::new(),
            tasks: TaskTracker::new(),
        }
    }

    /// Start the periodic sweep once. The first sweep waits a jittered
    /// fraction of the interval so replicas and restarts do not align.
    pub fn start(self: &Arc<Self>) {
        if self.stop.is_cancelled() || self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let owner = Arc::clone(self);
        self.tasks.spawn(async move { owner.run().await });
        tracing::info!(
            interval_seconds = self.config.interval.as_secs(),
            codex_age_seconds = self.config.codex_age.as_secs(),
            github_age_seconds = self.config.github_age.as_secs(),
            claude_age_seconds = self.config.claude_age.as_secs(),
            github_app = self.github_app.is_some(),
            "OAuth credential keep-alive started"
        );
    }

    /// Stop selecting new work. A refresh already past `begin` still finishes.
    pub fn start_shutdown(&self) {
        self.stop.cancel();
        self.tasks.close();
    }

    /// Wait until any in-flight refresh has reached its terminal outcome.
    pub async fn shutdown(&self) {
        self.start_shutdown();
        self.tasks.wait().await;
    }

    async fn run(&self) {
        let mut wait = jittered(self.config.interval, random()) / 4;
        loop {
            tokio::select! {
                biased;
                _ = self.stop.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
            }
            let sweep = self.sweep().await;
            if sweep.refreshed + sweep.failed + sweep.skipped > 0 || !sweep.complete {
                tracing::info!(
                    refreshed = sweep.refreshed,
                    failed = sweep.failed,
                    not_due = sweep.not_due,
                    skipped = sweep.skipped,
                    material_reads = sweep.material_reads,
                    complete = sweep.complete,
                    "OAuth credential keep-alive sweep finished"
                );
            } else {
                tracing::debug!(
                    not_due = sweep.not_due,
                    material_reads = sweep.material_reads,
                    "OAuth credential keep-alive sweep finished"
                );
            }
            wait = jittered(self.config.interval, random());
        }
    }

    /// The rotating credential forms this owner selects, each with the
    /// metadata age below which it is never a candidate. A Claude sign-in may
    /// be due earlier, at half its refresh token's lifetime; its decision
    /// reads that from the material, so its selection age is the minute floor.
    fn forms(&self) -> Vec<OAuthKeepAliveForm> {
        let mut forms = Vec::with_capacity(3);
        let mut add = |provider: &str, authentication_kind, age: Duration| {
            if let Ok(provider) = ProviderId::parse(provider) {
                forms.push(OAuthKeepAliveForm {
                    provider,
                    authentication_kind,
                    min_age_seconds: age.as_secs(),
                });
            }
        };
        add(
            CODEX_PROVIDER,
            CredentialAuthKind::OAuth,
            self.config.codex_age,
        );
        if self.github_app.is_some() {
            add(
                GITHUB_PROVIDER,
                CredentialAuthKind::OAuth,
                self.config.github_age,
            );
        }
        add(
            CLAUDE_PROVIDER,
            CredentialAuthKind::ClaudeSignIn,
            MIN_CLAUDE_SELECTION_AGE.min(self.config.claude_age),
        );
        forms
    }

    /// One bounded pass over every candidate page. Stops early, without
    /// pruning cached decisions, at a per-sweep cap or shutdown.
    pub(crate) async fn sweep(&self) -> OAuthKeepAliveSweep {
        let mut sweep = OAuthKeepAliveSweep::default();
        let forms = self.forms();
        let mut seen = HashSet::new();
        let mut after: Option<CredentialId> = None;
        'pages: loop {
            if self.stop.is_cancelled() {
                break;
            }
            let page = match self
                .store
                .oauth_keepalive_candidates(&forms, after.as_ref(), PAGE_SIZE)
                .await
            {
                Ok(page) => page,
                Err(error) => {
                    // A closed, value-blind class, for example a missing grant.
                    tracing::warn!(
                        failure = ?error,
                        "OAuth credential keep-alive could not select candidates"
                    );
                    break;
                }
            };
            let last_page = page.len() < PAGE_SIZE as usize;
            for candidate in page {
                if self.stop.is_cancelled() {
                    break 'pages;
                }
                after = Some(candidate.id.clone());
                seen.insert(candidate.id.clone());
                let Ok(now) = unix_now() else {
                    break 'pages;
                };
                if self.cached_not_due(&candidate, now) {
                    sweep.not_due += 1;
                    continue;
                }
                if sweep.material_reads >= MAX_MATERIAL_READS_PER_SWEEP
                    || sweep.refreshed + sweep.failed >= MAX_REFRESHES_PER_SWEEP
                {
                    break 'pages;
                }
                if sweep.refreshed + sweep.failed > 0 {
                    tokio::select! {
                        biased;
                        _ = self.stop.cancelled() => break 'pages,
                        _ = tokio::time::sleep(REFRESH_SPACING) => {}
                    }
                }
                sweep.material_reads += 1;
                match self.keep_alive(&candidate, now).await {
                    Outcome::Refreshed => sweep.refreshed += 1,
                    Outcome::Failed => sweep.failed += 1,
                    Outcome::Decided(decision) => {
                        self.remember(&candidate, decision);
                        sweep.not_due += 1;
                    }
                    Outcome::Skipped => sweep.skipped += 1,
                }
            }
            if last_page {
                sweep.complete = true;
                break;
            }
        }
        if sweep.complete
            && let Ok(mut decisions) = self.decisions.lock()
        {
            decisions.retain(|id, _| seen.contains(id));
        }
        sweep
    }

    fn cached_not_due(&self, candidate: &OAuthKeepAliveCandidate, now: u64) -> bool {
        let Ok(decisions) = self.decisions.lock() else {
            return false;
        };
        decisions.get(&candidate.id).is_some_and(|cached| {
            cached.version == candidate.version
                && match cached.decision {
                    Decision::Never => true,
                    Decision::NotBefore(due_at) => now < due_at,
                    Decision::Due => false,
                }
        })
    }

    fn remember(&self, candidate: &OAuthKeepAliveCandidate, decision: Decision) {
        if let Ok(mut decisions) = self.decisions.lock() {
            decisions.insert(
                candidate.id.clone(),
                Cached {
                    version: candidate.version,
                    decision,
                },
            );
        }
    }

    /// Read this exact version, decide from its own refresh time and, when it
    /// is due, refresh it through the durable journal.
    async fn keep_alive(&self, candidate: &OAuthKeepAliveCandidate, now: u64) -> Outcome {
        // A changed, inactive, expired or unavailable record is simply left
        // for a later sweep; nothing was reserved or sent.
        let Ok(material) = self
            .store
            .read_for_oauth_refresh(&candidate.owner, &candidate.id, candidate.version)
            .await
        else {
            return Outcome::Skipped;
        };
        let plan = match (candidate.provider.as_str(), candidate.authentication_kind) {
            (CODEX_PROVIDER, CredentialAuthKind::OAuth) => {
                match CodexOAuthCredential::parse(material.expose_secret()) {
                    Ok(credential) => match codex_decision(
                        credential.refreshed_at_unix(),
                        now,
                        self.config.codex_age.as_secs(),
                    ) {
                        Decision::Due => Plan::Codex(credential),
                        decision => return Outcome::Decided(decision),
                    },
                    Err(_) => return Outcome::Decided(Decision::Never),
                }
            }
            (CLAUDE_PROVIDER, CredentialAuthKind::ClaudeSignIn) => {
                match ClaudeOAuthCredential::parse(material.expose_secret()) {
                    Ok(credential) => match claude_decision(
                        credential.refreshed_at_unix(),
                        credential.refresh_expires_at_unix(),
                        now,
                        self.config.claude_age.as_secs(),
                    ) {
                        Decision::Due => Plan::Claude(credential),
                        decision => return Outcome::Decided(decision),
                    },
                    Err(_) => return Outcome::Decided(Decision::Never),
                }
            }
            (GITHUB_PROVIDER, CredentialAuthKind::OAuth) => {
                let Some(owner) = self.github_app.as_ref() else {
                    return Outcome::Decided(Decision::Never);
                };
                // Non-expiring tokens (CLI device flow, App without expiring
                // user tokens) have nothing to keep alive.
                let Ok(GitHubOAuthCredential::App(bundle)) =
                    GitHubOAuthCredential::parse(material.expose_secret())
                else {
                    return Outcome::Decided(Decision::Never);
                };
                let Ok((access_expires_at, refresh_expires_at)) = bundle.expiry_times() else {
                    return Outcome::Decided(Decision::Never);
                };
                match github_app_decision(
                    access_expires_at,
                    refresh_expires_at,
                    now,
                    self.config.github_age.as_secs(),
                ) {
                    Decision::Due => Plan::GitHub(Arc::clone(owner), bundle),
                    decision => return Outcome::Decided(decision),
                }
            }
            _ => return Outcome::Decided(Decision::Never),
        };
        drop(material);
        self.refresh(candidate, plan).await
    }

    async fn refresh(&self, candidate: &OAuthKeepAliveCandidate, plan: Plan) -> Outcome {
        let OAuthKeepAliveCandidate {
            owner, id, version, ..
        } = candidate;
        let provider = match plan {
            Plan::Codex(_) => CODEX_PROVIDER,
            Plan::GitHub(..) => GITHUB_PROVIDER,
            Plan::Claude(_) => CLAUDE_PROVIDER,
        };
        let Ok(refreshed_at_unix) = unix_now() else {
            return Outcome::Skipped;
        };
        let attempt_id = Uuid::new_v4();
        // Another replica, an on-demand refresh, a reconnect or an unknown
        // outcome all end here: nothing was sent and nothing is recorded.
        let Ok(prepared) = self
            .store
            .begin_oauth_refresh(owner, id, *version, attempt_id)
            .await
        else {
            return Outcome::Skipped;
        };
        if self.stop.is_cancelled() {
            // Shutdown before Start: release the reservation, send nothing.
            let _ = self
                .store
                .cancel_oauth_refresh(owner, id, *version, attempt_id)
                .await;
            return Outcome::Skipped;
        }
        // From here the exchange runs to a terminal outcome. An uncertain Start
        // ACK destroys the only permit; the storage deadline then fences it.
        let started = match self.store.start_oauth_refresh(prepared).await {
            Ok(started) => started,
            Err(error) => {
                RefreshFailure::Start(refresh_store_error(error)).warn(provider);
                return Outcome::Failed;
            }
        };
        let exchanged =
            match plan {
                Plan::Codex(credential) => {
                    exchange_codex_oauth_refresh(&*self.upstream, credential, refreshed_at_unix)
                        .await
                        .map(|bundle| ProtectedValue::from_slice(bundle.as_bytes()))
                }
                Plan::GitHub(owner, bundle) => exchange_github_app_refresh(&owner, bundle)
                    .await
                    .map(|bundle| {
                        let mut bytes = bundle.into_bytes();
                        ProtectedValue::new(std::mem::take(&mut *bytes))
                    }),
                Plan::Claude(credential) => {
                    exchange_claude_oauth_refresh(&*self.upstream, credential, refreshed_at_unix)
                        .await
                        .map(|bundle| {
                            let mut bytes = bundle.into_bytes();
                            ProtectedValue::new(std::mem::take(&mut *bytes))
                        })
                }
            };
        match exchanged {
            Ok(value) => {
                let published = match value {
                    Ok(value) => {
                        publish_started_refresh(
                            &self.store,
                            owner,
                            id,
                            *version,
                            attempt_id,
                            started,
                            value,
                        )
                        .await
                    }
                    Err(_) => Err(BrokerRefreshError::InvalidResponse),
                };
                match published {
                    Ok(()) => {
                        tracing::info!(provider, "OAuth credential keep-alive refreshed");
                        Outcome::Refreshed
                    }
                    Err(error) => {
                        RefreshFailure::Publication(error).warn(provider);
                        Outcome::Failed
                    }
                }
            }
            Err((failure, _)) => {
                failure.warn(provider);
                if self.store.fail_oauth_refresh(started).await.is_err() {
                    tracing::warn!(
                        provider,
                        failure = failure.class(),
                        "provider credential refresh failure could not be recorded"
                    );
                }
                Outcome::Failed
            }
        }
    }
}

/// Codex: due once the material's own last refresh is `age` old.
fn codex_decision(refreshed_at_unix: u64, now: u64, age: u64) -> Decision {
    let due_at = refreshed_at_unix.saturating_add(age);
    if due_at <= now {
        Decision::Due
    } else {
        Decision::NotBefore(due_at)
    }
}

/// Claude sign-in: due at the earlier of `age` and half the refresh token's
/// lifetime, both from the material's own last refresh. An already expired
/// refresh token cannot be renewed; on-demand use reports Reconnect instead.
fn claude_decision(
    refreshed_at_unix: u64,
    refresh_expires_at_unix: Option<u64>,
    now: u64,
    age: u64,
) -> Decision {
    if refresh_expires_at_unix.is_some_and(|expiry| expiry <= now) {
        return Decision::Never;
    }
    let half_lifetime = refresh_expires_at_unix.map_or(u64::MAX, |expiry| {
        expiry.saturating_sub(refreshed_at_unix) / 2
    });
    let due_at = refreshed_at_unix.saturating_add(age.min(half_lifetime));
    if due_at <= now {
        Decision::Due
    } else {
        Decision::NotBefore(due_at)
    }
}

/// GitHub App: dated by its access-token expiry, which follows each rotation
/// by the access-token lifetime. An already expired refresh token cannot be
/// renewed; on-demand use reports that connection instead.
fn github_app_decision(
    access_expires_at_unix: u64,
    refresh_expires_at_unix: u64,
    now: u64,
    age: u64,
) -> Decision {
    if refresh_expires_at_unix <= now {
        return Decision::Never;
    }
    let due_at = access_expires_at_unix.saturating_add(age);
    if due_at <= now {
        Decision::Due
    } else {
        Decision::NotBefore(due_at)
    }
}

/// `interval` scaled into [3/4, 5/4) by `random`.
fn jittered(interval: Duration, random: u64) -> Duration {
    let millis = u64::try_from(interval.as_millis()).unwrap_or(u64::MAX);
    let span = (millis / 2).max(1);
    Duration::from_millis((millis - millis / 4).saturating_add(random % span))
}

fn random() -> u64 {
    // Not a secret: only spreads sweeps across replicas and restarts.
    Uuid::new_v4().as_u128() as u64
}

fn unix_now() -> Result<u64, BrokerRefreshError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| BrokerRefreshError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn codex_is_due_exactly_at_its_material_age() {
        let age = DEFAULT_CODEX_KEEPALIVE_AGE.as_secs();
        assert_eq!(codex_decision(NOW - age, NOW, age), Decision::Due);
        assert_eq!(codex_decision(NOW - age - 1, NOW, age), Decision::Due);
        assert_eq!(
            codex_decision(NOW - age + 1, NOW, age),
            Decision::NotBefore(NOW + 1)
        );
        // Freshly imported or rotated material is not touched for a week.
        assert_eq!(
            codex_decision(NOW, NOW, age),
            Decision::NotBefore(NOW + age)
        );
        // A corrupt future timestamp never overflows into "due".
        assert_eq!(
            codex_decision(u64::MAX, NOW, age),
            Decision::NotBefore(u64::MAX)
        );
    }

    #[test]
    fn github_app_is_due_by_age_and_never_after_its_refresh_token_expired() {
        let age = DEFAULT_GITHUB_KEEPALIVE_AGE.as_secs();
        let six_months = 15_897_600;
        let issued = NOW - age - 28_800;
        let access = issued + 28_800;
        assert_eq!(
            github_app_decision(access, issued + six_months, NOW, age),
            Decision::Due
        );
        assert_eq!(
            github_app_decision(NOW + 28_800, NOW + six_months, NOW, age),
            Decision::NotBefore(NOW + 28_800 + age)
        );
        assert_eq!(
            github_app_decision(access, NOW, NOW, age),
            Decision::Never,
            "an expired refresh token cannot be renewed"
        );
        assert_eq!(
            github_app_decision(access, NOW - 1, NOW, age),
            Decision::Never
        );
    }

    #[test]
    fn claude_is_due_at_its_age_or_half_its_refresh_token_lifetime() {
        let age = DEFAULT_CLAUDE_KEEPALIVE_AGE.as_secs();
        // Without a reported refresh-token lifetime, the age alone applies.
        assert_eq!(claude_decision(NOW - age, None, NOW, age), Decision::Due);
        assert_eq!(
            claude_decision(NOW, None, NOW, age),
            Decision::NotBefore(NOW + age)
        );
        // A long refresh token keeps the age; a short one is due at half.
        assert_eq!(
            claude_decision(NOW, Some(NOW + 90 * 86_400), NOW, age),
            Decision::NotBefore(NOW + age)
        );
        assert_eq!(
            claude_decision(NOW, Some(NOW + 4 * 86_400), NOW, age),
            Decision::NotBefore(NOW + 2 * 86_400)
        );
        assert_eq!(
            claude_decision(NOW - 2 * 86_400, Some(NOW + 2 * 86_400), NOW, age),
            Decision::Due
        );
        // An expired refresh token cannot be renewed.
        assert_eq!(
            claude_decision(NOW - 86_400, Some(NOW), NOW, age),
            Decision::Never
        );
        assert_eq!(
            claude_decision(u64::MAX, None, NOW, age),
            Decision::NotBefore(u64::MAX)
        );
    }

    #[test]
    fn default_ages_stay_inside_provider_refresh_habits() {
        let config = OAuthKeepAliveConfig::default().validate().unwrap();
        // Codex CLI refreshes after 8 days; keep-alive must act earlier.
        assert!(config.codex_age < 8 * DAY);
        // GitHub refresh tokens last six months.
        assert!(config.github_age * 4 < Duration::from_secs(15_897_600));
        // Claude publishes no refresh-token lifetime: follow Codex's habit.
        assert!(config.claude_age < 8 * DAY);
        assert!(config.interval * 48 <= config.claude_age);
        assert!(config.interval * 48 <= config.codex_age);
    }

    #[test]
    fn configuration_ranges_are_closed() {
        let valid = OAuthKeepAliveConfig::default();
        for (config, error) in [
            (
                OAuthKeepAliveConfig {
                    interval: Duration::from_secs(9),
                    ..valid
                },
                OAuthKeepAliveConfigError::Interval,
            ),
            (
                OAuthKeepAliveConfig {
                    interval: DAY + Duration::from_secs(1),
                    ..valid
                },
                OAuthKeepAliveConfigError::Interval,
            ),
            (
                OAuthKeepAliveConfig {
                    codex_age: Duration::from_secs(59),
                    ..valid
                },
                OAuthKeepAliveConfigError::CodexAge,
            ),
            (
                OAuthKeepAliveConfig {
                    codex_age: 8 * DAY + Duration::from_secs(1),
                    ..valid
                },
                OAuthKeepAliveConfigError::CodexAge,
            ),
            (
                OAuthKeepAliveConfig {
                    github_age: 90 * DAY + Duration::from_secs(1),
                    ..valid
                },
                OAuthKeepAliveConfigError::GitHubAge,
            ),
            (
                OAuthKeepAliveConfig {
                    claude_age: Duration::from_secs(59),
                    ..valid
                },
                OAuthKeepAliveConfigError::ClaudeAge,
            ),
            (
                OAuthKeepAliveConfig {
                    claude_age: 8 * DAY + Duration::from_secs(1),
                    ..valid
                },
                OAuthKeepAliveConfigError::ClaudeAge,
            ),
        ] {
            assert_eq!(config.validate(), Err(error));
        }
        let short = OAuthKeepAliveConfig {
            interval: Duration::from_secs(10),
            codex_age: Duration::from_secs(60),
            github_age: Duration::from_secs(60),
            claude_age: Duration::from_secs(60),
        };
        assert_eq!(short.validate(), Ok(short));
    }

    #[test]
    fn jitter_spreads_within_a_quarter_of_the_interval() {
        let interval = DEFAULT_OAUTH_KEEPALIVE_INTERVAL;
        let low = jittered(interval, 0);
        assert_eq!(low, interval * 3 / 4);
        for random in [1, 7, u64::MAX / 3, u64::MAX] {
            let wait = jittered(interval, random);
            assert!(
                wait >= interval * 3 / 4 && wait < interval * 5 / 4,
                "{wait:?}"
            );
        }
        assert!(jittered(Duration::from_millis(1), u64::MAX) <= Duration::from_millis(1));
    }
}
