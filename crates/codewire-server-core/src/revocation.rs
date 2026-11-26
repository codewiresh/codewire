//! Ending a stream already admitted when the authority that admitted it is
//! lost (#3586; `docs/dev/AUTH-POLICY.md`, "Account access revocation").
//!
//! The database logs each loss in `credential_revocations` and wakes every
//! process on [`CHANNEL`]. One listener per process reads the log by sequence
//! on each wake-up and every [`BACKSTOP`], and ends the streams registered
//! under the lost user, session, OAuth token or grant, or API key, and the
//! streams into an organization its user left or whose deletion started.
//!
//! Admission ([`Fence::admit`]) takes a database snapshot, registers the
//! stream, then re-reads the check that admitted it. A log row whose
//! transaction that snapshot already sees never ends the stream: the re-read
//! decided on it. So an account disabled and enabled again, or a grant
//! revoked and signed in again, opens streams at once, however late the
//! listener reads the old row.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::watch;

use crate::auth::{AuthUser, CredentialContext, OAuthBearerAuthority};

/// The wake-up the log's writer sends, with no payload.
pub const CHANNEL: &str = "credential_revocations";
/// How often the listener reads the log whether or not a wake-up came, so a
/// lost one costs at most this.
pub const BACKSTOP: Duration = Duration::from_secs(30);
/// How long a skipped sequence number is read again: the writer removes rows
/// older than an hour, so a write still uncommitted after that has no row to
/// find.
const GAP_LIFETIME: Duration = Duration::from_secs(60 * 60);
/// Bounds the skipped numbers held. A revoking write is a short transaction,
/// so a number skipped for more than moments is a rolled-back write, which
/// never appears; dropping the oldest under a burst of rollbacks loses
/// nothing else. A dropped number whose write did commit is never read here,
/// and the streams it names run on until they are admitted again. Only
/// streams already open can miss it: a new admission re-reads its credential.
const MAX_GAPS: usize = 10_000;
const LISTENER_RETRY: Duration = Duration::from_secs(5);

/// What was lost, as the log names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation {
    User,
    Session,
    OAuthToken,
    OAuthGrant,
    ApiKey,
    UserToken,
    /// The user left the stream's organization or was removed from it.
    Membership,
    /// The stream's organization started to be deleted.
    Organization,
}

impl Revocation {
    fn parse(kind: &str) -> Option<Self> {
        Some(match kind {
            "user" => Self::User,
            "session" => Self::Session,
            "oauth_token" => Self::OAuthToken,
            "oauth_grant" => Self::OAuthGrant,
            "api_key" => Self::ApiKey,
            "user_token" => Self::UserToken,
            "membership" => Self::Membership,
            "organization" => Self::Organization,
            _ => return None,
        })
    }

    /// The log's name for it, as the audit event records it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Session => "session",
            Self::OAuthToken => "oauth_token",
            Self::OAuthGrant => "oauth_grant",
            Self::ApiKey => "api_key",
            Self::UserToken => "user_token",
            Self::Membership => "membership",
            Self::Organization => "organization",
        }
    }
}

/// Why a stream was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// The re-read no longer admits the credential.
    #[error("the credential no longer admits this stream")]
    Revoked,
    /// The snapshot or the re-read could not be read; never an admission.
    #[error("the stream's admission could not be checked")]
    Unavailable,
    /// The user is not a member of the stream's organization, or it doesn't
    /// exist: a surface answers as its own access check does for one.
    #[error("the user is not a member of the stream's organization")]
    NotMember,
    /// The stream's organization is being deleted.
    #[error("the stream's organization is being deleted")]
    OrganizationDeleting,
}

/// The user and the credential a stream was admitted with, and the
/// organization its environment belongs to: the keys it ends under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    user_id: String,
    credential: AdmittedCredential,
    organization: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AdmittedCredential {
    Session {
        session_id: String,
    },
    OAuthToken {
        token_hash: String,
        client_id: String,
    },
    ApiKey {
        key_id: String,
    },
    UserToken {
        token_id: String,
        client_id: String,
    },
}

impl Admitted {
    /// A stream admitted by a browser session, directly or through a
    /// terminal ticket that names it.
    pub fn session(user_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            credential: AdmittedCredential::Session {
                session_id: session_id.into(),
            },
            organization: None,
        }
    }

    /// The request's resolved credential. `None` for an OAuth token without
    /// its bearer authority, which authentication always records.
    pub fn from_request(
        user: &AuthUser,
        credential: &CredentialContext,
        bearer: Option<&OAuthBearerAuthority>,
    ) -> Option<Self> {
        let credential = match credential {
            CredentialContext::SessionCookie { session_id } => AdmittedCredential::Session {
                session_id: session_id.clone(),
            },
            CredentialContext::ApiKey { key_id, .. } => AdmittedCredential::ApiKey {
                key_id: key_id.clone(),
            },
            CredentialContext::UserToken {
                token_id,
                client_id,
                ..
            } => AdmittedCredential::UserToken {
                token_id: token_id.clone(),
                client_id: client_id.clone(),
            },
            CredentialContext::OidcAccessToken { .. } => {
                let bearer = bearer?;
                AdmittedCredential::OAuthToken {
                    token_hash: bearer.digest().to_owned(),
                    client_id: bearer.client_id().to_owned(),
                }
            }
        };
        Some(Self {
            user_id: user.user_id.clone(),
            credential,
            organization: None,
        })
    }

    /// The stream goes into an environment of `org_id`, so it also ends when
    /// its user leaves that organization or the organization's deletion
    /// starts, and its admission checks both again.
    #[must_use]
    pub fn in_organization(mut self, org_id: impl Into<String>) -> Self {
        self.organization = Some(org_id.into());
        self
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn organization(&self) -> Option<&str> {
        self.organization.as_deref()
    }

    /// Whether `other` names the same user and credential. A request's
    /// admission run again yields no organization, which only the stream's
    /// surface knows, so the organization is not compared.
    pub fn same_credential(&self, other: &Admitted) -> bool {
        self.user_id == other.user_id && self.credential == other.credential
    }

    fn keys(&self) -> Vec<Authority> {
        let mut keys = self.credential_keys();
        if let Some(org_id) = &self.organization {
            keys.push(Authority::Membership {
                user_id: self.user_id.clone(),
                org_id: org_id.clone(),
            });
            keys.push(Authority::Organization(org_id.clone()));
        }
        keys
    }

    fn credential_keys(&self) -> Vec<Authority> {
        let user = Authority::User(self.user_id.clone());
        match &self.credential {
            AdmittedCredential::Session { session_id } => {
                vec![user, Authority::Session(session_id.clone())]
            }
            AdmittedCredential::OAuthToken {
                token_hash,
                client_id,
            } => vec![
                user,
                Authority::OAuthToken(token_hash.clone()),
                Authority::OAuthGrant {
                    user_id: self.user_id.clone(),
                    client_id: client_id.clone(),
                },
            ],
            AdmittedCredential::ApiKey { key_id } => vec![user, Authority::ApiKey(key_id.clone())],
            // A user token ends when its row is deleted, and when its client's
            // grant is revoked for the user, as the sign-in it came from does.
            AdmittedCredential::UserToken {
                token_id,
                client_id,
            } => vec![
                user,
                Authority::UserToken(token_id.clone()),
                Authority::OAuthGrant {
                    user_id: self.user_id.clone(),
                    client_id: client_id.clone(),
                },
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Authority {
    User(String),
    Session(String),
    OAuthToken(String),
    OAuthGrant { user_id: String, client_id: String },
    ApiKey(String),
    UserToken(String),
    Membership { user_id: String, org_id: String },
    Organization(String),
}

/// A `pg_current_snapshot()`: which transactions had committed when it was
/// taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Snapshot {
    xmin: u64,
    xmax: u64,
    in_progress: HashSet<u64>,
}

impl Snapshot {
    /// Parses the `xmin:xmax:xip,...` text form. `None` for anything else.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let mut parts = text.split(':');
        let xmin = parts.next()?.parse().ok()?;
        let xmax = parts.next()?.parse().ok()?;
        let in_progress = match parts.next()? {
            "" => HashSet::new(),
            list => list
                .split(',')
                .map(str::parse)
                .collect::<Result<_, _>>()
                .ok()?,
        };
        if parts.next().is_some() || xmin > xmax {
            return None;
        }
        Some(Self {
            xmin,
            xmax,
            in_progress,
        })
    }

    /// Whether a committed transaction had committed when this was taken.
    pub(crate) fn sees(&self, xact: u64) -> bool {
        xact < self.xmin || (xact < self.xmax && !self.in_progress.contains(&xact))
    }
}

/// Where a revoked stream ran, for its `stream.revoked` audit event.
#[derive(Debug, Clone)]
pub struct StreamSite {
    /// The product surface: `terminal`, `exec`, `file`, `attach`, `logs` or
    /// `ssh_proxy`.
    pub surface: &'static str,
    pub environment_id: Option<String>,
}

/// Records that `admitted`'s stream at `site` ended on `revocation`: the
/// user, what was lost, the surface and the environment, never a
/// credential or the stream's contents. A failed write is logged; the stream
/// has ended either way.
pub async fn record_revoked(
    pool: &PgPool,
    admitted: &Admitted,
    revocation: Revocation,
    site: &StreamSite,
) {
    let metadata = serde_json::json!({
        "revocation": revocation.as_str(),
        "surface": site.surface,
        "environment_id": site.environment_id,
    });
    if let Err(error) = sqlx::query(
        "INSERT INTO audit_logs (id, timestamp, action, user_id, ip_address, user_agent, metadata, severity) \
         VALUES ($1, NOW(), 'stream.revoked', $2, '', '', $3, 'info')",
    )
    .bind(uuid::Uuid::new_v4().simple().to_string())
    .bind(&admitted.user_id)
    .bind(&metadata)
    .execute(pool)
    .await
    {
        tracing::error!(%error, surface = site.surface, "failed to record a revoked stream");
    }
}

/// What a Connect stream ends with when its authority is lost.
pub fn revoked_error() -> connectrpc::ConnectError {
    connectrpc::ConnectError::permission_denied("access revoked")
}

/// What a Connect stream ends with on `revocation`: the refusal a new stream
/// gets when its organization's deletion started, else [`revoked_error`].
pub fn ended_error(revocation: Revocation) -> connectrpc::ConnectError {
    match revocation {
        Revocation::Organization => {
            crate::connect::app_error_to_wire(&crate::org::organization_deleting_error(), None)
        }
        _ => revoked_error(),
    }
}

impl Watch {
    /// Completes when the stream's authority is lost, after recording it,
    /// with the Connect error the stream ends on.
    pub fn into_connect_end(
        self,
        pool: PgPool,
        admitted: Admitted,
        site: StreamSite,
    ) -> Pin<Box<dyn Future<Output = connectrpc::ConnectError> + Send>> {
        Box::pin(async move {
            let mut watch = self;
            let revocation = watch.revoked().await;
            record_revoked(&pool, &admitted, revocation, &site).await;
            ended_error(revocation)
        })
    }
}

/// The process's registry of admitted streams. Cloning shares it.
#[derive(Clone)]
pub struct Fence {
    registry: Arc<Mutex<Registry>>,
    /// The log position below which the listener has read every row, or -1
    /// before its first read ([`LogCursor::position`]).
    through: Arc<AtomicI64>,
}

impl Default for Fence {
    fn default() -> Self {
        Self {
            registry: Arc::default(),
            through: Arc::new(AtomicI64::new(-1)),
        }
    }
}

#[derive(Default)]
struct Registry {
    next_id: u64,
    by_key: HashMap<Authority, HashSet<u64>>,
    entries: HashMap<u64, Entry>,
}

struct Entry {
    keys: Vec<Authority>,
    snapshot: Snapshot,
    revoked: watch::Sender<Option<Revocation>>,
}

/// A stream's registration. Dropping it ends the registration.
pub struct Watch {
    registry: Arc<Mutex<Registry>>,
    id: u64,
    revoked: watch::Receiver<Option<Revocation>>,
}

impl Watch {
    /// Completes when the stream's authority is lost, with what was lost.
    pub async fn revoked(&mut self) -> Revocation {
        // The sender lives in the registry entry until this watch drops, so
        // the channel can't close while it waits.
        if let Ok(revoked) = self.revoked.wait_for(Option::is_some).await
            && let Some(revocation) = *revoked
        {
            return revocation;
        }
        std::future::pending().await
    }

    /// [`Watch::revoked`] as an owned future, for a stream to select on. The
    /// registration ends when the future is dropped with its stream.
    pub fn into_signal(mut self) -> Pin<Box<dyn Future<Output = Revocation> + Send>> {
        Box::pin(async move { self.revoked().await })
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let mut registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        registry.remove(self.id);
    }
}

impl Registry {
    fn insert(
        &mut self,
        keys: Vec<Authority>,
        snapshot: Snapshot,
    ) -> (u64, watch::Receiver<Option<Revocation>>) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let (revoked, receiver) = watch::channel(None);
        for key in &keys {
            self.by_key.entry(key.clone()).or_default().insert(id);
        }
        self.entries.insert(
            id,
            Entry {
                keys,
                snapshot,
                revoked,
            },
        );
        (id, receiver)
    }

    fn remove(&mut self, id: u64) {
        let Some(entry) = self.entries.remove(&id) else {
            return;
        };
        for key in entry.keys {
            if let Some(ids) = self.by_key.get_mut(&key) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.by_key.remove(&key);
                }
            }
        }
    }

    fn dispatch(&self, row: &LogEntry) {
        let Some(ids) = self.by_key.get(&row.key) else {
            return;
        };
        for entry in ids.iter().filter_map(|id| self.entries.get(id)) {
            if entry.snapshot.sees(row.xact) {
                continue;
            }
            entry.revoked.send_if_modified(|revoked| {
                let first = revoked.is_none();
                if first {
                    *revoked = Some(row.revocation);
                }
                first
            });
        }
    }
}

/// Whether `user_id` is still a member of `org_id` and the organization
/// still admits streams (`org_admits_streams`).
pub(crate) async fn recheck_membership(
    pool: &PgPool,
    user_id: &str,
    org_id: &str,
) -> Result<(), Refused> {
    let admits: Option<bool> = sqlx::query_scalar(
        "SELECT o.deletion_state = 'active' FROM organizations o \
         JOIN org_members m ON m.org_id = o.id AND m.user_id = $2 \
         WHERE o.id = $1",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        tracing::warn!(%error, "stream admission could not re-read its membership");
        Refused::Unavailable
    })?;
    match admits {
        Some(true) => Ok(()),
        Some(false) => Err(Refused::OrganizationDeleting),
        None => Err(Refused::NotMember),
    }
}

async fn current_snapshot(pool: &PgPool) -> Result<Snapshot, Refused> {
    let text: String = sqlx::query_scalar("SELECT pg_current_snapshot()::text")
        .fetch_one(pool)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "stream admission could not take a snapshot");
            Refused::Unavailable
        })?;
    Snapshot::parse(&text).ok_or_else(|| {
        tracing::warn!(snapshot = %text, "stream admission read an unparseable snapshot");
        Refused::Unavailable
    })
}

impl Fence {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits a stream: takes a snapshot, registers `admitted` with it, then
    /// runs `recheck`, which must be the same check that admitted the stream.
    ///
    /// `recheck` is a future, so it starts only when awaited here, after the
    /// registration. Each of its statements runs under READ COMMITTED with a
    /// snapshot taken when it starts, so never older than the one registered:
    /// a revocation the registered snapshot doesn't see either reaches the
    /// registration or is seen by the re-read, which refuses.
    ///
    /// A stream into an organization's environment also has its membership
    /// and the organization re-read here, on `pool`, the primary: a removal
    /// or a deletion between admission and registration refuses it.
    pub async fn admit(
        &self,
        pool: &PgPool,
        admitted: &Admitted,
        recheck: impl Future<Output = Result<(), Refused>>,
    ) -> Result<Watch, Refused> {
        let watch = self.register(admitted, current_snapshot(pool).await?);
        recheck.await?;
        if let Some(org_id) = &admitted.organization {
            recheck_membership(pool, &admitted.user_id, org_id).await?;
        }
        Ok(watch)
    }

    fn register(&self, admitted: &Admitted, snapshot: Snapshot) -> Watch {
        let (id, revoked) = self
            .registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(admitted.keys(), snapshot);
        Watch {
            registry: Arc::clone(&self.registry),
            id,
            revoked,
        }
    }

    fn dispatch(&self, rows: &[LogEntry]) {
        let registry = self.registry.lock().unwrap_or_else(PoisonError::into_inner);
        for row in rows {
            registry.dispatch(row);
        }
    }

    /// Runs the process's listener on `pool`, reconnecting after failures.
    pub fn spawn_listener(&self, pool: PgPool) -> tokio::task::JoinHandle<()> {
        self.spawn_listener_every(pool, BACKSTOP)
    }

    pub(crate) fn spawn_listener_every(
        &self,
        pool: PgPool,
        backstop: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let fence = self.clone();
        tokio::spawn(async move {
            let mut cursor = LogCursor::default();
            loop {
                if let Err(error) = fence.listen(&pool, &mut cursor, backstop).await {
                    tracing::warn!(%error, "credential revocation listener failed");
                }
                tokio::time::sleep(LISTENER_RETRY).await;
            }
        })
    }

    async fn listen(
        &self,
        pool: &PgPool,
        cursor: &mut LogCursor,
        backstop: Duration,
    ) -> Result<(), ListenerError> {
        let mut listener = PgListener::connect_with(pool).await?;
        listener.listen(CHANNEL).await?;
        // Rows committed while unsubscribed sent no wake-up.
        self.read_log(pool, cursor).await?;
        let mut tick = tokio::time::interval(backstop);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                notification = listener.try_recv() => {
                    // `None` is a lost connection; reconnect from the caller
                    // so the read above follows the new subscription.
                    if notification?.is_none() {
                        return Err(ListenerError::ConnectionLost);
                    }
                }
                _ = tick.tick() => {}
            }
            self.read_log(pool, cursor).await?;
        }
    }

    /// Reads the log after `cursor` and the numbers it skipped, and ends the
    /// streams the new rows name.
    pub(crate) async fn read_log(
        &self,
        pool: &PgPool,
        cursor: &mut LogCursor,
    ) -> Result<(), sqlx::Error> {
        let gaps: Vec<i64> = cursor.gaps.keys().copied().collect();
        let rows: Vec<LogRow> = sqlx::query_as(
            "SELECT seq, kind, credential_id, user_id, org_id, xact::text AS xact \
             FROM credential_revocations \
             WHERE seq > $1 OR seq = ANY($2) \
             ORDER BY seq",
        )
        .bind(cursor.last.unwrap_or(0))
        .bind(&gaps)
        .fetch_all(pool)
        .await?;
        let entries: Vec<LogEntry> = rows.iter().filter_map(LogRow::entry).collect();
        self.dispatch(&entries);
        cursor.record(rows.iter().map(|row| row.seq), Instant::now());
        self.through.store(cursor.position(), Ordering::Release);
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
enum ListenerError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("the listener's connection was lost")]
    ConnectionLost,
}

#[derive(sqlx::FromRow)]
struct LogRow {
    seq: i64,
    kind: String,
    credential_id: String,
    user_id: String,
    org_id: Option<String>,
    xact: String,
}

struct LogEntry {
    key: Authority,
    revocation: Revocation,
    xact: u64,
}

impl LogRow {
    fn entry(&self) -> Option<LogEntry> {
        let (Some(revocation), Ok(xact)) = (Revocation::parse(&self.kind), self.xact.parse())
        else {
            tracing::warn!(seq = self.seq, kind = %self.kind, "unreadable credential revocation row");
            return None;
        };
        let id = self.credential_id.clone();
        let key = match revocation {
            Revocation::User => Authority::User(id),
            Revocation::Session => Authority::Session(id),
            Revocation::OAuthToken => Authority::OAuthToken(id),
            Revocation::OAuthGrant => Authority::OAuthGrant {
                user_id: self.user_id.clone(),
                client_id: id,
            },
            Revocation::ApiKey => Authority::ApiKey(id),
            Revocation::UserToken => Authority::UserToken(id),
            Revocation::Membership | Revocation::Organization => {
                let Some(org_id) = self.org_id.clone() else {
                    tracing::warn!(seq = self.seq, kind = %self.kind, "unreadable credential revocation row");
                    return None;
                };
                if revocation == Revocation::Membership {
                    Authority::Membership {
                        user_id: self.user_id.clone(),
                        org_id,
                    }
                } else {
                    Authority::Organization(org_id)
                }
            }
        };
        Some(LogEntry {
            key,
            revocation,
            xact,
        })
    }
}

/// Where the listener has read to. Sequence numbers are taken in the order
/// writes start, not the order they commit, so a number below the newest
/// read may still appear: each skipped one is read again until it does or
/// until [`GAP_LIFETIME`].
#[derive(Debug, Default)]
pub(crate) struct LogCursor {
    last: Option<i64>,
    gaps: BTreeMap<i64, Instant>,
}

impl LogCursor {
    fn record(&mut self, seqs: impl Iterator<Item = i64>, now: Instant) {
        let mut seqs: Vec<i64> = seqs.collect();
        seqs.sort_unstable();
        for seq in &seqs {
            self.gaps.remove(seq);
        }
        let mut expected = self.last.map(|last| last.saturating_add(1));
        for &seq in &seqs {
            if self.last.is_some_and(|last| seq <= last) {
                continue;
            }
            if let Some(from) = expected {
                for skipped in from..seq {
                    self.gaps.insert(skipped, now);
                }
            }
            expected = Some(seq.saturating_add(1));
            self.last = Some(seq);
        }
        self.gaps
            .retain(|_, since| now.saturating_duration_since(*since) < GAP_LIFETIME);
        while self.gaps.len() > MAX_GAPS {
            self.gaps.pop_first();
        }
    }

    /// The highest position at and below which every row has been read: just
    /// below the oldest skipped number still awaited, else the newest read,
    /// else 0 when the log has held nothing.
    fn position(&self) -> i64 {
        match self.gaps.first_key_value() {
            Some((&gap, _)) => gap.saturating_sub(1),
            None => self.last.unwrap_or(0),
        }
    }
}

mod carried;
pub use carried::CarriedAdmission;

#[cfg(test)]
mod database_tests;
#[cfg(test)]
mod tests;
