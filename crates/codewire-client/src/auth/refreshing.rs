//! The refreshing token provider: OAuth credentials from a store, renewed
//! through their refresh token. Moved from the parent module with no change in
//! behaviour.

use super::*;

/// A refresh-on-demand provider backed by an atomic credential store. The
/// mutex coalesces concurrent RPC refreshes so a rotated refresh token is not
/// replayed by another local request.
pub struct RefreshingTokenProvider<S = FileCredentialStore> {
    client: OAuthClient,
    store: S,
    credentials: Mutex<OAuthCredentials>,
    pub(super) lock_wait: Duration,
}

/// How long a refresh waits for another process's refresh to finish before
/// going ahead without the lock: a stuck or suspended process must not stop
/// every other one from refreshing.
const REFRESH_LOCK_WAIT: Duration = Duration::from_secs(30);
const REFRESH_LOCK_POLL: Duration = Duration::from_millis(100);

impl<S: CredentialStore> RefreshingTokenProvider<S> {
    pub fn from_store(client: OAuthClient, store: S) -> Result<Self, ClientError> {
        let credentials = store.load()?.ok_or_else(|| {
            ClientError::new(ErrorCode::Unauthenticated, "OAuth credentials unavailable")
        })?;
        if credentials.issuer != client.discovery.issuer {
            return Err(ClientError::new(
                ErrorCode::Unauthenticated,
                "OAuth credentials are not for this Codewire server",
            ));
        }
        Ok(Self {
            client,
            store,
            credentials: Mutex::new(credentials),
            lock_wait: REFRESH_LOCK_WAIT,
        })
    }

    pub fn new(
        client: OAuthClient,
        store: S,
        credentials: OAuthCredentials,
    ) -> Result<Self, ClientError> {
        if credentials.issuer != client.discovery.issuer {
            return Err(ClientError::new(
                ErrorCode::Unauthenticated,
                "OAuth credentials are not for this Codewire server",
            ));
        }
        Ok(Self {
            client,
            store,
            credentials: Mutex::new(credentials),
            lock_wait: REFRESH_LOCK_WAIT,
        })
    }
}

#[async_trait]
impl<S: CredentialStore> TokenProvider for RefreshingTokenProvider<S> {
    async fn token(&self) -> Result<BearerToken, ClientError> {
        let mut credentials = self.credentials.lock().await;
        if credentials.is_fresh() {
            return credentials.bearer_token();
        }
        self.renew(&mut credentials, None).await
    }

    /// A refused access token is renewed once: another call or process may
    /// already have renewed it, and then its token is used instead.
    async fn after_refusal(
        &self,
        rejected: &BearerToken,
    ) -> Result<Option<BearerToken>, ClientError> {
        let mut credentials = self.credentials.lock().await;
        if credentials.access_token != rejected.expose_secret() {
            return credentials.bearer_token().map(Some);
        }
        self.renew(&mut credentials, Some(rejected)).await.map(Some)
    }
}

impl<S: CredentialStore> RefreshingTokenProvider<S> {
    /// A refresh token is single-use, and presenting a rotated one is
    /// refused. Another process sharing the store may have refreshed since
    /// this one loaded it: under the store's lock, adopt the pair it saved
    /// when that pair will do (fresh, or not the `rejected` token), and
    /// refresh only otherwise.
    async fn renew(
        &self,
        credentials: &mut OAuthCredentials,
        rejected: Option<&BearerToken>,
    ) -> Result<BearerToken, ClientError> {
        let _lock = match self.store.refresh_lock_path() {
            Some(path) => lock_refresh(&path, self.lock_wait).await?,
            None => None,
        };
        if let Some(stored) = self.store.load()?
            && stored.issuer == credentials.issuer
            && stored.refresh_token() != credentials.refresh_token()
        {
            *credentials = stored;
            let usable = match rejected {
                None => credentials.is_fresh(),
                Some(rejected) => credentials.access_token != rejected.expose_secret(),
            };
            if usable {
                return credentials.bearer_token();
            }
        }
        let refreshed = self
            .client
            .refresh(credentials)
            .await
            .map_err(AuthClientError::into_client_error)?;
        self.store.save(&refreshed)?;
        *credentials = refreshed;
        credentials.bearer_token()
    }
}

/// An exclusive lock on `path`, held until the returned file is dropped, or
/// `None` once `wait` passes with another process still holding it: the
/// caller then refreshes without it, as before this lock existed.
pub(super) async fn lock_refresh(
    path: &Path,
    wait: Duration,
) -> Result<Option<fs::File>, ClientError> {
    let file = credential_lock_file(path)?;
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(Some(file)),
            Err(fs::TryLockError::WouldBlock) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(REFRESH_LOCK_POLL).await;
            }
            Err(fs::TryLockError::WouldBlock) => {
                tracing::warn!(
                    wait_secs = wait.as_secs(),
                    "another process kept the OAuth credentials locked; refreshing without the lock"
                );
                return Ok(None);
            }
            Err(fs::TryLockError::Error(_)) => {
                return Err(credential_error("lock OAuth credentials for refresh"));
            }
        }
    }
}
