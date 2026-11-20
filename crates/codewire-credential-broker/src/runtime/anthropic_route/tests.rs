//! A Claude sign-in the provider rejects (#3999 change 6): refreshed once
//! outside the environment and its request sent once more, but only when the
//! sign-in was last refreshed ten minutes ago or more, by the time stored in
//! the sign-in. The 401 is read to its end first, so nothing upstream is held
//! open during the exchange, and a refresh that fails answers that 401. The
//! API-key and subscription-token forms, which are never retried, are in
//! `anthropic_subscription_tests.rs`.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use codewire_access::{CredentialId, CredentialMetadata, CredentialPlaceholder};
use tokio::sync::Barrier;

use super::super::forced_refresh::{FORCED_REFRESH_MIN_AGE, HELD_REJECTION_MAX_BYTES};
use super::super::*;
use crate::claude_oauth::{ClaudeIssuedTokens, ClaudeProfile, import_tokens_at};
use crate::http_test_support::Lease;

const TOKEN_ENDPOINT: &str = "https://platform.claude.com/v1/oauth/token";
const SCOPES: &str = "user:inference user:profile";
const ACCESS_TOKEN_LIFETIME_SECONDS: u64 = 28_800;
/// Old enough for a 401 to force a refresh.
const OLD: u64 = FORCED_REFRESH_MIN_AGE.as_secs();
/// Too young, with a minute to spare for a slow test run.
const YOUNG: u64 = OLD - 60;
/// The API's 401.
const REJECTION: &str =
    r#"{"type":"error","error":{"type":"authentication_error","message":"synthetic rejection"}}"#;
/// The chunks a 401's body arrives in.
const REJECTION_CHUNK_BYTES: usize = 16 * 1024;

/// A 401 too long to hold while the sign-in refreshes.
fn oversized_rejection() -> String {
    let message = "r".repeat(HELD_REJECTION_MAX_BYTES + 1);
    format!(r#"{{"type":"error","error":{{"type":"authentication_error","message":"{message}"}}}}"#)
}

/// Counts a 401's body from when the provider answers until the broker lets
/// go of it.
struct OpenRejection(Arc<AtomicUsize>);

impl OpenRejection {
    fn new(open: &Arc<AtomicUsize>) -> Self {
        open.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(open))
    }
}

impl Drop for OpenRejection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn access_token(refreshes: usize) -> String {
    format!("synthetic-sign-in-access-{refreshes}")
}

/// The stored sign-in and how often it was refreshed.
struct Journal {
    bundle: Vec<u8>,
    generation: u64,
    begun: usize,
    committed: usize,
    failed: usize,
    /// The authority refuses to start a refresh it has reserved.
    refuses_start: bool,
    /// The authority refuses to begin a refresh of this sign-in.
    refuses_begin: bool,
    leases: usize,
    /// Leases after this many are of another credential, as when the
    /// environment is bound to another sign-in.
    rebind_after_leases: Option<usize>,
}

/// A sign-in whose access token was issued `age_seconds` ago.
fn journal(age_seconds: u64) -> Arc<Mutex<Journal>> {
    let (bundle, _) = import_tokens_at(
        ClaudeIssuedTokens {
            access_token: Zeroizing::new(access_token(0)),
            refresh_token: Some(Zeroizing::new("synthetic-sign-in-refresh-0".into())),
            expires_in: ACCESS_TOKEN_LIFETIME_SECONDS,
            refresh_token_expires_in: None,
            scope: Some(SCOPES.into()),
        },
        ClaudeProfile::default(),
        current_unix_time().unwrap() - age_seconds,
    )
    .unwrap()
    .into_parts();
    Arc::new(Mutex::new(Journal {
        bundle: bundle.into_bytes().to_vec(),
        generation: 1,
        begun: 0,
        committed: 0,
        failed: 0,
        refuses_start: false,
        refuses_begin: false,
        leases: 0,
        rebind_after_leases: None,
    }))
}

struct SignInLease {
    lease: Lease,
    generation: u64,
}

impl BrokerCredentialLease for SignInLease {
    fn credential_metadata(&self) -> &CredentialMetadata {
        self.lease.credential_metadata()
    }
    fn grant(&self) -> &DerivedGrant {
        self.lease.grant()
    }
    fn permission(&self) -> &GrantPermission {
        self.lease.permission()
    }
    fn material_generation(&self) -> u64 {
        self.generation
    }
    fn with_material<T>(self, operation: impl FnOnce(&[u8]) -> T) -> T {
        self.lease.with_material(operation)
    }
    fn placeholder(&self) -> Option<&CredentialPlaceholder> {
        self.lease.placeholder()
    }
}

struct Authority {
    journal: Arc<Mutex<Journal>>,
}

#[async_trait]
impl BrokerLeaseProvider for Authority {
    type Lease = SignInLease;
    type RefreshReservation = ();
    type StartedRefresh = ();
    async fn lease_operation(
        &self,
        _id: Uuid,
        _slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<SignInLease, BrokerLeaseError> {
        let mut journal = self.journal.lock().unwrap();
        journal.leases += 1;
        let mut lease = Lease::new(
            "anthropic",
            CredentialAuthKind::ClaudeSignIn,
            "anthropic",
            operation.as_str(),
            route.as_str(),
        );
        lease.material = Zeroizing::new(journal.bundle.clone());
        if journal
            .rebind_after_leases
            .is_some_and(|leases| journal.leases > leases)
        {
            let other = CredentialId::parse("33333333-3333-4333-8333-333333333333").unwrap();
            lease.grant.credential_id = other.clone();
            lease.metadata.id = other;
        }
        Ok(SignInLease {
            lease,
            generation: journal.generation,
        })
    }
    async fn begin_credential_refresh(
        &self,
        request: BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<()>, BrokerRefreshError> {
        let mut journal = self.journal.lock().unwrap();
        if journal.refuses_begin {
            return Err(BrokerRefreshError::Denied);
        }
        if request.material_generation != journal.generation {
            return Err(BrokerRefreshError::Stale);
        }
        journal.begun += 1;
        Ok(BrokerRefreshAdmission::Reserved(()))
    }
    async fn start_credential_refresh(&self, (): ()) -> Result<(), BrokerRefreshError> {
        if self.journal.lock().unwrap().refuses_start {
            return Err(BrokerRefreshError::Unavailable);
        }
        Ok(())
    }
    async fn commit_credential_refresh(
        &self,
        (): (),
        _: CanonicalCodexOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        panic!("a Claude sign-in never commits a Codex login")
    }
    async fn commit_claude_oauth_refresh(
        &self,
        (): (),
        bundle: CanonicalClaudeOAuthBundle,
    ) -> Result<(), CommitFailure<Self::StartedRefresh>> {
        let mut journal = self.journal.lock().unwrap();
        journal.bundle = bundle.into_bytes().to_vec();
        journal.generation += 1;
        journal.committed += 1;
        Ok(())
    }
    async fn abort_credential_refresh(&self, (): ()) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
    async fn fail_credential_refresh(&self, (): ()) -> Result<(), BrokerRefreshError> {
        self.journal.lock().unwrap().failed += 1;
        Ok(())
    }
    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
}

/// The API, answering each request with the next scripted status and then
/// 200, and the token endpoint, answering each exchange with the next
/// scripted failure and then a numbered access token.
#[derive(Default)]
struct Provider {
    answers: Mutex<VecDeque<StatusCode>>,
    /// A bearer the API rejects whenever it arrives, whatever `answers` says.
    rejected_bearer: Option<String>,
    /// Each API request's bearer and body, in order.
    requests: Mutex<Vec<(String, Vec<u8>)>>,
    token_failures: Mutex<VecDeque<(StatusCode, &'static str)>>,
    /// Every request the token endpoint received, failed ones included.
    refreshes: AtomicUsize,
    /// The API's 401 body, when not `REJECTION`.
    rejection: Option<String>,
    /// The 401 bodies the broker has not yet let go of.
    open_rejections: Arc<AtomicUsize>,
    /// The exchanges that arrived while a 401's body was still open.
    refreshes_during_an_open_rejection: AtomicUsize,
    /// Holds the first two API requests until both have arrived.
    gate: Option<Barrier>,
    gated: AtomicUsize,
}

#[async_trait]
impl BrokerUpstreamTransport for Provider {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (_, target, headers, body) = request.into_parts();
        let (status, body) = if target.as_str() == TOKEN_ENDPOINT {
            let refreshes = self.refreshes.fetch_add(1, Ordering::Relaxed) + 1;
            if self.open_rejections.load(Ordering::Relaxed) > 0 {
                self.refreshes_during_an_open_rejection
                    .fetch_add(1, Ordering::Relaxed);
            }
            let failure = self.token_failures.lock().unwrap().pop_front();
            if let Some((status, body)) = failure {
                (status, body.to_owned())
            } else {
                let answer = serde_json::json!({
                    "access_token": access_token(refreshes),
                    "refresh_token": format!("synthetic-sign-in-refresh-{refreshes}"),
                    "expires_in": ACCESS_TOKEN_LIFETIME_SECONDS,
                    "scope": SCOPES,
                });
                (StatusCode::OK, answer.to_string())
            }
        } else {
            let bearer = headers["authorization"].to_str().unwrap().to_owned();
            let rejected = self.rejected_bearer.as_deref() == Some(bearer.as_str());
            self.requests.lock().unwrap().push((bearer, body));
            if let Some(gate) = &self.gate
                && self.gated.fetch_add(1, Ordering::Relaxed) < 2
            {
                gate.wait().await;
            }
            let scripted = self.answers.lock().unwrap().pop_front();
            if rejected || scripted == Some(StatusCode::UNAUTHORIZED) {
                let rejection = self.rejection.as_deref().unwrap_or(REJECTION);
                return Ok(json_response(
                    StatusCode::UNAUTHORIZED,
                    rejection,
                    Some(OpenRejection::new(&self.open_rejections)),
                ));
            }
            (scripted.unwrap_or(StatusCode::OK), "{}".to_owned())
        };
        Ok(json_response(status, &body, None))
    }
}

/// A JSON reply in chunks of `REJECTION_CHUNK_BYTES`. `open` lives as long as
/// the body's stream does.
fn json_response(
    status: StatusCode,
    body: &str,
    open: Option<OpenRejection>,
) -> BrokerUpstreamResponse {
    let chunks: Vec<Result<Bytes, BrokerUpstreamError>> = body
        .as_bytes()
        .chunks(REJECTION_CHUNK_BYTES)
        .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
        .collect();
    BrokerUpstreamResponse::new(
        status,
        HeaderMap::from_iter([(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]),
        Box::pin(futures::stream::iter(chunks).map(move |chunk| {
            let _open = &open;
            chunk
        })),
    )
}

type SignInBroker = OpenAiBroker<Authority, Provider>;

fn broker(journal: &Arc<Mutex<Journal>>) -> SignInBroker {
    broker_with(journal, Provider::default())
}

fn broker_with(journal: &Arc<Mutex<Journal>>, provider: Provider) -> SignInBroker {
    OpenAiBroker::new(
        Authority {
            journal: Arc::clone(journal),
        },
        provider,
    )
    .unwrap()
}

const BODY: &[u8] = br#"{"model":"synthetic","max_tokens":1,"messages":[]}"#;

/// One Messages request, answered by the provider with `answers` in turn.
async fn send(broker: &SignInBroker, answers: &[StatusCode]) -> StatusCode {
    try_send(broker, answers).await.unwrap().0
}

/// One Messages request's status and the body the guest reads.
async fn try_send(
    broker: &SignInBroker,
    answers: &[StatusCode],
) -> Result<(StatusCode, Vec<u8>), BrokerRequestError> {
    broker
        .upstream
        .answers
        .lock()
        .unwrap()
        .extend(answers.iter().copied());
    let header = |name: &str, value: &str| v1::CredentialHttpHeader {
        name: name.into(),
        value: value.as_bytes().to_vec(),
    };
    let response = broker
        .execute(v1::CredentialBridgeRequest {
            request_id: Uuid::new_v4().to_string(),
            capability_slot: "anthropic".into(),
            route: "anthropic-api".into(),
            method: "POST".into(),
            path: "/v1/messages".into(),
            query: String::new(),
            headers: vec![
                header("content-type", "application/json"),
                header("anthropic-version", "2023-06-01"),
                header("authorization", "Bearer codewire-managed"),
            ],
            body: BODY.to_vec(),
            intercepted_host: String::new(),
            destination_ip: String::new(),
            streamed_body: false,
            intercept_decision: Vec::new(),
        })
        .await?;
    let (status, _, mut body) = response.into_parts();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await {
        bytes.extend(chunk.unwrap());
    }
    Ok((status, bytes))
}

/// The bearer of each request the API received, in order.
fn bearers(broker: &SignInBroker) -> Vec<String> {
    let requests = broker.upstream.requests.lock().unwrap();
    assert!(requests.iter().all(|(_, body)| body == BODY));
    requests.iter().map(|(bearer, _)| bearer.clone()).collect()
}

fn bearer(refreshes: usize) -> String {
    format!("Bearer {}", access_token(refreshes))
}

fn refreshes(broker: &SignInBroker) -> usize {
    broker.upstream.refreshes.load(Ordering::Relaxed)
}

fn refreshes_during_an_open_rejection(broker: &SignInBroker) -> usize {
    broker
        .upstream
        .refreshes_during_an_open_rejection
        .load(Ordering::Relaxed)
}

fn provider_rejecting_with(rejection: Option<String>) -> Provider {
    Provider {
        rejection,
        ..Provider::default()
    }
}

/// What the guest reads of a 401 that nothing retries: the same rejection on
/// a sign-in too young for a forced refresh.
async fn the_unretried_401(rejection: Option<String>) -> Vec<u8> {
    let journal = journal(YOUNG);
    let broker = broker_with(&journal, provider_rejecting_with(rejection));
    let (status, body) = try_send(&broker, &[StatusCode::UNAUTHORIZED])
        .await
        .unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(refreshes(&broker), 0);
    assert!(!body.is_empty());
    body
}

#[tokio::test]
async fn a_rejected_sign_in_is_refreshed_once_and_its_request_sent_once_more() {
    let journal = journal(OLD);
    let broker = broker(&journal);
    let status = send(&broker, &[StatusCode::UNAUTHORIZED, StatusCode::OK]).await;
    assert_eq!(status, StatusCode::OK);
    // The same request, first with the rejected token, then the fresh one.
    assert_eq!(bearers(&broker), [bearer(0), bearer(1)]);
    assert_eq!(refreshes(&broker), 1);
    // The 401 was read to its end before the exchange was sent.
    assert_eq!(refreshes_during_an_open_rejection(&broker), 0);
    let journal = journal.lock().unwrap();
    assert_eq!((journal.begun, journal.committed), (1, 1));
}

#[tokio::test]
async fn a_second_401_is_returned_after_one_refresh_and_one_retry() {
    let journal = journal(OLD);
    let broker = broker(&journal);
    let rejected = [StatusCode::UNAUTHORIZED; 2];
    assert_eq!(send(&broker, &rejected).await, StatusCode::UNAUTHORIZED);
    assert_eq!(bearers(&broker), [bearer(0), bearer(1)]);
    assert_eq!(refreshes(&broker), 1);
}

/// A token refreshed moments ago and still rejected is not fixed by another
/// exchange.
#[tokio::test]
async fn a_401_on_a_sign_in_refreshed_under_ten_minutes_ago_refreshes_nothing() {
    let journal = journal(YOUNG);
    let broker = broker(&journal);
    assert_eq!(
        send(&broker, &[StatusCode::UNAUTHORIZED]).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(bearers(&broker), [bearer(0)]);
    assert_eq!(refreshes(&broker), 0);
    assert_eq!(journal.lock().unwrap().begun, 0);
}

/// A 401 too long to hold in memory is answered as it is: nothing upstream
/// is held open during an exchange, so there is no exchange.
#[tokio::test]
async fn a_401_too_long_to_hold_is_returned_whole_and_refreshes_nothing() {
    let unretried = the_unretried_401(Some(oversized_rejection())).await;
    let journal = journal(OLD);
    let broker = broker_with(
        &journal,
        provider_rejecting_with(Some(oversized_rejection())),
    );
    let (status, body) = try_send(&broker, &[StatusCode::UNAUTHORIZED])
        .await
        .unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        body == unretried,
        "the long 401 is answered as an unretried one"
    );
    assert_eq!(bearers(&broker), [bearer(0)]);
    assert_eq!(refreshes(&broker), 0);
    assert_eq!(journal.lock().unwrap().begun, 0);
}

/// The age that counts is that of the token the request was sent with: here
/// the one the expiry refresh issued a moment before.
#[tokio::test]
async fn a_sign_in_refreshed_before_sending_and_then_rejected_is_not_refreshed_again() {
    let journal = journal(ACCESS_TOKEN_LIFETIME_SECONDS - 100);
    let broker = broker(&journal);
    assert_eq!(
        send(&broker, &[StatusCode::UNAUTHORIZED]).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(bearers(&broker), [bearer(1)]);
    assert_eq!(refreshes(&broker), 1);
}

/// The time is stored with the sign-in, so the bound holds across brokers
/// and their restarts: a broker with nothing in memory reads the refresh
/// another one forced.
#[tokio::test]
async fn another_broker_cannot_force_a_second_refresh_of_the_same_sign_in() {
    let journal = journal(OLD);
    let first = broker(&journal);
    let status = send(&first, &[StatusCode::UNAUTHORIZED, StatusCode::OK]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(refreshes(&first), 1);

    let second = broker(&journal);
    assert_eq!(
        send(&second, &[StatusCode::UNAUTHORIZED]).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(bearers(&second), [bearer(1)]);
    assert_eq!(refreshes(&second), 0);
    let journal = journal.lock().unwrap();
    assert_eq!((journal.begun, journal.committed), (1, 1));
}

/// Nothing bounds a retry, only an exchange: a request rejected for a token
/// another request has already replaced is sent once more with the new one.
#[tokio::test]
async fn two_requests_rejected_for_one_token_cause_one_refresh_and_both_are_retried() {
    let journal = journal(OLD);
    let broker = broker_with(
        &journal,
        Provider {
            // Both requests are held until both have arrived with the old
            // token, and the API rejects that token whichever asks.
            gate: Some(Barrier::new(2)),
            rejected_bearer: Some(bearer(0)),
            ..Provider::default()
        },
    );
    let (first, second) = tokio::join!(send(&broker, &[]), send(&broker, &[]));
    assert_eq!((first, second), (StatusCode::OK, StatusCode::OK));
    // Both were sent with the old token, and both again with the new one.
    assert_eq!(
        bearers(&broker),
        [bearer(0), bearer(0), bearer(1), bearer(1)]
    );
    assert_eq!(refreshes(&broker), 1);
    let journal = journal.lock().unwrap();
    assert_eq!((journal.begun, journal.committed), (1, 1));
}

/// One request, one failed exchange, and the provider's 401 as the answer.
async fn assert_a_failed_forced_refresh_returns_the_first_401(failure: (StatusCode, &'static str)) {
    let journal = journal(OLD);
    let broker = broker(&journal);
    broker
        .upstream
        .token_failures
        .lock()
        .unwrap()
        .push_back(failure);
    let (status, body) = try_send(&broker, &[StatusCode::UNAUTHORIZED])
        .await
        .unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{failure:?}");
    // The guest reads what it reads of a 401 nothing retried.
    assert_eq!(body, the_unretried_401(None).await, "{failure:?}");
    // The request was not sent a second time.
    assert_eq!(bearers(&broker), [bearer(0)], "{failure:?}");
    assert_eq!(refreshes(&broker), 1, "{failure:?}");
    assert_eq!(
        refreshes_during_an_open_rejection(&broker),
        0,
        "{failure:?}"
    );
    // The started attempt is recorded as failed, as for every refresh.
    let journal = journal.lock().unwrap();
    assert_eq!(
        (journal.begun, journal.committed, journal.failed),
        (1, 0, 1),
        "{failure:?}"
    );
}

/// The agent then asks the token endpoint itself, which tells it the login
/// is gone.
#[tokio::test]
async fn a_forced_refresh_the_provider_refuses_returns_the_first_401() {
    assert_a_failed_forced_refresh_returns_the_first_401((
        StatusCode::BAD_REQUEST,
        r#"{"error":"invalid_grant"}"#,
    ))
    .await;
}

#[tokio::test]
async fn a_forced_refresh_answered_429_or_503_returns_the_first_401() {
    for status in [
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        assert_a_failed_forced_refresh_returns_the_first_401((status, "{}")).await;
    }
}

/// `AuthorityUnavailable` ends the epoch, so it is never turned into a 401.
#[tokio::test]
async fn a_forced_refresh_the_authority_cannot_start_fails_the_request() {
    let journal = journal(OLD);
    journal.lock().unwrap().refuses_start = true;
    let broker = broker(&journal);
    let failed = try_send(&broker, &[StatusCode::UNAUTHORIZED]).await;
    assert_eq!(
        failed.unwrap_err(),
        BrokerRequestError::AuthorityUnavailable
    );
    assert_eq!(bearers(&broker), [bearer(0)]);
    assert_eq!(refreshes(&broker), 0);
}

/// A retry the authority refuses to lease, because the environment is now
/// bound to another sign-in, is the request's denial, not the provider's 401:
/// the provider never judged that (#4974).
#[tokio::test]
async fn a_sign_in_unbound_while_its_401_is_held_is_a_denial() {
    let journal = journal(OLD);
    journal.lock().unwrap().rebind_after_leases = Some(1);
    let broker = broker(&journal);
    let failed = try_send(&broker, &[StatusCode::UNAUTHORIZED]).await;
    assert_eq!(failed.unwrap_err(), BrokerRequestError::Denied);
    assert_eq!(bearers(&broker), [bearer(0)]);
    assert_eq!(refreshes(&broker), 0);
}

/// The authority refusing to begin the refresh is the same fact as a refused
/// re-lease, so it is the request's denial too (#4974).
#[tokio::test]
async fn a_forced_refresh_the_authority_refuses_to_begin_is_a_denial() {
    let journal = journal(OLD);
    journal.lock().unwrap().refuses_begin = true;
    let broker = broker(&journal);
    let failed = try_send(&broker, &[StatusCode::UNAUTHORIZED]).await;
    assert_eq!(failed.unwrap_err(), BrokerRequestError::Denied);
    assert_eq!(bearers(&broker), [bearer(0)]);
    assert_eq!(refreshes(&broker), 0);
}
