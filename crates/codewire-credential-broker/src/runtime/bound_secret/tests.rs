use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use codewire_access::{
    ApplicationSecretKey, BoundHeader, BoundHost, BrokerOperationId, BrokerRouteId, CapabilitySlot,
    EnvironmentId, PLACEHOLDER_KEY_BYTES, PlaceholderKey, PlaceholderPrefix, ReservedHosts,
};
use codewire_daemon_proto::codewire::bridge::v1;
use futures::StreamExt as _;
use uuid::Uuid;

use super::*;
use crate::bound_secret::{BoundSecretRow, EpochBoundSecret};
use crate::http_test_support::Lease;
use crate::{
    BrokerLeaseError, BrokerRefreshAdmission, BrokerRefreshError, BrokerUpstreamError,
    BrokerUpstreamResponse, CanonicalCodexOAuthBundle, CommitFailure,
};

const HOST: &str = "api.fancy.com";
const OTHER_HOST: &str = "api.other.com";
const PROJECT: &str =
    "/projects/0f8a4c1e3b2d4e5f8a9b1c2d3e4f5a6b/7d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
const DESTINATION: &str = "203.0.113.7";
/// A synthetic canary whose JSON-escaped, percent-encoded and base64 forms
/// all differ from it.
const VALUE: &[u8] = b"syn\"thetic\\canary+/=1";
const WAIT: Duration = Duration::from_secs(10);

fn environment() -> EnvironmentId {
    EnvironmentId::parse("a94ef1b4-bbbc-45dd-aa7f-143b8d1f8417").unwrap()
}

fn key() -> ApplicationSecretKey {
    ApplicationSecretKey::derive(&PlaceholderKey::from_slice(&[9; PLACEHOLDER_KEY_BYTES]).unwrap())
}

fn record(key_name: &str, binding: u128, hosts: &[&str]) -> FirstBindSecret {
    FirstBindSecret {
        path: PROJECT.into(),
        key: key_name.into(),
        binding_id: Uuid::from_u128(binding).to_string(),
        binding_generation: 2,
        prefix: Some("ft_".into()),
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
    }
}

fn grant(record: FirstBindSecret) -> EpochBoundSecret {
    let placeholder = record.placeholder(&key(), &environment()).unwrap();
    EpochBoundSecret {
        record,
        placeholder,
    }
}

fn binding(presentation: Presentation, hosts: &[&str]) -> HostBinding {
    HostBinding::new(
        hosts
            .iter()
            .map(|host| BoundHost::parse(host, &ReservedHosts::default()).unwrap())
            .collect(),
        presentation,
        Some(PlaceholderPrefix::parse("ft_").unwrap()),
    )
    .unwrap()
}

fn header_presentation(headers: &[&str], scheme: &str) -> Presentation {
    Presentation::header(
        headers
            .iter()
            .map(|name| BoundHeader::parse(name).unwrap())
            .collect(),
        Scheme::parse(scheme).unwrap(),
    )
    .unwrap()
}

/// What the fake authority answers and what it was asked.
/// One audit line as the test keeps it: key, scope, host, presentation and
/// outcome.
type AuditLine = (String, &'static str, String, &'static str, &'static str);

/// A refusal case: the request's headers, its query and body, and the code.
type RefusalCase<'a> = (Vec<(&'a str, String)>, (String, Vec<u8>), &'a str);

struct Leases {
    grants: Result<Vec<EpochBoundSecret>, BoundSecretLeaseError>,
    row: Mutex<Result<BoundSecretRow, BoundSecretLeaseError>>,
    rows: AtomicUsize,
    values: AtomicUsize,
    audits: Mutex<Vec<AuditLine>>,
}

impl Leases {
    fn new(grants: Vec<EpochBoundSecret>, presentation: Presentation) -> Self {
        Self {
            grants: Ok(grants),
            row: Mutex::new(Ok(BoundSecretRow {
                binding: binding(presentation, &[HOST]),
                value_version: 1,
            })),
            rows: AtomicUsize::new(0),
            values: AtomicUsize::new(0),
            audits: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl BrokerLeaseProvider for Leases {
    type Lease = Lease;
    type RefreshReservation = ();
    type StartedRefresh = ();

    fn bound_secrets(&self) -> Result<&[EpochBoundSecret], BoundSecretLeaseError> {
        self.grants.as_deref().map_err(|error| *error)
    }

    async fn lease_bound_secret_row(
        &self,
        _secret: &FirstBindSecret,
        _host: &str,
    ) -> Result<BoundSecretRow, BoundSecretLeaseError> {
        self.rows.fetch_add(1, Ordering::Relaxed);
        self.row.lock().unwrap().clone()
    }

    async fn lease_bound_secret_value(
        &self,
        _secret: &FirstBindSecret,
        _host: &str,
        _row: &BoundSecretRow,
    ) -> Result<Zeroizing<Vec<u8>>, BoundSecretLeaseError> {
        self.values.fetch_add(1, Ordering::Relaxed);
        Ok(Zeroizing::new(VALUE.to_vec()))
    }

    fn audit_bound_secret(&self, swap: BoundSecretSwap<'_>) {
        self.audits.lock().unwrap().push((
            swap.key.to_owned(),
            swap.scope,
            swap.host.to_owned(),
            swap.presentation,
            swap.outcome,
        ));
    }

    async fn lease_operation(
        &self,
        _id: Uuid,
        _slot: CapabilitySlot,
        _operation: BrokerOperationId,
        _route: BrokerRouteId,
    ) -> Result<Lease, BrokerLeaseError> {
        Err(BrokerLeaseError::Denied)
    }

    async fn begin_credential_refresh(
        &self,
        _: crate::BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<()>, BrokerRefreshError> {
        Err(BrokerRefreshError::Denied)
    }

    async fn start_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        Err(BrokerRefreshError::Denied)
    }

    async fn commit_credential_refresh(
        &self,
        permit: (),
        _: CanonicalCodexOAuthBundle,
    ) -> Result<(), CommitFailure<()>> {
        Err(CommitFailure::returned(permit, BrokerRefreshError::Denied))
    }

    async fn abort_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        Ok(())
    }

    async fn fail_credential_refresh(&self, _: ()) -> Result<(), BrokerRefreshError> {
        Ok(())
    }

    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
}

/// One request the bound host received.
#[derive(Clone, Debug)]
struct Sent {
    method: http::Method,
    target: String,
    headers: HeaderMap,
    body: Vec<u8>,
    pinned: Option<SocketAddr>,
}

/// The bound host: it records each request and answers `reply`.
#[derive(Default)]
struct Upstream {
    sent: Mutex<Vec<Sent>>,
    reply_headers: Vec<(&'static str, String)>,
    reply_body: Vec<u8>,
}

#[async_trait]
impl BrokerUpstreamTransport for Upstream {
    async fn execute(
        &self,
        _request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        panic!("a bound secret's request never goes through a provider route")
    }

    async fn send_bound_secret(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let pinned = request.pinned();
        let (method, target, headers, body) = request.into_parts();
        self.sent.lock().unwrap().push(Sent {
            method,
            target: target.to_string(),
            headers,
            body,
            pinned,
        });
        let mut headers = HeaderMap::new();
        for (name, value) in &self.reply_headers {
            headers.append(*name, HeaderValue::from_str(value).unwrap());
        }
        let body = Bytes::from(self.reply_body.clone());
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            headers,
            Box::pin(stream::once(async move { Ok(body) })),
        ))
    }
}

/// One front-door request on the bound route for `host`.
fn request(
    host: &str,
    headers: &[(&str, String)],
    query: &str,
    body: &[u8],
) -> v1::CredentialBridgeRequest {
    v1::CredentialBridgeRequest {
        request_id: Uuid::new_v4().to_string(),
        method: "POST".into(),
        path: "/v1/things".into(),
        query: query.into(),
        headers: headers
            .iter()
            .map(|(name, value)| v1::CredentialHttpHeader {
                name: (*name).into(),
                value: value.as_bytes().to_vec(),
            })
            .collect(),
        body: body.to_vec(),
        capability_slot: crate::bound_secret::BOUND_SECRET_SLOT.into(),
        route: crate::bound_secret::BOUND_SECRET_ROUTE.into(),
        intercepted_host: host.into(),
        destination_ip: DESTINATION.into(),
        ..Default::default()
    }
}

struct Run {
    leases: Arc<Leases>,
    upstream: Arc<Upstream>,
    result: Result<BrokerHttpResponse, BrokerRequestError>,
}

impl Run {
    fn sent(&self) -> Vec<Sent> {
        self.upstream.sent.lock().unwrap().clone()
    }

    async fn body(self) -> (StatusCode, HeaderMap, Vec<u8>) {
        let (status, headers, mut body) = self.result.expect("an answer").into_parts();
        let mut bytes = Vec::new();
        while let Some(chunk) = tokio::time::timeout(WAIT, body.next()).await.unwrap() {
            bytes.extend_from_slice(&chunk.expect("a body chunk"));
        }
        (status, headers, bytes)
    }

    fn refused_with(&self) -> Option<String> {
        let response = self.result.as_ref().ok()?;
        response
            .headers
            .get(codewire_access::REFUSAL_HEADER)
            .map(|value| value.to_str().unwrap().to_owned())
    }
}

async fn run_with(leases: Leases, upstream: Upstream, request: v1::CredentialBridgeRequest) -> Run {
    let leases = Arc::new(leases);
    let upstream = Arc::new(upstream);
    let broker = OpenAiBroker::new(
        ArcLeases(Arc::clone(&leases)),
        ArcUpstream(Arc::clone(&upstream)),
    )
    .unwrap()
    .with_untouched_forwards_refused();
    let result = tokio::time::timeout(WAIT, broker.execute_front_door(request))
        .await
        .expect("bounded");
    Run {
        leases,
        upstream,
        result,
    }
}

async fn run(
    grants: Vec<EpochBoundSecret>,
    presentation: Presentation,
    request: v1::CredentialBridgeRequest,
) -> Run {
    run_with(
        Leases::new(grants, presentation),
        Upstream::default(),
        request,
    )
    .await
}

/// The test's fakes, shared with the broker that owns them.
struct ArcLeases(Arc<Leases>);
struct ArcUpstream(Arc<Upstream>);

#[async_trait]
impl BrokerLeaseProvider for ArcLeases {
    type Lease = Lease;
    type RefreshReservation = ();
    type StartedRefresh = ();

    fn bound_secrets(&self) -> Result<&[EpochBoundSecret], BoundSecretLeaseError> {
        self.0.bound_secrets()
    }
    async fn lease_bound_secret_row(
        &self,
        secret: &FirstBindSecret,
        host: &str,
    ) -> Result<BoundSecretRow, BoundSecretLeaseError> {
        self.0.lease_bound_secret_row(secret, host).await
    }
    async fn lease_bound_secret_value(
        &self,
        secret: &FirstBindSecret,
        host: &str,
        row: &BoundSecretRow,
    ) -> Result<Zeroizing<Vec<u8>>, BoundSecretLeaseError> {
        self.0.lease_bound_secret_value(secret, host, row).await
    }
    fn audit_bound_secret(&self, swap: BoundSecretSwap<'_>) {
        self.0.audit_bound_secret(swap);
    }
    async fn lease_operation(
        &self,
        id: Uuid,
        slot: CapabilitySlot,
        operation: BrokerOperationId,
        route: BrokerRouteId,
    ) -> Result<Lease, BrokerLeaseError> {
        self.0.lease_operation(id, slot, operation, route).await
    }
    async fn begin_credential_refresh(
        &self,
        request: crate::BrokerCredentialRefreshRequest,
    ) -> Result<BrokerRefreshAdmission<()>, BrokerRefreshError> {
        self.0.begin_credential_refresh(request).await
    }
    async fn start_credential_refresh(&self, permit: ()) -> Result<(), BrokerRefreshError> {
        self.0.start_credential_refresh(permit).await
    }
    async fn commit_credential_refresh(
        &self,
        permit: (),
        bundle: CanonicalCodexOAuthBundle,
    ) -> Result<(), CommitFailure<()>> {
        self.0.commit_credential_refresh(permit, bundle).await
    }
    async fn abort_credential_refresh(&self, permit: ()) -> Result<(), BrokerRefreshError> {
        self.0.abort_credential_refresh(permit).await
    }
    async fn fail_credential_refresh(&self, permit: ()) -> Result<(), BrokerRefreshError> {
        self.0.fail_credential_refresh(permit).await
    }
    async fn wait_for_active_operations(&self) -> Result<(), BrokerRefreshError> {
        Ok(())
    }
}

#[async_trait]
impl BrokerUpstreamTransport for ArcUpstream {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        self.0.execute(request).await
    }
    async fn send_bound_secret(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        self.0.send_bound_secret(request).await
    }
}

fn fancy() -> EpochBoundSecret {
    grant(record("FANCY_TOKEN", 7, &[HOST]))
}

fn placeholder() -> String {
    fancy().placeholder.as_str().to_owned()
}

fn basic_of(credentials: &str) -> String {
    format!("Basic {}", STANDARD.encode(credentials))
}

fn sent_header(sent: &Sent, name: &str) -> Vec<String> {
    sent.headers
        .get_all(name)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect()
}

/// Each presentation swaps exactly the bound header's placeholder for the
/// value in its shape, asks for an identity coding, keeps the request's
/// other headers, path, query and body, and dials the admitted address.
#[tokio::test]
async fn each_presentation_swaps_the_value_into_its_header() {
    let ours = placeholder();
    let value = std::str::from_utf8(VALUE).unwrap();
    for (presentation, sent, expected) in [
        (
            header_presentation(&["Authorization"], "Bearer"),
            vec![("authorization", format!("bearer {ours}"))],
            vec![("authorization", format!("Bearer {value}"))],
        ),
        (
            header_presentation(&["X-Api-Key"], "none"),
            vec![("x-api-key", ours.clone())],
            vec![("x-api-key", value.to_owned())],
        ),
        (
            header_presentation(&["Authorization", "X-Api-Key"], "Token"),
            vec![
                ("authorization", format!("Token {ours}")),
                ("x-api-key", format!("Token {ours}")),
            ],
            vec![
                ("authorization", format!("Token {value}")),
                ("x-api-key", format!("Token {value}")),
            ],
        ),
        (
            Presentation::basic(Some("git")).unwrap(),
            vec![("authorization", basic_of(&format!("anyone:{ours}")))],
            vec![("authorization", basic_of(&format!("git:{value}")))],
        ),
        (
            Presentation::BasicUser,
            vec![("authorization", basic_of(&format!("{ours}:")))],
            vec![("authorization", basic_of(&format!("{value}:")))],
        ),
    ] {
        let mut headers = sent.clone();
        headers.push(("x-request-kind", "synthetic".into()));
        headers.push(("accept-encoding", "gzip".into()));
        let run = run(
            vec![fancy()],
            presentation.clone(),
            request(HOST, &headers, "page=2", b"{\"plain\":true}"),
        )
        .await;
        let outbound = run.sent();
        assert_eq!(outbound.len(), 1, "{presentation:?}");
        let outbound = &outbound[0];
        assert_eq!(outbound.method, http::Method::POST);
        assert_eq!(outbound.target, format!("https://{HOST}/v1/things?page=2"));
        assert_eq!(outbound.body, b"{\"plain\":true}");
        assert_eq!(
            outbound.pinned,
            Some(SocketAddr::new(DESTINATION.parse().unwrap(), 443))
        );
        for (name, value) in &expected {
            assert_eq!(
                sent_header(outbound, name),
                std::slice::from_ref(value),
                "{presentation:?}"
            );
        }
        assert_eq!(sent_header(outbound, "accept-encoding"), ["identity"]);
        assert_eq!(sent_header(outbound, "x-request-kind"), ["synthetic"]);
        assert_eq!(
            run.leases.audits.lock().unwrap().as_slice(),
            [(
                "FANCY_TOKEN".to_owned(),
                "project",
                HOST.to_owned(),
                presentation_name(&presentation),
                "swapped"
            )]
        );
        assert_eq!(run.body().await.0, StatusCode::OK);
    }
}

/// Every refusal of step 4 by its name, with nothing sent and no value read.
#[tokio::test]
async fn each_refusal_is_answered_by_name_and_nothing_is_sent() {
    let ours = placeholder();
    let bearer = header_presentation(&["Authorization"], "Bearer");
    let outside = "placeholder_outside_binding";
    let conflict = "credential_conflict";
    let bearer_ours = || vec![("authorization", format!("Bearer {ours}"))];
    let none = || (String::new(), Vec::new());
    let cases: Vec<RefusalCase<'_>> = vec![
        (vec![("x-api-key", ours.clone())], none(), outside),
        (
            vec![
                ("authorization", format!("Bearer {ours}")),
                ("x-trace", ours.clone()),
            ],
            none(),
            outside,
        ),
        (vec![], (format!("key={ours}"), Vec::new()), outside),
        (vec![], (format!("key=x%20{ours}"), Vec::new()), outside),
        (
            bearer_ours(),
            (String::new(), format!("{{\"k\":\"{ours}\"}}").into_bytes()),
            outside,
        ),
        (
            vec![("authorization", format!("Token {ours}"))],
            none(),
            outside,
        ),
        (
            vec![("authorization", format!("Bearer {ours}x"))],
            none(),
            outside,
        ),
        (
            vec![("authorization", basic_of(&format!("u:{ours}")))],
            none(),
            outside,
        ),
        (
            vec![
                ("authorization", format!("Bearer {ours}")),
                ("authorization", format!("Bearer {ours}")),
            ],
            none(),
            conflict,
        ),
        (
            vec![("authorization", format!("Bearer {ours}, Bearer other"))],
            none(),
            conflict,
        ),
        (
            vec![("authorization", format!("Bearer {ours} {ours}"))],
            none(),
            conflict,
        ),
        (
            vec![
                ("authorization", format!("Bearer {ours}")),
                ("cookie", "session=1".into()),
            ],
            none(),
            conflict,
        ),
        (
            vec![
                ("authorization", format!("Bearer {ours}")),
                ("proxy-authorization", "Basic dTpw".into()),
            ],
            none(),
            conflict,
        ),
    ];
    for (headers, (query, body), code) in cases {
        let run = run(
            vec![fancy()],
            bearer.clone(),
            request(HOST, &headers, &query, &body),
        )
        .await;
        assert_eq!(
            run.refused_with().as_deref(),
            Some(code),
            "{headers:?} {query}"
        );
        assert!(run.sent().is_empty(), "{headers:?} {query}");
        assert_eq!(run.leases.values.load(Ordering::Relaxed), 0);
        let (status, _, body) = run.body().await;
        assert_eq!(status.as_u16(), if code == conflict { 400 } else { 403 });
        assert!(
            !String::from_utf8(body).unwrap().contains(&ours),
            "a refusal never echoes the placeholder"
        );
    }
}

/// The hint names the header and the scheme the request used, and only
/// says the value can't be protected for the query and body.
#[tokio::test]
async fn a_placeholder_outside_its_binding_gets_the_command_that_binds_it_there() {
    let ours = placeholder();
    let run = run(
        vec![fancy()],
        header_presentation(&["Authorization"], "Bearer"),
        request(HOST, &[("x-api-key", ours)], "", b""),
    )
    .await;
    let (_, _, body) = run.body().await;
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "Codewire: FANCY_TOKEN is bound to Authorization on api.fancy.com; this request sent it elsewhere, so it was not sent.\nFix: to send it in X-Api-Key, run `cw secrets --cloud --project=PROJECT set FANCY_TOKEN --host api.fancy.com --header X-Api-Key --scheme none`; it asks for the value again.\n"
    );
}

/// Two secrets' placeholders are a conflict; a secret whose record doesn't
/// name this host is refused before any row is read.
#[tokio::test]
async fn another_secrets_placeholder_is_never_swapped_here() {
    let other = grant(record("OTHER_TOKEN", 8, &[OTHER_HOST]));
    let theirs = other.placeholder.as_str().to_owned();
    let bearer = header_presentation(&["Authorization"], "Bearer");
    let both = run(
        vec![fancy(), other.clone()],
        bearer.clone(),
        request(
            HOST,
            &[
                ("authorization", format!("Bearer {}", placeholder())),
                ("x-other", theirs.clone()),
            ],
            "",
            b"",
        ),
    )
    .await;
    assert_eq!(both.refused_with().as_deref(), Some("credential_conflict"));
    assert!(both.sent().is_empty());
    let elsewhere = run(
        vec![fancy(), other],
        bearer,
        request(
            HOST,
            &[("authorization", format!("Bearer {theirs}"))],
            "",
            b"",
        ),
    )
    .await;
    assert_eq!(
        elsewhere.refused_with().as_deref(),
        Some("secret_not_bound_to_host")
    );
    assert_eq!(elsewhere.leases.rows.load(Ordering::Relaxed), 0);
    assert!(elsewhere.sent().is_empty());
}

/// The lease's reread decides: a host removed since the Pod, a changed
/// binding and a deleted secret are each refused by name, nothing is sent
/// and the value is never read.
#[tokio::test]
async fn a_lease_refused_by_the_row_sends_nothing() {
    for (error, code) in [
        (
            BoundSecretLeaseError::NotBoundToHost,
            "secret_not_bound_to_host",
        ),
        (
            BoundSecretLeaseError::BindingChanged,
            "secret_binding_changed",
        ),
        (BoundSecretLeaseError::Deleted, "secret_deleted"),
    ] {
        let leases = Leases::new(
            vec![fancy()],
            header_presentation(&["Authorization"], "Bearer"),
        );
        *leases.row.lock().unwrap() = Err(error);
        let run = run_with(
            leases,
            Upstream::default(),
            request(
                HOST,
                &[("authorization", format!("Bearer {}", placeholder()))],
                "",
                b"",
            ),
        )
        .await;
        assert_eq!(run.refused_with().as_deref(), Some(code));
        assert!(run.sent().is_empty());
        assert_eq!(run.leases.values.load(Ordering::Relaxed), 0);
        assert_eq!(run.leases.audits.lock().unwrap()[0].4, code);
    }
}

/// With none of this environment's bound-secret placeholders, a hosted
/// broker forwards nothing: `selected_credential_only`, as for every
/// intercepted host. A foreign placeholder-shaped value counts as none.
#[tokio::test]
async fn a_request_without_a_placeholder_is_refused_hosted() {
    let foreign = grant(record("FANCY_TOKEN", 99, &[HOST])).placeholder;
    for headers in [
        vec![],
        vec![("authorization", "Bearer users-own-key".to_owned())],
        vec![("authorization", format!("Bearer {}", foreign.as_str()))],
    ] {
        let run = run(
            vec![fancy()],
            header_presentation(&["Authorization"], "Bearer"),
            request(HOST, &headers, "", b""),
        )
        .await;
        assert!(matches!(
            run.result,
            Err(BrokerRequestError::SelectedCredentialOnly)
        ));
        assert!(run.sent().is_empty());
        assert_eq!(run.leases.rows.load(Ordering::Relaxed), 0);
    }
}

/// An epoch whose environment's key couldn't be read refuses rather than
/// forwarding what it can't tell apart.
#[tokio::test]
async fn an_epoch_without_its_placeholders_refuses_as_unavailable() {
    let mut leases = Leases::new(vec![], header_presentation(&["Authorization"], "Bearer"));
    leases.grants = Err(BoundSecretLeaseError::Unavailable);
    let run = run_with(
        leases,
        Upstream::default(),
        request(HOST, &[("authorization", "Bearer x".into())], "", b""),
    )
    .await;
    assert!(matches!(
        run.result,
        Err(BrokerRequestError::AuthorityUnavailable)
    ));
    assert!(run.sent().is_empty());
}

/// A reply that echoes the value, in a header or the body, raw,
/// JSON-escaped, percent-encoded or in base64, is redacted of it.
#[tokio::test]
async fn every_form_of_the_value_is_redacted_from_the_reply() {
    let value = std::str::from_utf8(VALUE).unwrap();
    let json = serde_json::to_string(value).unwrap();
    let json = &json[1..json.len() - 1];
    let percent: String = url::form_urlencoded::byte_serialize(VALUE).collect();
    let base64 = STANDARD.encode(VALUE);
    let forms = [
        value.to_owned(),
        json.to_owned(),
        percent.clone(),
        base64.clone(),
    ];
    assert_eq!(
        forms.iter().collect::<BTreeSet<_>>().len(),
        4,
        "each form differs"
    );
    let upstream = Upstream {
        reply_headers: vec![
            ("x-echo", format!("Bearer {percent}")),
            ("content-type", "text/plain".into()),
        ],
        reply_body: format!("raw={value} json={json} percent={percent} base64={base64}")
            .into_bytes(),
        ..Upstream::default()
    };
    let run = run_with(
        Leases::new(
            vec![fancy()],
            header_presentation(&["Authorization"], "Bearer"),
        ),
        upstream,
        request(
            HOST,
            &[("authorization", format!("Bearer {}", placeholder()))],
            "",
            b"",
        ),
    )
    .await;
    let (status, headers, body) = run.body().await;
    assert_eq!(status, StatusCode::OK);
    let body = String::from_utf8(body).unwrap();
    let echoed = headers.get("x-echo").unwrap().to_str().unwrap().to_owned();
    for form in &forms {
        assert!(!body.contains(form.as_str()), "{form} in {body}");
        assert!(!echoed.contains(form.as_str()), "{form} in {echoed}");
    }
}

/// A reply in a content coding the broker can't redact is refused, never
/// passed on unread.
#[tokio::test]
async fn a_reply_in_another_coding_is_refused() {
    for coding in ["gzip", "br", "identity, gzip"] {
        let upstream = Upstream {
            reply_headers: vec![("content-encoding", coding.into())],
            reply_body: b"\x1f\x8b".to_vec(),
            ..Upstream::default()
        };
        let run = run_with(
            Leases::new(
                vec![fancy()],
                header_presentation(&["Authorization"], "Bearer"),
            ),
            upstream,
            request(
                HOST,
                &[("authorization", format!("Bearer {}", placeholder()))],
                "",
                b"",
            ),
        )
        .await;
        assert!(
            matches!(run.result, Err(BrokerRequestError::UpstreamFailed)),
            "{coding}"
        );
        assert_eq!(run.leases.audits.lock().unwrap()[0].4, "upstream_failed");
    }
}

/// The audit line names the key, its scope, the host, the presentation and
/// the outcome, and never the value, a placeholder or the set's path.
#[tokio::test]
async fn the_audit_line_holds_no_value_placeholder_or_path() {
    let ours = placeholder();
    let run = run(
        vec![fancy()],
        header_presentation(&["Authorization"], "Bearer"),
        request(
            HOST,
            &[("authorization", format!("Bearer {ours}"))],
            "",
            b"",
        ),
    )
    .await;
    let audits = run.leases.audits.lock().unwrap().clone();
    assert_eq!(audits.len(), 1);
    let (key, scope, host, presentation, outcome) = &audits[0];
    let line = format!("{key} {scope} {host} {presentation} {outcome}");
    let value = std::str::from_utf8(VALUE).unwrap();
    for forbidden in [value, ours.as_str(), PROJECT, "7d1e2f3a", "0f8a4c1e"] {
        assert!(!line.contains(forbidden), "{forbidden} in {line}");
    }
    assert_eq!(line, "FANCY_TOKEN project api.fancy.com header swapped");
}

/// The bound route is a front door's only, for an exact name no provider
/// route names.
#[test]
fn only_a_front_door_request_to_a_plain_name_takes_the_bound_route() {
    let ok = request(HOST, &[], "", b"");
    assert_eq!(
        super::super::entry::bound_dial(crate::bridge::BridgeEntry::FrontDoor, &ok).unwrap(),
        Some(BoundDial {
            host: HOST.into(),
            destination: Some(DESTINATION.parse().unwrap()),
        })
    );
    assert!(super::super::entry::bound_dial(crate::bridge::BridgeEntry::Loopback, &ok).is_err());
    for host in [
        "api.anthropic.com",
        "github.com",
        "x.chatgpt.com",
        "API.FANCY.COM",
        "localhost",
        "203.0.113.7",
    ] {
        assert!(
            super::super::entry::bound_dial(
                crate::bridge::BridgeEntry::FrontDoor,
                &request(host, &[], "", b"")
            )
            .is_err(),
            "{host}"
        );
    }
}
