//! Hosted front-door requests end to end (#6195, #6196, #6197): an
//! intercepted epoch with hosted placeholders over real generated gRPC and
//! restricted SQL, its front door joined with the epoch's handle, and each
//! request carrying the placeholder the agent's login file holds. The
//! listener is test-local plaintext loopback.

use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use codewire_access::{
    CapabilitySlot, CredentialAuthKind, CredentialPlaceholder, EnvironmentAccessBinding, Refusal,
};
use codewire_daemon_proto::CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER;
use codewire_platform_credentials::CredentialRecord;
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use tonic::metadata::BinaryMetadataValue;

use super::front_door::handle_of;
use super::rotation::DatabaseAuthenticator;
use super::*;
use crate::platform::tests::claude_sign_in::{sign_in_material, sign_in_registration};
use crate::platform::tests::support::{registration, value};
use crate::platform::tests::{Fixture as DatabaseFixture, TIMEOUT, profiles, token};

/// The account the stored Codex sign-ins name.
const CREDENTIAL_ACCOUNT: &str = "synthetic-account";
/// The account the agent names in its own requests.
const AGENT_ACCOUNT: &str = "agent-named-account";
/// Codex's routing discovery, and the workspace origins its reply names: one
/// for the credential's account, another for the agent's.
const ACCOUNTS_CHECK: &str = "/backend-api/wham/accounts/check";
const ROUTED: &str = "routed.chatgpt.com";
const OTHER_ORIGIN: &str = "https://other.chatgpt.com";
/// The address the front door says it admitted for a routed dial; it is on
/// the repository's public-address list.
const ADMITTED: &str = "1.1.1.1";
const MODEL: &str = "/backend-api/codex/responses";

/// A provider that records what it was sent. It answers Codex's routing
/// discovery with a workspace origin per account, and anything else by
/// echoing the credential back, as a provider's reply can.
#[derive(Clone, Default)]
struct Provider {
    sent: Arc<Mutex<Vec<(Method, String, HeaderMap)>>>,
}

impl Provider {
    fn sent(&self) -> Vec<(Method, String, HeaderMap)> {
        self.sent.lock().unwrap().clone()
    }

    fn calls(&self) -> usize {
        self.sent.lock().unwrap().len()
    }
}

#[async_trait]
impl BrokerUpstreamTransport for Provider {
    async fn execute(
        &self,
        request: BrokerUpstreamRequest,
    ) -> Result<BrokerUpstreamResponse, BrokerUpstreamError> {
        let (method, target, headers, _) = request.into_parts();
        let reply = if target.path() == ACCOUNTS_CHECK {
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "accounts": [
                        {"id": CREDENTIAL_ACCOUNT, "workspace_backend_origin": format!("https://{ROUTED}"),
                            "account_routing_override": "us", "structure": "workspace"},
                        {"id": AGENT_ACCOUNT, "workspace_backend_origin": OTHER_ORIGIN,
                            "account_routing_override": "us", "structure": "workspace"},
                    ],
                    "account_ordering": [CREDENTIAL_ACCOUNT, AGENT_ACCOUNT],
                }))
                .map_err(|_| BrokerUpstreamError::Protocol)?,
            )
        } else {
            headers
                .get(header::AUTHORIZATION)
                .map(|value| Bytes::copy_from_slice(value.as_bytes()))
                .unwrap_or_default()
        };
        self.sent
            .lock()
            .unwrap()
            .push((method, target.to_string(), headers));
        Ok(BrokerUpstreamResponse::new(
            StatusCode::OK,
            HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )]),
            Box::pin(futures::stream::once(async move { Ok(reply) })),
        ))
    }
}

type HostedService = PlatformCredentialBridgeService<DatabaseAuthenticator, Provider>;

/// The credential service with hosted placeholders on, as hosted runs it.
struct Hosted {
    service: HostedService,
    provider: Provider,
    endpoint: String,
    stop_listener: CancellationToken,
    server: JoinHandle<Result<(), tonic::transport::Error>>,
}

/// A front-door stream joined to an intercepted epoch, which it keeps open.
struct FrontDoor {
    _epoch: (
        mpsc::Sender<v1::CredentialBridgeGuestMessage>,
        Response<Streaming<v1::CredentialBridgeHostMessage>>,
    ),
    input: mpsc::Sender<v1::CredentialBridgeGuestMessage>,
    output: Streaming<v1::CredentialBridgeHostMessage>,
}

/// What the front door is answered with for one request.
#[derive(Debug)]
enum Answer {
    Http {
        status: u32,
        headers: Vec<v1::CredentialHttpHeader>,
        body: Vec<u8>,
    },
    Refused(v1::CredentialBridgeResponseFailure),
}

impl Answer {
    fn header(&self, name: &str) -> Option<&[u8]> {
        match self {
            Self::Http { headers, .. } => headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case(name))
                .map(|header| header.value.as_slice()),
            Self::Refused(_) => None,
        }
    }
}

fn ready(f: &DatabaseFixture) -> v1::CredentialBridgeGuestMessage {
    v1::CredentialBridgeGuestMessage {
        payload: Some(v1::credential_bridge_guest_message::Payload::Ready(
            v1::CredentialBridgeReady {
                protocol_version: CREDENTIAL_BRIDGE_PROTOCOL_VERSION,
                environment_id: f.context.environment_id.to_string(),
                environment_generation: f.context.environment_generation,
            },
        )),
    }
}

impl Hosted {
    async fn start(f: &DatabaseFixture) -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let provider = Provider::default();
        let service = HostedService::new(
            Arc::new(DatabaseAuthenticator(Arc::clone(&f.authority))),
            Arc::clone(&f.store),
            profiles(f.pool.clone(), builtin_provider_catalog()),
            provider.clone(),
        )
        .with_hosted_placeholders()?;
        let stop_listener = CancellationToken::new();
        let stop = stop_listener.clone();
        let generated = service.clone().into_server();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(generated)
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    stop.cancelled_owned(),
                )
                .await
        });
        Ok(Self {
            service,
            provider,
            endpoint,
            stop_listener,
            server,
        })
    }

    /// An epoch the relay says is intercepted, and a front door joined to it
    /// with its handle.
    async fn front_door(&self, f: &DatabaseFixture) -> Result<FrontDoor> {
        let mut client = Client::connect(self.endpoint.clone()).await?;
        let (epoch_input, receiver) = mpsc::channel(4);
        epoch_input.send(ready(f)).await?;
        let epoch = tokio::time::timeout(
            TIMEOUT,
            client.credential_bridge(intercepted_as(
                rpc_request(receiver, Some("synthetic-allow")),
                &["true"],
            )),
        )
        .await
        .context("intercepted epoch admission timed out")??;
        let handle = handle_of(&epoch);
        let (input, receiver) = mpsc::channel(4);
        input.send(ready(f)).await?;
        let mut request = rpc_request(receiver, Some("synthetic-allow"));
        request.metadata_mut().insert_bin(
            CREDENTIAL_BRIDGE_EPOCH_HANDLE_HEADER,
            BinaryMetadataValue::from_bytes(&handle),
        );
        let output = tokio::time::timeout(TIMEOUT, client.front_door_bridge(request))
            .await
            .context("front-door join timed out")??
            .into_inner();
        Ok(FrontDoor {
            _epoch: (epoch_input, epoch),
            input,
            output,
        })
    }

    async fn finish(self) -> Result<()> {
        let drained = tokio::time::timeout(TIMEOUT, self.service.shutdown())
            .await
            .context("generated service did not drain");
        self.stop_listener.cancel();
        let stopped = tokio::time::timeout(TIMEOUT, self.server)
            .await
            .context("generated test listener did not stop")?;
        drained??;
        stopped??;
        Ok(())
    }
}

impl FrontDoor {
    async fn send(&mut self, request: v1::CredentialBridgeRequest) -> Result<Answer> {
        let id = request.request_id.clone();
        self.input
            .send(v1::CredentialBridgeGuestMessage {
                payload: Some(v1::credential_bridge_guest_message::Payload::Request(
                    request,
                )),
            })
            .await?;
        tokio::time::timeout(TIMEOUT, async {
            let mut start = None;
            let mut body = Vec::new();
            loop {
                let frame = self
                    .output
                    .message()
                    .await?
                    .context("the front door ended before an answer")?;
                match frame.payload {
                    Some(v1::credential_bridge_host_message::Payload::ResponseStart(started))
                        if started.request_id == id =>
                    {
                        start = Some(started);
                    }
                    Some(v1::credential_bridge_host_message::Payload::ResponseBody(chunk))
                        if chunk.request_id == id =>
                    {
                        body.extend_from_slice(&chunk.data);
                    }
                    Some(v1::credential_bridge_host_message::Payload::ResponseEnd(end))
                        if end.request_id == id =>
                    {
                        let started = start.context("an end before a start")?;
                        return Ok(Answer::Http {
                            status: started.status_code,
                            headers: started.headers,
                            body,
                        });
                    }
                    Some(v1::credential_bridge_host_message::Payload::ResponseFailure(failure))
                        if failure.request_id == id =>
                    {
                        return Ok(Answer::Refused(failure));
                    }
                    _ => {}
                }
            }
        })
        .await
        .context("no answer to the front-door request")?
    }
}

/// The placeholder this environment's login files carry for `record` in
/// `slot` under `binding`: derived from the environment, the binding's
/// revision, the slot and the credential (`docs/dev/SECRETS-AND-CREDENTIALS.md`,
/// "Per-environment placeholders").
async fn placeholder(
    f: &DatabaseFixture,
    binding: &EnvironmentAccessBinding,
    slot: &CapabilitySlot,
    record: &CredentialRecord,
) -> Result<String> {
    let key = f
        .store
        .environment_placeholder_key(&binding.environment_id)
        .await?;
    Ok(CredentialPlaceholder::derive(
        &key,
        &binding.environment_id,
        binding.profile_revision,
        slot,
        &record.metadata.id,
    )
    .as_str()
    .to_owned())
}

/// A stored Codex ChatGPT sign-in named `label`, unexpired, and its access
/// token.
async fn codex_sign_in(f: &DatabaseFixture, label: &str) -> Result<(CredentialRecord, String)> {
    let access = token(serde_json::json!({
        "exp": crate::platform::unix_now()? + 7_200,
        "synthetic": label,
    }));
    let id_token = token(serde_json::json!({
        "https://api.openai.com/auth": {"chatgpt_account_id": CREDENTIAL_ACCOUNT},
    }));
    let bundle = crate::import_codex_tokens(
        zeroize::Zeroizing::new(id_token),
        zeroize::Zeroizing::new(access.clone()),
        zeroize::Zeroizing::new(format!("synthetic-refresh-{label}")),
    )?
    .into_parts()
    .0;
    let record = f
        .store
        .create(
            &f.owner,
            registration(label, CredentialAuthKind::OAuth),
            &value(bundle.as_bytes()),
        )
        .await?;
    Ok((record, access))
}

fn header(name: &str, value: impl Into<Vec<u8>>) -> v1::CredentialHttpHeader {
    v1::CredentialHttpHeader {
        name: name.into(),
        value: value.into(),
    }
}

/// Codex's model call to chatgpt.com with `placeholder` as its bearer,
/// naming `account` as Codex does.
fn codex_request(placeholder: &str, account: &str) -> v1::CredentialBridgeRequest {
    v1::CredentialBridgeRequest {
        capability_slot: "codex".into(),
        route: "openai-api".into(),
        request_id: Uuid::new_v4().to_string(),
        method: "POST".into(),
        path: MODEL.into(),
        query: String::new(),
        headers: vec![
            header("content-type", "application/json"),
            header("authorization", format!("Bearer {placeholder}")),
            header("chatgpt-account-id", account),
        ],
        body: br#"{"input":"hello"}"#.to_vec(),
        intercepted_host: "chatgpt.com".into(),
        destination_ip: String::new(),
        streamed_body: false,
        intercept_decision: Vec::new(),
    }
}

fn sent_header<'a>(headers: &'a HeaderMap, name: &str) -> Vec<&'a [u8]> {
    headers
        .get_all(name)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect()
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// Asserts the Codex model call was served at chatgpt.com with `access` for
/// the credential's account and nothing of the agent's.
fn served_with(
    answer: &Answer,
    sent: &(Method, String, HeaderMap),
    access: &str,
    placeholder: &str,
) -> Result<()> {
    served_at(answer, sent, "chatgpt.com", access, placeholder)
}

/// [`served_with`] at the origin `host`.
fn served_at(
    answer: &Answer,
    sent: &(Method, String, HeaderMap),
    host: &str,
    access: &str,
    placeholder: &str,
) -> Result<()> {
    ensure!(
        matches!(answer, Answer::Http { status: 200, .. }),
        "{answer:?}"
    );
    let (method, target, headers) = sent;
    ensure!(*method == Method::POST);
    ensure!(*target == format!("https://{host}{MODEL}"), "{target}");
    ensure!(
        sent_header(headers, "authorization") == [format!("Bearer {access}").as_bytes()],
        "the provider gets only the swapped token"
    );
    ensure!(
        sent_header(headers, "chatgpt-account-id") == [CREDENTIAL_ACCOUNT.as_bytes()],
        "the provider gets only the credential's account"
    );
    ensure!(
        headers
            .iter()
            .all(|(_, value)| !contains(value.as_bytes(), placeholder)),
        "the placeholder never reaches the provider"
    );
    Ok(())
}

/// Runs `test` against a fresh database fixture and a hosted service.
async fn hosted_case<F>(test: F) -> Result<()>
where
    F: AsyncFnOnce(&DatabaseFixture, &Hosted) -> Result<()>,
{
    let f = DatabaseFixture::create_for_bridge().await?;
    let result = async {
        let hosted = Hosted::start(&f).await?;
        let result = test(&f, &hosted).await;
        let finished = hosted.finish().await;
        result.and(finished)
    }
    .await;
    f.finish(result).await
}

/// #6195: Codex names an account of its own; the provider sees only the
/// stored credential's account, beside the swapped token.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn codex_through_the_front_door_reaches_only_the_credentials_account() -> Result<()> {
    hosted_case(async |f, hosted| {
        let (record, access) = codex_sign_in(f, "account-header").await?;
        let binding = f.select(CapabilitySlot::codex(), &record).await?;
        let placeholder = placeholder(f, &binding, &CapabilitySlot::codex(), &record).await?;
        let mut front_door = hosted.front_door(f).await?;
        let answer = front_door
            .send(codex_request(&placeholder, AGENT_ACCOUNT))
            .await?;
        let sent = hosted.provider.sent();
        ensure!(sent.len() == 1, "{} provider calls", sent.len());
        served_with(&answer, &sent[0], &access, &placeholder)
    })
    .await
}

/// #6195: at a routed `*.chatgpt.com` origin too, the one the routing
/// discovery named for the credential's account, the provider sees only
/// the credential's account beside the swapped token. The broker already
/// serves such an origin; the front door admitting the name is #6195's.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn codex_at_a_routed_origin_reaches_only_the_credentials_account() -> Result<()> {
    hosted_case(async |f, hosted| {
        let (record, access) = codex_sign_in(f, "routed-account").await?;
        let binding = f.select(CapabilitySlot::codex(), &record).await?;
        let placeholder = placeholder(f, &binding, &CapabilitySlot::codex(), &record).await?;
        let mut front_door = hosted.front_door(f).await?;
        let mut discovery = codex_request(&placeholder, AGENT_ACCOUNT);
        discovery.method = "GET".into();
        discovery.path = ACCOUNTS_CHECK.into();
        discovery.body = Vec::new();
        let answer = front_door.send(discovery).await?;
        ensure!(
            matches!(answer, Answer::Http { status: 200, .. }),
            "{answer:?}"
        );
        let mut model = codex_request(&placeholder, AGENT_ACCOUNT);
        model.intercepted_host = ROUTED.into();
        model.destination_ip = ADMITTED.into();
        let answer = front_door.send(model).await?;
        let sent = hosted.provider.sent();
        ensure!(sent.len() == 2, "{answer:?}");
        served_at(&answer, &sent[1], ROUTED, &access, &placeholder)
    })
    .await
}

/// #6196: Claude Code's `/usage` with a Claude sign-in's placeholder is
/// swapped like any Anthropic request, and the reply is redacted.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn claude_usage_through_the_front_door_is_swapped_and_its_reply_redacted() -> Result<()> {
    hosted_case(async |f, hosted| {
        // An hour left and refreshed a minute ago: no refresh is due.
        let sign_in = f
            .store
            .create(
                &f.owner,
                sign_in_registration("Claude"),
                &sign_in_material("usage", 3_600, 60, None),
            )
            .await?;
        let binding = f.select(CapabilitySlot::anthropic(), &sign_in).await?;
        let placeholder = placeholder(f, &binding, &CapabilitySlot::anthropic(), &sign_in).await?;
        let mut front_door = hosted.front_door(f).await?;
        let answer = front_door
            .send(v1::CredentialBridgeRequest {
                capability_slot: "anthropic".into(),
                route: "anthropic-api".into(),
                request_id: Uuid::new_v4().to_string(),
                method: "GET".into(),
                path: "/api/oauth/usage".into(),
                query: String::new(),
                headers: vec![
                    header("authorization", format!("Bearer {placeholder}")),
                    header("anthropic-beta", "oauth-2025-04-20"),
                ],
                body: Vec::new(),
                intercepted_host: "api.anthropic.com".into(),
                destination_ip: String::new(),
                streamed_body: false,
                intercept_decision: Vec::new(),
            })
            .await?;
        let sent = hosted.provider.sent();
        ensure!(sent.len() == 1, "{} provider calls", sent.len());
        let (method, target, headers) = &sent[0];
        ensure!(*method == Method::GET);
        ensure!(target == "https://api.anthropic.com/api/oauth/usage");
        ensure!(
            sent_header(headers, "authorization") == [&b"Bearer synthetic-access-usage"[..]],
            "the provider gets the sign-in's own token"
        );
        let Answer::Http { status, body, .. } = &answer else {
            anyhow::bail!("{answer:?}");
        };
        ensure!(*status == 200);
        ensure!(
            !contains(body, "synthetic-access-usage"),
            "the token the provider echoed never reaches the agent"
        );
        ensure!(contains(body, "[REDACTED]"), "the echo is redacted");
        Ok(())
    })
    .await
}

/// #6197: once the credential is revoked, the next request is answered 403
/// `credential_revoked`, and nothing reaches the provider.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_revoked_credential_is_refused_at_the_front_door_and_never_sent() -> Result<()> {
    hosted_case(async |f, hosted| {
        let (record, access) = codex_sign_in(f, "revoked").await?;
        let binding = f.select(CapabilitySlot::codex(), &record).await?;
        let placeholder = placeholder(f, &binding, &CapabilitySlot::codex(), &record).await?;
        let mut front_door = hosted.front_door(f).await?;
        let answer = front_door
            .send(codex_request(&placeholder, CREDENTIAL_ACCOUNT))
            .await?;
        served_with(&answer, &hosted.provider.sent()[0], &access, &placeholder)?;

        let current = f.store.record(&f.owner, &record.metadata.id).await?;
        f.store
            .revoke(&f.owner, &record.metadata.id, current.version)
            .await?;
        let answer = front_door
            .send(codex_request(&placeholder, CREDENTIAL_ACCOUNT))
            .await?;
        ensure!(
            matches!(answer, Answer::Http { status: 403, .. }),
            "{answer:?}"
        );
        ensure!(
            answer.header(codewire_access::REFUSAL_HEADER)
                == Some(Refusal::CredentialRevoked.reason().as_bytes()),
            "{answer:?}"
        );
        ensure!(hosted.provider.calls() == 1, "the provider was called");
        Ok(())
    })
    .await
}

/// A credential, selected in the Codex slot and used once through the front
/// door; then another selected in its place within the same epoch, which
/// moves the profile's revision and so the placeholder.
struct Reselected {
    front_door: FrontDoor,
    old_placeholder: String,
    new_placeholder: String,
    new_access: String,
}

async fn reselect(f: &DatabaseFixture, hosted: &Hosted) -> Result<Reselected> {
    let (first, first_access) = codex_sign_in(f, "first").await?;
    let binding = f.select(CapabilitySlot::codex(), &first).await?;
    let old_placeholder = placeholder(f, &binding, &CapabilitySlot::codex(), &first).await?;
    let mut front_door = hosted.front_door(f).await?;
    let answer = front_door
        .send(codex_request(&old_placeholder, CREDENTIAL_ACCOUNT))
        .await?;
    served_with(
        &answer,
        &hosted.provider.sent()[0],
        &first_access,
        &old_placeholder,
    )?;

    let (second, new_access) = codex_sign_in(f, "second").await?;
    let binding = f.select(CapabilitySlot::codex(), &second).await?;
    let new_placeholder = placeholder(f, &binding, &CapabilitySlot::codex(), &second).await?;
    ensure!(new_placeholder != old_placeholder);
    Ok(Reselected {
        front_door,
        old_placeholder,
        new_placeholder,
        new_access,
    })
}

impl Reselected {
    /// The new placeholder is served with the newly selected credential.
    async fn new_is_served(&mut self, hosted: &Hosted) -> Result<()> {
        let calls = hosted.provider.calls();
        let answer = self
            .front_door
            .send(codex_request(&self.new_placeholder, CREDENTIAL_ACCOUNT))
            .await?;
        let sent = hosted.provider.sent();
        ensure!(sent.len() == calls + 1, "{answer:?}");
        served_with(
            &answer,
            &sent[calls],
            &self.new_access,
            &self.new_placeholder,
        )
    }

    /// The old placeholder is answered 403 `selected_credential_only`, and
    /// nothing reaches the provider.
    async fn old_is_refused(&mut self, hosted: &Hosted) -> Result<()> {
        let calls = hosted.provider.calls();
        let answer = self
            .front_door
            .send(codex_request(&self.old_placeholder, CREDENTIAL_ACCOUNT))
            .await?;
        let Answer::Refused(failure) = &answer else {
            anyhow::bail!("{answer:?}");
        };
        ensure!(failure.refusal == v1::CredentialBridgeRefusal::SelectedCredentialOnly as i32);
        ensure!(Refusal::SelectedCredentialOnly.status() == 403);
        ensure!(hosted.provider.calls() == calls, "the provider was called");
        Ok(())
    }
}

/// #6197: a reselect reaches a running epoch once its authority decision is
/// older than its reuse (`docs/dev/SECRETS-AND-CREDENTIALS.md`: rebinding
/// the running environment applies within 60 seconds): the new placeholder
/// is served, and the old one refused.
#[tokio::test]
#[ignore = "requires isolated TEST_DATABASE_URL"]
async fn a_reselect_reaches_a_running_epoch_once_its_decision_is_past_reuse() -> Result<()> {
    hosted_case(async |f, hosted| {
        let mut reselected = reselect(f, hosted).await?;
        tokio::time::pause();
        tokio::time::advance(
            crate::platform::decision::AUTHORITY_DECISION_REUSE + Duration::from_secs(1),
        )
        .await;
        tokio::time::resume();
        reselected.new_is_served(hosted).await?;
        reselected.old_is_refused(hosted).await
    })
    .await
}
