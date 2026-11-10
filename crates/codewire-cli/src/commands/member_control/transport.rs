use super::{
    custody::OwnerPin,
    store::{Alias, Directory, Identity, MemberPath, RequestRecord},
    wire::{self, Binding, Channel},
};
use anyhow::{Context, ensure};
use codewire_client::member_tailnet::{MemberTailnet, MemberTransportOptions};
use codewire_daemon_proto::daemon::v1;
use codewire_tailnet::netstack::TcpStream;
use prost::Message;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

const RPC_TIMEOUT: Duration = Duration::from_secs(15);
/// How long `mutate` follows a request its reply left unsettled. Longer than
/// the daemon's own longest step (a launch's 40 s, then 5 s of cleanup), so a
/// request still unsettled after this is stuck rather than slow (#3774).
const SETTLE_BOUND: Duration = Duration::from_secs(60);
const SETTLE_POLL: Duration = Duration::from_millis(200);
const READ_PAGE: u64 = 8 * 1024;
/// How long a finished command waits for the target to close its side.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

fn admit_info(
    value: &v1::HostControlInfoResponse,
    environment_id: &str,
    managed: bool,
) -> anyhow::Result<()> {
    ensure!(
        value.environment_id == environment_id
            && value.protocol_version == 1
            && matches!(value.managed_agent_protocol_version, 0 | 1)
            && value.verbs
                == if value.managed_agent_protocol_version == 0 {
                    vec![1, 2, 3, 4]
                } else {
                    (1..=11).collect()
                },
        "member protocol or host identity changed"
    );
    ensure!(
        !managed || value.managed_agent_protocol_version == 1,
        "member target does not implement managed conversations"
    );
    Ok(())
}

struct PathSample {
    path: codewire_tailnet::conn::PeerTransport,
    verified: bool,
    stats: Option<codewire_tailnet::direct_udp::Stats>,
}
impl PathSample {
    fn name(&self) -> &'static str {
        use codewire_tailnet::conn::PeerTransport;
        match self.path {
            PeerTransport::DirectUdp => "direct_udp",
            PeerTransport::DerpRelay => "derp",
            PeerTransport::PeerRelay => "peer_relay",
            PeerTransport::Unknown => "unknown",
        }
    }
    fn diagnostic(&self) -> serde_json::Value {
        serde_json::json!({"transport":self.name(),"direct_verified":self.verified,
            "direct_wg_sent":self.stats.as_ref().map(|s|s.direct_wg_sent),
            "direct_wg_received":self.stats.as_ref().map(|s|s.direct_wg_received),
            "fallback_wg_sent":self.stats.as_ref().map(|s|s.fallback_wg_sent),
            "peer_relay_wg_sent":self.stats.as_ref().map(|s|s.peer_relay_wg_sent)})
    }
}

fn require_exchange_path(
    expected: MemberPath,
    before: &PathSample,
    after: &PathSample,
) -> anyhow::Result<()> {
    ensure!(
        before.name() == expected.name() && after.name() == expected.name(),
        "member required transport changed; mutation outcome may be unknown, observe only"
    );
    match expected {
        MemberPath::DirectUdp => {
            let old = before
                .stats
                .as_ref()
                .context("direct path counters absent")?;
            let new = after
                .stats
                .as_ref()
                .context("direct path counters absent")?;
            ensure!(
                before.verified
                    && after.verified
                    && new.direct_wg_sent > old.direct_wg_sent
                    && new.direct_wg_received > old.direct_wg_received
                    && new.fallback_wg_sent == old.fallback_wg_sent
                    && new.peer_relay_wg_sent == old.peer_relay_wg_sent,
                "member direct request path unproved; mutation outcome may be unknown, observe only"
            );
        }
        MemberPath::Derp => ensure!(
            before.stats.is_none() && after.stats.is_none(),
            "member DERP requirement needs an explicitly disabled direct transport"
        ),
    }
    Ok(())
}

struct ExchangePath {
    before: Option<PathSample>,
    action: u8,
    request_id: Option<String>,
    session_id: Option<String>,
}
struct Exchange<T> {
    value: T,
    path: ExchangePath,
}

// Authenticated effect evidence is durable before any post-route wait or
// refusal. A cancelled qualifier cannot erase a confirmed ACK or make the
// retained request permission to send Mutate again.
pub(super) async fn retain_receipt(
    directory: &Directory,
    record: &mut RequestRecord,
    value: v1::HostControlReceipt,
    qualification: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<v1::HostControlReceipt> {
    record.finish(directory, value).await?;
    let value = wire::decode(record.receipt.as_ref().expect("finish saved receipt"))?;
    if qualification.await.is_err() {
        eprintln!(
            "[cw] member authenticated receipt retained {}",
            serde_json::to_string(&super::receipt_value(&value))?
        );
        anyhow::bail!(
            "member transport qualification failed; authenticated receipt retained, observe original request UUID and never reissue"
        );
    }
    Ok(value)
}

/// The daemon's reply waits only 3 s for its request, which carries on either
/// way, so a phase of pending or issued means "not finished yet", not failure.
fn unsettled(receipt: &v1::HostControlReceipt) -> bool {
    [
        v1::HostControlRequestPhase::Pending as i32,
        v1::HostControlRequestPhase::Issued as i32,
    ]
    .contains(&receipt.phase)
}

/// Follows an unsettled request with `observe` until it settles or `bound`
/// runs out, and returns the last receipt. Observing never sends the request
/// again, and the caller still judges whatever comes back.
pub(in crate::commands) async fn settle_receipt(
    mut receipt: v1::HostControlReceipt,
    bound: Duration,
    poll: Duration,
    mut observe: impl AsyncFnMut() -> anyhow::Result<v1::HostControlReceipt>,
) -> anyhow::Result<v1::HostControlReceipt> {
    let deadline = tokio::time::Instant::now() + bound;
    while unsettled(&receipt) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(poll).await;
        receipt = observe().await?;
    }
    Ok(receipt)
}

/// The visible record of a wait: a slow request shows a number, not just a
/// success. The host-member journey reports these lines.
fn settle_report(id: &str, receipt: &v1::HostControlReceipt, waited: Duration) -> String {
    let phase = v1::HostControlRequestPhase::try_from(receipt.phase)
        .map(|phase| phase.as_str_name())
        .unwrap_or("UNKNOWN");
    format!(
        "[cw] member request {id} {} {phase} after {} ms",
        if unsettled(receipt) {
            "still"
        } else {
            "settled as"
        },
        waited.as_millis()
    )
}

pub(super) struct Remote {
    channel: Channel<TcpStream>,
    tailnet: MemberTailnet,
    peer: codewire_tailnet::node::Node,
    pub alias: Alias,
}
impl Remote {
    /// Connects, runs `body`, then closes the connection whatever `body`
    /// returned. A process that exits with its connection open never tells the
    /// target, which holds one of its few connection slots until a timeout.
    pub async fn with<T>(
        directory: &Directory,
        alias: Alias,
        globals: &super::super::Globals,
        body: impl AsyncFnOnce(&mut Self) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut remote = Self::connect(directory, alias, globals).await?;
        let result = body(&mut remote).await;
        // The command's own result stands; a close that fails or times out
        // leaves only the target's idle timeout to end the connection.
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, remote.channel.close()).await;
        result
    }
    async fn connect(
        directory: &Directory,
        alias: Alias,
        globals: &super::super::Globals,
    ) -> anyhow::Result<Self> {
        alias.validate()?;
        let identity = Identity::load(directory, false).await?;
        ensure!(
            *identity.secret().public().as_bytes() == alias.binding.caller,
            "member caller key was replaced"
        );
        let paths = super::super::ResolvePaths::from_env(&super::super::OsEnv)?;
        let config = super::super::resolve_mesh(
            globals,
            &paths,
            &super::super::OsEnv,
            Some(alias.origin.clone()),
            Some(alias.binding.network.clone()),
        )?;
        ensure!(
            config.mesh_url.trim_end_matches('/') == alias.origin.trim_end_matches('/'),
            "member Mesh origin changed"
        );
        let client = codewire_client::CodewireClient::with_http_token_provider(
            codewire_client::ClientConfig::new(&alias.origin)?.with_mesh_url(&alias.origin)?,
            config.token_provider(),
            reqwest::Client::new(),
        )?;
        let mut tailnet = MemberTailnet::dial(
            &client,
            &alias.binding.org,
            &alias.binding.network,
            &alias.route_name,
            MemberTransportOptions {
                derp_only: alias.derp_only,
                ..Default::default()
            },
        )
        .await?;
        let (stream, peer) = tailnet
            .dial_member(
                alias.binding.target_wg,
                wire::canonical_uuid(&alias.binding.environment_id)?,
            )
            .await?;
        let channel = tokio::time::timeout(
            RPC_TIMEOUT,
            Channel::caller(stream, identity.secret(), alias.binding.clone()),
        )
        .await
        .context("member authentication timed out")??;
        Ok(Self {
            channel,
            tailnet,
            peer,
            alias,
        })
    }
    async fn exchange<Q: Message, R: Message + Default>(
        &mut self,
        action: u8,
        request: Q,
        request_id: Option<&str>,
        session_id: Option<&str>,
    ) -> anyhow::Result<Exchange<R>> {
        ensure!(
            self.tailnet.is_ready(),
            "member transport owner unavailable"
        );
        let before = if let Some(expected) = self.alias.required_transport {
            Some(self.sample_path(Some(expected.name()), RPC_TIMEOUT).await?)
        } else {
            None
        };
        let response = tokio::time::timeout(RPC_TIMEOUT, async {
            self.channel.send(action, &request.encode_to_vec()).await?;
            let (reply, payload) = self.channel.receive().await?;
            ensure!(reply == action, "member response action changed");
            wire::result(&payload)
        })
        .await;
        let value = match response {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                self.channel.refuse();
                return Err(error);
            }
            Err(_) => {
                self.channel.refuse();
                anyhow::bail!("member response unknown; retain and observe original request UUID");
            }
        };
        Ok(Exchange {
            value,
            path: ExchangePath {
                before,
                action,
                request_id: request_id.map(str::to_owned),
                session_id: session_id.map(str::to_owned),
            },
        })
    }
    fn path_sample(&self) -> anyhow::Result<PathSample> {
        Ok(PathSample {
            path: self.tailnet.path(&self.peer)?.transport,
            verified: self.tailnet.has_verified_direct(&self.peer),
            stats: self.tailnet.direct_stats(),
        })
    }
    async fn qualify(&mut self, exchange: ExchangePath) -> anyhow::Result<()> {
        if let (Some(expected), Some(before)) = (self.alias.required_transport, exchange.before) {
            let after = self.path_sample().ok();
            let qualified = after
                .as_ref()
                .is_some_and(|after| require_exchange_path(expected, &before, after).is_ok());
            if !qualified {
                self.channel.refuse();
            }
            // Explicit saved policy only, with bounded public identities and
            // actual same-connection counters. No argv, stdin or capability.
            // An Observe witness is the route of this observation, not proof
            // of a retained mutation's original route.
            eprintln!(
                "[cw] member transport {}",
                serde_json::to_string(&serde_json::json!({
                    "schema":"codewire.host-member-path/v1",
                    "environment_id":self.alias.binding.environment_id,
                    "scope_sha256":super::hex(&Sha256::digest(serde_json::to_vec(&self.alias.binding)?)),
                    "action":exchange.action,"request_id":exchange.request_id,
                    "session_id":exchange.session_id,"qualified":qualified,
                    "before":before.diagnostic(),"after":after.map(|value|value.diagnostic()),
                    "inbound_derp_counter_available":false,"nat_traversal_claim":false
                }))?
            );
            ensure!(
                qualified,
                "member route qualification failed after authenticated reply; effects must be observed, never reissued"
            );
        }
        Ok(())
    }
    pub async fn info(&mut self) -> anyhow::Result<v1::HostControlInfoResponse> {
        let value: Exchange<v1::HostControlInfoResponse> = self
            .exchange(1, v1::HostControlInfoRequest {}, None, None)
            .await?;
        self.qualify(value.path).await?;
        let value = value.value;
        admit_info(&value, &self.alias.binding.environment_id, false)?;
        Ok(value)
    }
    pub async fn observe_path(
        &self,
        expected: Option<&str>,
        wait: Duration,
    ) -> anyhow::Result<serde_json::Value> {
        Ok(self.sample_path(expected, wait).await?.diagnostic())
    }
    pub async fn managed_ready(&mut self) -> anyhow::Result<()> {
        let info = self.info().await?;
        admit_info(&info, &self.alias.binding.environment_id, true)
    }
    pub async fn managed_record(
        &mut self,
        request: v1::HostControlManagedReadRequest,
    ) -> anyhow::Result<serde_json::Value> {
        self.managed_ready().await?;
        ensure!(
            request.scope.as_ref() == Some(&self.alias.binding.scope()),
            "member read scope differs"
        );
        let before = if let Some(expected) = self.alias.required_transport {
            Some(self.sample_path(Some(expected.name()), RPC_TIMEOUT).await?)
        } else {
            None
        };
        let value = tokio::time::timeout(RPC_TIMEOUT, async {
            self.channel.send(7, &request.encode_to_vec()).await?;
            let mut chunks = Vec::new();
            let mut bytes = 0usize;
            loop {
                let (action, payload) = self.channel.receive().await?;
                ensure!(action == 7, "member managed response action changed");
                let chunk: v1::HostControlManagedRecordChunk = wire::result(&payload)?;
                ensure!(
                    chunk.total_bytes > 0
                        && chunk.total_bytes <= 5 * 1024 * 1024
                        && chunk.offset == bytes as u64
                        && !chunk.data.is_empty()
                        && chunk.encoded_len() < wire::MAX_PAYLOAD
                        && chunks.len() < 32,
                    "member managed record framing refused"
                );
                bytes = bytes
                    .checked_add(chunk.data.len())
                    .context("member managed response size overflow")?;
                ensure!(
                    bytes <= chunk.total_bytes as usize,
                    "member managed reply exceeds declared total"
                );
                let done = bytes == chunk.total_bytes as usize;
                chunks.push(chunk);
                if done {
                    break;
                }
            }
            let bytes = codewire_daemon::client::validate_host_managed_chunks(&request, &chunks)?;
            serde_json::from_slice(&bytes).context("invalid member managed record")
        })
        .await;
        let value = match value {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                self.channel.refuse();
                return Err(error);
            }
            Err(_) => {
                self.channel.refuse();
                anyhow::bail!("member managed read unavailable; no mutation was reissued");
            }
        };
        self.qualify(ExchangePath {
            before,
            action: 7,
            request_id: None,
            session_id: Some(request.session_id),
        })
        .await?;
        Ok(value)
    }
    async fn sample_path(
        &self,
        expected: Option<&str>,
        wait: Duration,
    ) -> anyhow::Result<PathSample> {
        tokio::time::timeout(wait, async {
            loop {
                let sample = self.path_sample()?;
                let verified = sample.verified;
                if expected.is_none_or(|value| value == sample.name())
                    && (sample.name() != "direct_udp" || verified)
                {
                    return Ok::<_, anyhow::Error>(sample);
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .context("member required transport not observed")?
    }
    pub async fn mutate(
        &mut self,
        directory: &Directory,
        request: v1::HostControlMutationRequest,
    ) -> anyhow::Result<v1::HostControlReceipt> {
        if matches!(
            request.operation,
            Some(
                v1::host_control_mutation_request::Operation::ManagedLaunch(_)
                    | v1::host_control_mutation_request::Operation::ManagedControl(_)
            )
        ) {
            self.managed_ready().await?;
        }
        let (mut record, existing) =
            RequestRecord::prepare(directory, self.alias.binding.clone(), &request).await?;
        let receipt = if existing {
            self.observe_record(directory, &mut record).await?
        } else {
            // Durable before the first possible frame write. Cancellation/drop
            // can never make a duplicate invocation permission to send Mutate
            // again.
            record.begin(directory).await?;
            let value = self
                .exchange(2, request, Some(&record.id), Some(&record.session_id))
                .await?;
            retain_receipt(
                directory,
                &mut record,
                value.value,
                self.qualify(value.path),
            )
            .await?
        };
        if !unsettled(&receipt) {
            return Ok(receipt);
        }
        let started = std::time::Instant::now();
        let receipt = settle_receipt(receipt, SETTLE_BOUND, SETTLE_POLL, async || {
            self.observe_record(directory, &mut record).await
        })
        .await?;
        eprintln!("{}", settle_report(&record.id, &receipt, started.elapsed()));
        Ok(receipt)
    }
    pub async fn observe_record(
        &mut self,
        directory: &Directory,
        record: &mut RequestRecord,
    ) -> anyhow::Result<v1::HostControlReceipt> {
        ensure!(
            record.binding == self.alias.binding,
            "member request belongs to another alias scope"
        );
        let value = self
            .exchange(
                3,
                v1::HostControlObserveRequest {
                    request_id: record.id.clone(),
                    scope: Some(record.binding.scope()),
                },
                Some(&record.id),
                Some(&record.session_id),
            )
            .await?;
        retain_receipt(directory, record, value.value, self.qualify(value.path)).await
    }
    pub async fn list(
        &mut self,
        after: String,
    ) -> anyhow::Result<v1::HostControlListSessionsResponse> {
        let value: Exchange<v1::HostControlListSessionsResponse> = self
            .exchange(
                4,
                v1::HostControlReadRequest {
                    scope: Some(self.alias.binding.scope()),
                    after_session_id: after.clone(),
                    page_limit: 8,
                    ..Default::default()
                },
                None,
                None,
            )
            .await?;
        self.qualify(value.path).await?;
        let value = value.value;
        ensure!(
            value.sessions.len() <= 8
                && value
                    .sessions
                    .windows(2)
                    .all(|x| x[0].session_id < x[1].session_id)
                && value
                    .sessions
                    .iter()
                    .all(|x| x.session_id > after && x.launch_generation > 0)
                && (value.next_session_id.is_empty()
                    || value
                        .sessions
                        .last()
                        .is_some_and(|x| x.session_id == value.next_session_id)),
            "member page cursor changed"
        );
        Ok(value)
    }
    pub async fn get(&mut self, id: &str) -> anyhow::Result<v1::SessionRecord> {
        let value: Exchange<v1::GetSessionResponse> = self
            .exchange(
                5,
                v1::HostControlReadRequest {
                    scope: Some(self.alias.binding.scope()),
                    session_id: id.into(),
                    ..Default::default()
                },
                None,
                Some(id),
            )
            .await?;
        self.qualify(value.path).await?;
        let value = value.value;
        let value = value.session.context("member session is absent")?;
        ensure!(
            value.session_id == id && value.launch_generation > 0,
            "member session identity changed"
        );
        Ok(value)
    }
    pub async fn output(
        &mut self,
        id: &str,
        offset: u64,
    ) -> anyhow::Result<v1::ReadSessionOutputResponse> {
        let value: Exchange<v1::ReadSessionOutputResponse> = self
            .exchange(
                6,
                v1::HostControlReadRequest {
                    scope: Some(self.alias.binding.scope()),
                    session_id: id.into(),
                    offset,
                    limit: READ_PAGE,
                    allow_history_gap: true,
                    ..Default::default()
                },
                None,
                Some(id),
            )
            .await?;
        self.qualify(value.path).await?;
        let value = value.value;
        let mut cursor = if value.history_gap {
            value.retained_start_offset
        } else {
            offset
        };
        let mut size = 0;
        for chunk in &value.chunks {
            ensure!(
                chunk.offset == cursor
                    && chunk.next_offset
                        == cursor
                            .checked_add(chunk.data.len() as u64)
                            .context("member output cursor overflow")?,
                "member output cursor changed"
            );
            cursor = chunk.next_offset;
            size += chunk.data.len();
        }
        ensure!(
            size <= READ_PAGE as usize && value.next_offset == cursor && cursor >= offset,
            "member output page refused"
        );
        Ok(value)
    }
}

/// There is no admin, legacy session, file, resize, provider or arbitrary route
/// dispatch. Principal assertions originate only in the authenticated channel.
pub(super) async fn serve_connection(
    stream: TcpStream,
    secret: codewire_tailnet::derp::key::NodePrivate,
    binding: Binding,
    pin: Arc<OwnerPin>,
    client: codewire_daemon::client::HostControlClient,
) -> anyhow::Result<()> {
    let mut channel =
        tokio::time::timeout(RPC_TIMEOUT, Channel::target(stream, secret, &binding)).await??;
    loop {
        let (action, payload) =
            tokio::time::timeout(Duration::from_secs(60), channel.receive()).await??;
        pin.validate()?;
        let scope = channel.binding.scope();
        if action == 7 {
            let request: v1::HostControlManagedReadRequest = wire::decode(&payload)?;
            ensure!(
                request.scope.as_ref() == Some(&scope),
                "member managed read principal changed"
            );
            let reply =
                tokio::time::timeout(RPC_TIMEOUT, client.read_managed_chunks(request)).await;
            match reply {
                Ok(Ok(chunks)) => {
                    for chunk in chunks {
                        pin.validate()?;
                        let bytes = wire::response(Ok(chunk))?;
                        ensure!(
                            bytes.len() <= wire::MAX_PAYLOAD,
                            "member managed frame exceeds bound"
                        );
                        tokio::time::timeout(RPC_TIMEOUT, channel.send(7, &bytes)).await??;
                    }
                }
                _ => {
                    tokio::time::timeout(RPC_TIMEOUT, channel.send(7, &[0])).await??;
                }
            }
            continue;
        }
        let response = tokio::time::timeout(RPC_TIMEOUT, async {
            let bytes = match action {
                1 => {
                    let _: v1::HostControlInfoRequest = wire::decode(&payload)?;
                    wire::response(client.require_ready().await.map_err(Into::into))?
                }
                2 => {
                    let request: v1::HostControlMutationRequest = wire::decode(&payload)?;
                    ensure!(
                        request.scope.as_ref() == Some(&scope),
                        "member mutation principal changed"
                    );
                    if let Some(v1::host_control_mutation_request::Operation::Launch(x)) =
                        &request.operation
                    {
                        ensure!(
                            !x.pty && x.term.is_empty() && x.width == 0 && x.height == 0,
                            "member PTY is not admitted"
                        );
                    }
                    wire::response(client.mutate(request).await.map_err(Into::into))?
                }
                3 => {
                    let request: v1::HostControlObserveRequest = wire::decode(&payload)?;
                    ensure!(
                        request.scope.as_ref() == Some(&scope),
                        "member observe principal changed"
                    );
                    wire::response(client.observe(request).await.map_err(Into::into))?
                }
                4..=6 => {
                    let request: v1::HostControlReadRequest = wire::decode(&payload)?;
                    ensure!(
                        request.scope.as_ref() == Some(&scope),
                        "member read principal changed"
                    );
                    match action {
                        4 => wire::response(client.list(request).await.map_err(Into::into))?,
                        5 => wire::response(
                            client
                                .get(request)
                                .await
                                .map(|x| v1::GetSessionResponse { session: Some(x) })
                                .map_err(Into::into),
                        )?,
                        _ => {
                            ensure!(
                                (1..=READ_PAGE).contains(&request.limit),
                                "member output page bound exceeded"
                            );
                            wire::response(client.read_output(request).await.map_err(Into::into))?
                        }
                    }
                }
                _ => anyhow::bail!("member action unavailable"),
            };
            Ok::<_, anyhow::Error>(bytes)
        })
        .await
        .context("member target reply unavailable")??;
        pin.validate()?;
        tokio::time::timeout(RPC_TIMEOUT, channel.send(action, &response)).await??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_tailnet::{conn::PeerTransport, direct_udp::Stats};

    #[test]
    fn member_managed_capability_refuses_older_or_partial_owner_before_any_mutation() {
        let env = uuid::Uuid::new_v4().to_string();
        let old = v1::HostControlInfoResponse {
            protocol_version: 1,
            environment_id: env.clone(),
            verbs: vec![1, 2, 3, 4],
            managed_agent_protocol_version: 0,
        };
        admit_info(&old, &env, false).unwrap();
        assert!(admit_info(&old, &env, true).is_err());
        let current = v1::HostControlInfoResponse {
            verbs: (1..=11).collect(),
            managed_agent_protocol_version: 1,
            ..old
        };
        admit_info(&current, &env, true).unwrap();
        for field in ["future", "partial", "duplicate", "identity", "protocol"] {
            let mut bad = current.clone();
            match field {
                "future" => bad.managed_agent_protocol_version = 2,
                "partial" => {
                    bad.verbs.pop();
                }
                "duplicate" => bad.verbs.push(11),
                "identity" => bad.environment_id = uuid::Uuid::new_v4().to_string(),
                "protocol" => bad.protocol_version = 2,
                _ => unreachable!(),
            }
            assert!(admit_info(&bad, &env, true).is_err(), "{field}");
        }
    }

    fn direct(sent: u64, received: u64) -> PathSample {
        PathSample {
            path: PeerTransport::DirectUdp,
            verified: true,
            stats: Some(Stats {
                direct_wg_sent: sent,
                direct_wg_received: received,
                fallback_wg_sent: 3,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn member_required_path_refuses_fallback_unverified_empty_and_changed_exchange() {
        let before = direct(10, 20);
        let after = direct(11, 21);
        require_exchange_path(MemberPath::DirectUdp, &before, &after).unwrap();
        // A path probe by itself, without traffic in this actual exchange,
        // cannot stand in for correlated request/response counters.
        assert!(require_exchange_path(MemberPath::DirectUdp, &before, &before).is_err());
        for changed in 0..5 {
            let mut after = direct(11, 21);
            match changed {
                0 => after.verified = false,
                1 => after.stats.as_mut().unwrap().fallback_wg_sent += 1,
                2 => after.stats.as_mut().unwrap().peer_relay_wg_sent += 1,
                3 => after.path = PeerTransport::DerpRelay,
                _ => after.stats.as_mut().unwrap().direct_wg_received = 20,
            }
            assert!(require_exchange_path(MemberPath::DirectUdp, &before, &after).is_err());
        }
        let relay = PathSample {
            path: PeerTransport::DerpRelay,
            verified: false,
            stats: None,
        };
        require_exchange_path(MemberPath::Derp, &relay, &relay).unwrap();
        let maybe_direct = PathSample {
            path: PeerTransport::DerpRelay,
            verified: false,
            stats: Some(Stats::default()),
        };
        assert!(require_exchange_path(MemberPath::Derp, &maybe_direct, &maybe_direct).is_err());
    }
}
