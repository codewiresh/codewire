//! Live runtime transactions for local Linux guests. Transfer owns no
//! lifecycle lock; only admission and the short selector commit hold the
//! authoritative core lock.
use super::*;
use crate::cw_runtime::AdmittedCwRuntimeAsset;
use codewire_vmm_guest_probe::cw_runtime::CwRuntimeProvenance;
use codewire_vmm_guest_probe::cw_runtime_live::*;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use v1::environment_runner_service_client::EnvironmentRunnerServiceClient;
use v1::linux_cw_runtime_service_server::LinuxCwRuntimeService;

#[cfg(target_os = "linux")]
use crate::host::process::LiveProcess as RecordedProcess;
use crate::host::process::ProcessIdentity;
#[cfg(target_os = "macos")]
use crate::host::process::WatchedProcess as RecordedProcess;

/// Observe a recorded runner or VMM birth for liveness. Linux recovers it as
/// a pidfd; Darwin never adopts a process it did not spawn, so it only
/// watches that exact birth's exit.
fn recorded(identity: &ProcessIdentity) -> Result<RecordedProcess, RecoveryError> {
    #[cfg(target_os = "linux")]
    {
        LiveProcess::recover(identity)
    }
    #[cfg(target_os = "macos")]
    {
        RecordedProcess::watch(identity)
    }
}

// Info/observe also verify all retained sealed members in the guest; their
// deadline must cover the same bounded admission as publication/selection.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(LIVE_RUNTIME_TIMEOUT_SECONDS);
const RUNNER_OBSERVE_TIMEOUT: Duration = Duration::from_secs(3);
const RUNNER_OBSERVE_MAX_BYTES: usize = 4096;

/// This connector has only the saved runner's actual socket-derived birth.
/// It cannot discover/adopt a different runner or enter lifecycle recovery.
struct RuntimeRunnerPin {
    socket: PathBuf,
    identity: SocketIdentity,
    process: ProcessIdentity,
    peer: OwnedFd,
}

impl RuntimeRunnerPin {
    fn require_live_peer(&self) -> io::Result<()> {
        let mut descriptor = libc::pollfd {
            fd: self.peer.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: an owned socket-derived pidfd and one initialized entry;
        // zero timeout cannot wait. Exit, errors and interruption deny access.
        if unsafe { libc::poll(&mut descriptor, 1, 0) } != 0 || descriptor.revents != 0 {
            return Err(runner_peer_changed());
        }
        Ok(())
    }

    fn revalidate(&self) -> io::Result<()> {
        self.require_live_peer()?;
        self.identity
            .revalidate(&self.socket)
            .map_err(|_| runner_peer_changed())?;
        recorded(&self.process).map_err(|_| runner_peer_changed())?;
        self.require_live_peer()?;
        Ok(())
    }

    async fn connect(&self) -> io::Result<RuntimeRunnerStream> {
        self.revalidate()?;
        let stream =
            tokio::time::timeout(RUNNER_OBSERVE_TIMEOUT, UnixStream::connect(&self.socket))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "retained runner connect timed out")
                })??;
        let peer = crate::host::supervisor_peer::admit_known_process_stream(&stream, &self.process)
            .map_err(|_| runner_peer_changed())?;
        self.identity
            .revalidate(&self.socket)
            .map_err(|_| runner_peer_changed())?;
        Ok(RuntimeRunnerStream {
            stream,
            _peer: peer,
        })
    }
}

fn runner_peer_changed() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "retained runner identity changed",
    )
}

/// Keep SO_PEERPIDFD until the corresponding tonic connection is closed.
struct RuntimeRunnerStream {
    stream: UnixStream,
    _peer: OwnedFd,
}
impl AsyncRead for RuntimeRunnerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for RuntimeRunnerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn validate_observed_runner(
    binding: &RuntimeBinding,
    runner: &RunnerRecord,
    info: &v1::RunnerInfo,
) -> Result<(), Status> {
    if info.environment_id != binding.environment_id.to_string()
        || info.generation != binding.generation
        || info.state != v1::EnvironmentState::Running as i32
        || info.artifact_generation != runner.artifact_generation
        || info.cw_runtime_catalog_generation != binding.bootstrap_catalog_sha256
        || !info.error_code.is_empty()
    {
        return Err(Status::failed_precondition(
            "retained running VM identity changed",
        ));
    }
    Ok(())
}

async fn observe_retained_runner(
    socket: PathBuf,
    binding: &RuntimeBinding,
    runner: &RunnerRecord,
) -> Result<(v1::DaemonAccess, Arc<RuntimeRunnerPin>), Status> {
    // The first connection supplies the exact birth pin retained throughout
    // this transaction; every tonic reconnect must prove that same birth.
    runner
        .socket
        .revalidate(&socket)
        .map_err(|_| Status::failed_precondition("retained runner socket changed"))?;
    let initial = tokio::time::timeout(RUNNER_OBSERVE_TIMEOUT, UnixStream::connect(&socket))
        .await
        .map_err(|_| Status::deadline_exceeded("retained runner connect timed out"))?
        .map_err(|_| Status::failed_precondition("retained runner is unavailable"))?;
    let peer = crate::host::supervisor_peer::admit_known_process_stream(&initial, &runner.process)
        .map_err(|_| Status::failed_precondition("retained runner birth changed"))?;
    runner
        .socket
        .revalidate(&socket)
        .map_err(|_| Status::failed_precondition("retained runner socket changed"))?;
    let pin = Arc::new(RuntimeRunnerPin {
        socket,
        identity: runner.socket.clone(),
        process: runner.process.clone(),
        peer,
    });
    drop(initial);
    let connector_pin = pin.clone();
    let channel =
        tonic::transport::Endpoint::from_static("http://codewire-retained-runtime-runner")
            .connect_timeout(RUNNER_OBSERVE_TIMEOUT)
            .timeout(RUNNER_OBSERVE_TIMEOUT)
            .connect_with_connector(tower::service_fn(move |_| {
                let pin = connector_pin.clone();
                async move { pin.connect().await.map(hyper_util::rt::TokioIo::new) }
            }))
            .await
            .map_err(|_| Status::failed_precondition("retained runner connection was refused"))?;
    let mut client = EnvironmentRunnerServiceClient::new(channel)
        .max_decoding_message_size(RUNNER_OBSERVE_MAX_BYTES);
    let protocol = client
        .get_runner_protocol_info(v1::GetRunnerProtocolInfoRequest {})
        .await?
        .into_inner();
    crate::runner_service::admit_runner_protocol_info(&protocol)
        .map_err(|_| Status::failed_precondition("retained runner protocol is unsupported"))?;
    let info = client
        .get_runner_info(v1::GetRunnerInfoRequest {})
        .await?
        .into_inner();
    validate_observed_runner(binding, runner, &info)?;
    let access = client
        .get_generation_daemon_access(v1::GetGenerationDaemonAccessRequest {
            environment_id: binding.environment_id.to_string(),
            generation: binding.generation,
        })
        .await?
        .into_inner();
    // Validate the same closed transport/capability shape without retaining it
    // in any record, response or log. The final physical endpoint binds its path.
    codewire_vmm_guest_probe::Seed::new(
        binding.environment_id,
        binding.generation,
        access.guest_port,
        access.generation_capability.clone(),
    )
    .map_err(|_| Status::failed_precondition("invalid retained generation access"))?;
    if access.hybrid_socket.is_empty()
        || access.hybrid_socket.len() > RUNNER_OBSERVE_MAX_BYTES
        || access.hybrid_socket.contains('\0')
    {
        return Err(Status::failed_precondition(
            "invalid retained generation access",
        ));
    }
    let info = client
        .get_runner_info(v1::GetRunnerInfoRequest {})
        .await?
        .into_inner();
    validate_observed_runner(binding, runner, &info)?;
    pin.revalidate()
        .map_err(|_| Status::failed_precondition("retained runner changed during observation"))?;
    Ok((access, pin))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    binding: RuntimeBinding,
    runner: RunnerRecord,
    vmm: ProcessIdentity,
    vsock: SocketIdentity,
    expected_revision: u64,
    target: CwRuntimeProvenance,
    rollback: bool,
}

impl Intent {
    fn decode(operation: &OperationRecord) -> Result<Self, Status> {
        let intent: Self = serde_json::from_value(operation.payload.clone())
            .map_err(|_| Status::failed_precondition("invalid runtime intent"))?;
        intent
            .binding
            .validate()
            .map_err(Status::failed_precondition)?;
        intent
            .target
            .validate()
            .map_err(Status::failed_precondition)?;
        if operation.environment_id != Some(intent.binding.environment_id)
            || !operation.kind.cw_runtime()
            || intent.expected_revision == 0
            || !valid_sha256(&intent.runner.artifact_generation)
            || intent.rollback != (operation.kind == OperationKind::RollbackCwRuntime)
            || intent.runner.cw_runtime_catalog_generation.as_deref()
                != Some(intent.binding.bootstrap_catalog_sha256.as_str())
        {
            return Err(Status::failed_precondition(
                "runtime intent identity changed",
            ));
        }
        Ok(intent)
    }
    fn request(&self, operation_id: Uuid, cancel: bool) -> RuntimeRequest {
        let target_sha256 = self.target.payload.sha256.clone();
        let action = if cancel {
            RuntimeAction::Cancel {
                operation_id,
                expected_revision: self.expected_revision,
                target_sha256,
            }
        } else if self.rollback {
            RuntimeAction::RetainedSelect {
                operation_id,
                expected_revision: self.expected_revision,
                target_sha256,
            }
        } else {
            RuntimeAction::Select {
                operation_id,
                expected_revision: self.expected_revision,
                target_sha256,
            }
        };
        RuntimeRequest {
            protocol_version: LIVE_RUNTIME_PROTOCOL,
            binding: self.binding.clone(),
            action,
        }
    }
}

impl crate::cw_runtime::CwRuntimeJournalEvidence<'_> {
    /// The public facade exposes only a fixed validation result. Keep the
    /// owning intent/result types private and perform no live admission here.
    pub(crate) fn validate_owned(&self) -> bool {
        let kind = match self.kind {
            "update_cw_runtime" => OperationKind::UpdateCwRuntime,
            "rollback_cw_runtime" => OperationKind::RollbackCwRuntime,
            _ => return false,
        };
        let phase = match self.phase {
            "intent" => OperationPhase::Intent,
            "effect_applied" => OperationPhase::EffectApplied,
            "completed" => OperationPhase::Completed,
            "failed" => OperationPhase::Failed,
            "interrupted" => OperationPhase::Interrupted,
            _ => return false,
        };
        if self.operation_id.is_nil()
            || self.environment_id.is_nil()
            || self.payload.is_empty()
            || self.payload.len() > Self::MAXIMUM_JSON_BYTES
            || self
                .result
                .is_some_and(|bytes| bytes.is_empty() || bytes.len() > Self::MAXIMUM_JSON_BYTES)
            || self.error_code.is_some_and(|code| {
                code.is_empty()
                    || code.len() > 64
                    || !code
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            })
        {
            return false;
        }
        let valid_outcome = match phase {
            OperationPhase::Intent | OperationPhase::EffectApplied => {
                self.result.is_none() && self.error_code.is_none()
            }
            OperationPhase::Completed => self.result.is_some() && self.error_code.is_none(),
            OperationPhase::Failed | OperationPhase::Interrupted => {
                self.result.is_none() && self.error_code.is_some()
            }
        };
        if !valid_outcome {
            return false;
        }
        let Ok(payload) = serde_json::from_slice(self.payload) else {
            return false;
        };
        let operation = OperationRecord {
            operation_id: self.operation_id,
            // Request identity and diagnostic counters do not participate in
            // the owner's intent/receipt validation. No store is consulted.
            request_id: self.operation_id,
            environment_id: Some(self.environment_id),
            kind,
            phase,
            checkpoint: 0,
            payload,
            result: None,
            error_code: None,
            created_unix_ms: 0,
            updated_unix_ms: 0,
        };
        let Ok(intent) = Intent::decode(&operation) else {
            return false;
        };
        if let Some(bytes) = self.result {
            let Ok(result) = serde_json::from_slice(bytes) else {
                return false;
            };
            let Ok(reply) = decode_result(&operation, &result) else {
                return false;
            };
            // A cancelled operation may not have published its target. Any
            // admitted target member must retain its approved full identity.
            if reply
                .selection
                .catalog
                .runtime(&intent.target.payload.sha256)
                .is_some_and(|member| member != &intent.target)
            {
                return false;
            }
        }
        true
    }
}

struct Endpoint {
    binding: RuntimeBinding,
    socket: PathBuf,
    socket_identity: SocketIdentity,
    runner: RecordedProcess,
    vmm: RecordedProcess,
    // Startup already owns its runner directly; ordinary runtime calls keep
    // their admitted socket-derived runner pin for the entire transaction.
    runner_pin: Option<Arc<RuntimeRunnerPin>>,
}

impl Endpoint {
    fn revalidate(&self) -> Result<(), Status> {
        if let Some(pin) = &self.runner_pin {
            pin.revalidate()
                .map_err(|_| Status::failed_precondition("retained runner changed"))?;
        }
        self.socket_identity
            .revalidate(&self.socket)
            .map_err(|_| Status::failed_precondition("runtime transport was replaced"))?;
        if self
            .vmm
            .is_exited()
            .map_err(|_| Status::failed_precondition("runtime VM birth unavailable"))?
        {
            return Err(Status::failed_precondition("runtime VM process exited"));
        }
        if self
            .runner
            .is_exited()
            .map_err(|_| Status::failed_precondition("runtime process custody unavailable"))?
        {
            return Err(Status::failed_precondition("runtime owner process exited"));
        }
        Ok(())
    }
    async fn call(
        &self,
        action: RuntimeAction,
        pack: Option<&[u8]>,
    ) -> Result<RuntimeReply, Status> {
        self.revalidate()?;
        let request = RuntimeRequest {
            protocol_version: LIVE_RUNTIME_PROTOCOL,
            binding: self.binding.clone(),
            action,
        };
        request.validate().map_err(Status::invalid_argument)?;
        let bound = if pack.is_some() {
            Duration::from_secs(LIVE_RUNTIME_TIMEOUT_SECONDS)
        } else {
            CONTROL_TIMEOUT
        };
        let reply = tokio::time::timeout(bound, async {
            let (mut stream, _peer) = crate::hybrid_vsock::connect_runtime_publisher(&self.socket, &self.socket_identity, self.vmm.identity()).await
                .map_err(|_| Status::failed_precondition("running guest does not offer the trusted cw publisher; old guests require an explicit later boot"))?;
            stream.write_all(&encode_frame(&request).map_err(Status::invalid_argument)?).await
                .map_err(|_| unknown())?;
            if let Some(pack) = pack {
                for chunk in pack.chunks(64 * 1024) { stream.write_all(chunk).await.map_err(|_| unknown())?; }
            }
            stream.shutdown().await.map_err(|_| unknown())?;
            let size = stream.read_u32().await.map_err(|_| unknown())? as usize;
            if size == 0 || size > LIVE_RUNTIME_MAX_FRAME { return Err(Status::failed_precondition("invalid runtime response bound")); }
            let mut bytes = vec![0; size]; stream.read_exact(&mut bytes).await.map_err(|_| unknown())?;
            let mut excess = [0];
            if stream.read(&mut excess).await.map_err(|_| unknown())? != 0 { return Err(Status::failed_precondition("runtime response trailing bytes")); }
            let response: RuntimeResponse = serde_json::from_slice(&bytes)
                .map_err(|_| Status::failed_precondition("invalid runtime response"))?;
            let reply = match (response.reply, response.refusal) {
                (Some(reply), None) => reply,
                (None, Some(refusal)) => return Err(refusal_status(refusal)),
                _ => return Err(Status::failed_precondition("ambiguous runtime response")),
            };
            reply.validate(&self.binding).map_err(Status::failed_precondition)?;
            Ok(reply)
        }).await.map_err(|_| unknown())??;
        self.revalidate()?;
        Ok(reply)
    }
}

fn unknown() -> Status {
    Status::unavailable(
        "runtime outcome is unknown; observe the SAME request UUID on the SAME VM, do not replay",
    )
}
fn refusal_status(refusal: RuntimeRefusal) -> Status {
    match refusal {
        RuntimeRefusal::StaleRevision => Status::aborted("runtime selection revision changed"),
        RuntimeRefusal::Capacity => {
            Status::resource_exhausted("runtime retention capacity reached")
        }
        RuntimeRefusal::Collision => Status::aborted("runtime operation or sealed bytes conflict"),
        RuntimeRefusal::Cancelled => Status::cancelled("runtime operation was cancelled"),
        _ => Status::failed_precondition("runtime publisher refused the request"),
    }
}

async fn admit_endpoint(
    core: &mut SupervisorCore,
    id: Uuid,
    expected: Option<&Intent>,
) -> Result<(Endpoint, RunnerRecord), Status> {
    if core
        .store
        .has_pending_lifecycle_operation(id)
        .map_err(SupervisorError::from)
        .map_err(Status::from)?
    {
        return Err(Status::aborted(
            "native environment has a pending lifecycle operation; runtime control cannot replay it",
        ));
    }
    let environment = core
        .state
        .environments
        .values()
        .find(|environment| environment.id == id)
        .cloned()
        .ok_or_else(|| Status::not_found("native environment UUID was not found"))?;
    if core.incompatible_runners.contains(&id)
        || environment.state != StoredEnvironmentState::Running
    {
        return Err(Status::failed_precondition(
            "runtime requires a compatible running Linux VM",
        ));
    }
    let binding = environment
        .cw_runtime
        .as_ref()
        .filter(|binding| binding.staging_catalog_generation.is_none())
        .ok_or_else(|| Status::failed_precondition("VM has no immutable cw bootstrap catalog"))?;
    let runner = environment
        .runner
        .clone()
        .filter(|runner| {
            runner.cw_runtime_catalog_generation.as_deref()
                == Some(binding.active_catalog_generation.as_str())
        })
        .ok_or_else(|| Status::failed_precondition("VM bootstrap attachment changed"))?;
    let identity = RuntimeBinding {
        environment_id: id,
        generation: environment.generation,
        bootstrap_catalog_sha256: binding.active_catalog_generation.clone(),
    };
    identity.validate().map_err(Status::failed_precondition)?;
    if expected.is_some_and(|expected| expected.binding != identity || expected.runner != runner) {
        return Err(Status::failed_precondition(
            "runtime operation belongs to a different VM birth",
        ));
    }
    let _live = recorded(&runner.process)
        .map_err(|_| Status::failed_precondition("runtime runner birth unavailable"))?;
    // No generic daemon_access/reconcile/adopt/spawn/retire route is reachable.
    // The retained runner's actual birth, protocol and Running reply are read
    // directly; its transient capability never enters durable runtime state.
    let (access, pin) =
        observe_retained_runner(core.config.runner_socket(id), &identity, &runner).await?;
    let (mut endpoint, runner) = admit_physical_endpoint(core, identity, runner, access, expected)?;
    endpoint.runner_pin = Some(pin);
    endpoint.revalidate()?;
    Ok((endpoint, runner))
}

/// Startup already admitted the exact RunnerClient and its Running reply.
/// Confirm the guest's retained selector before the lifecycle journal may
/// promote that boot. This is observation only: lost selectors/receipts never
/// cause a new publish, selection or bootstrap-default substitution.
pub(super) async fn confirm_boot(
    core: &mut SupervisorCore,
    name: &str,
    generation: u64,
    access: v1::DaemonAccess,
) -> Result<(), Status> {
    let environment = core.environment(name).map_err(Status::from)?;
    let Some(binding) = environment.cw_runtime.as_ref() else {
        return Ok(());
    };
    if binding.staging_catalog_generation.is_some() {
        return Err(Status::failed_precondition(
            "runtime bootstrap is not fixed",
        ));
    }
    let mut runner = environment
        .runner
        .clone()
        .ok_or_else(|| Status::failed_precondition("runtime startup owner is missing"))?;
    runner.cw_runtime_catalog_generation = Some(binding.active_catalog_generation.clone());
    let identity = RuntimeBinding {
        environment_id: environment.id,
        generation,
        bootstrap_catalog_sha256: binding.active_catalog_generation.clone(),
    };
    identity.validate().map_err(Status::failed_precondition)?;
    let (endpoint, _) = admit_physical_endpoint(core, identity, runner, access, None)?;
    let reply = endpoint.call(RuntimeAction::Info, None).await?;
    approve_reply(core, &reply)?;
    reconcile_interrupted(&core.store, &reply)?;
    Ok(())
}

fn admit_physical_endpoint(
    core: &SupervisorCore,
    identity: RuntimeBinding,
    runner: RunnerRecord,
    access: v1::DaemonAccess,
    expected: Option<&Intent>,
) -> Result<(Endpoint, RunnerRecord), Status> {
    let id = identity.environment_id;
    let live = recorded(&runner.process)
        .map_err(|_| Status::failed_precondition("runtime runner birth unavailable"))?;
    let vm_root = core.config.engine_root().join("vms").join(id.to_string());
    // The VM's sockets live in the engine's short socket directory (#2735).
    let socket = crate::socket_dir::predicted(&core.config.engine_root())
        .join("vms")
        .join(id.to_string())
        .join("vsock")
        .join(crate::state::VSOCK_SOCKET_NAME);
    if Path::new(&access.hybrid_socket) != socket || access.guest_port != DAEMON_VSOCK_PORT {
        return Err(Status::failed_precondition(
            "runtime transport is not the authoritative VM endpoint",
        ));
    }
    let persisted = crate::state::PersistedVmState::read(&vm_root.join("state.json"))
        .map_err(|_| Status::failed_precondition("runtime VM state is unavailable"))?;
    if persisted.vm_id != id
        || persisted.generation != identity.generation
        || persisted.phase != crate::state::VmPhase::Running
    {
        return Err(Status::failed_precondition(
            "runtime VM incarnation changed",
        ));
    }
    let disk = asset_store(core)?
        .open_catalog(&identity.bootstrap_catalog_sha256)
        .map_err(|_| Status::failed_precondition("runtime bootstrap disk admission failed"))?;
    if persisted.cw_runtime_disk.as_ref() != Some(&disk) {
        return Err(Status::failed_precondition(
            "runtime bootstrap disk was replaced",
        ));
    }
    let socket_identity = persisted
        .vsock_socket
        .ok_or_else(|| Status::failed_precondition("runtime VM endpoint is unbound"))?;
    if expected.is_some_and(|expected| {
        expected.vmm != persisted.process || expected.vsock != socket_identity
    }) {
        return Err(Status::failed_precondition(
            "runtime VMM birth or endpoint was replaced",
        ));
    }
    socket_identity
        .revalidate(&socket)
        .map_err(|_| Status::failed_precondition("runtime VM endpoint was replaced"))?;
    let vmm = recorded(&persisted.process)
        .map_err(|_| Status::failed_precondition("runtime VMM birth is unavailable"))?;
    Ok((
        Endpoint {
            binding: identity,
            socket,
            socket_identity,
            runner: live,
            vmm,
            runner_pin: None,
        },
        runner,
    ))
}

fn asset_store(core: &SupervisorCore) -> Result<CwRuntimeStore, Status> {
    let engine = PrivateRoot::open(&core.config.engine_root())
        .map_err(|_| Status::failed_precondition("runtime store unavailable"))?;
    CwRuntimeStore::create(&engine)
        .map_err(|_| Status::failed_precondition("runtime store unavailable"))
}

fn approve_reply(core: &SupervisorCore, reply: &RuntimeReply) -> Result<(), Status> {
    reply
        .validate(&reply.binding)
        .map_err(Status::failed_precondition)?;
    let store = asset_store(core)?;
    let bootstrap = store
        .open_catalog(&reply.binding.bootstrap_catalog_sha256)
        .map_err(|_| Status::failed_precondition("runtime bootstrap catalog unavailable"))?;
    for member in &bootstrap.manifest.catalog.runtimes {
        if reply.selection.catalog.runtime(&member.payload.sha256) != Some(member) {
            return Err(Status::failed_precondition(
                "runtime bootstrap member was lost",
            ));
        }
    }
    for member in &reply.selection.catalog.runtimes {
        if bootstrap.manifest.catalog.runtime(&member.payload.sha256) == Some(member) {
            continue;
        }
        let asset = store.read_asset(&member.payload.sha256).map_err(|_| {
            Status::failed_precondition("runtime asset is not retained by the host")
        })?;
        if asset.provenance != *member {
            return Err(Status::failed_precondition(
                "runtime asset provenance conflicts",
            ));
        }
    }
    for receipt in &reply.selection.operations {
        let operation = core
            .store
            .cw_runtime_operation_by_id(receipt.operation_id)
            .map_err(SupervisorError::from)
            .map_err(Status::from)?
            .ok_or_else(|| {
                Status::failed_precondition("runtime receipt has no approved host intent")
            })?;
        let intent = Intent::decode(&operation)?;
        if intent.binding.environment_id != reply.binding.environment_id
            || intent.binding.bootstrap_catalog_sha256 != reply.binding.bootstrap_catalog_sha256
            || intent.binding.generation > reply.binding.generation
        {
            return Err(Status::failed_precondition(
                "runtime receipt belongs to a different environment or future VM",
            ));
        }
        check_receipt(&intent, receipt)?;
    }
    check_selection_history(&bootstrap.manifest.catalog, &reply.selection)?;
    for completed in core
        .store
        .completed_cw_runtime_operations(reply.binding.environment_id)
        .map_err(SupervisorError::from)
        .map_err(Status::from)?
    {
        let saved = completed
            .result
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("runtime result missing"))?;
        let saved = decode_result(&completed, saved)?;
        if saved.selection.revision > reply.selection.revision
            || saved.observed.as_ref().is_none_or(|receipt| {
                reply.selection.receipt(receipt.operation_id) != Some(receipt)
            })
        {
            return Err(Status::failed_precondition(
                "confirmed runtime selection or receipt was lost",
            ));
        }
    }
    Ok(())
}

/// Reconstruct only selection effects, from the immutable bootstrap and the
/// complete append-only receipts. Membership publication alone cannot change
/// default/previous/revision, and a retained receipt cannot mask a reverted or
/// substituted selector after a boot.
fn check_selection_history(
    bootstrap: &codewire_vmm_guest_probe::cw_runtime::CwRuntimeCatalog,
    selection: &RuntimeSelection,
) -> Result<(), Status> {
    let mut active = bootstrap.active_sha256.as_str();
    let mut previous = None;
    let mut revision = 1_u64;
    for receipt in &selection.operations {
        if receipt.outcome == SelectionOutcome::Committed {
            if receipt.expected_revision != revision {
                return Err(Status::failed_precondition(
                    "runtime receipt history is discontinuous",
                ));
            }
            revision = revision
                .checked_add(1)
                .ok_or_else(|| Status::failed_precondition("runtime revision overflow"))?;
            previous = Some(active);
            active = &receipt.target_sha256;
        }
        if receipt.selection_revision != revision {
            return Err(Status::failed_precondition(
                "runtime receipt revision changed",
            ));
        }
    }
    if selection.revision != revision
        || selection.catalog.active_sha256 != active
        || selection.previous_sha256.as_deref() != previous
    {
        return Err(Status::failed_precondition(
            "runtime default does not match its retained receipt history",
        ));
    }
    Ok(())
}

fn reconcile_interrupted(
    store: &SupervisorStore,
    reply: &RuntimeReply,
) -> Result<Vec<String>, Status> {
    let operations = store
        .interrupted_cw_runtime_operations(reply.binding.environment_id)
        .map_err(SupervisorError::from)
        .map_err(Status::from)?;
    let mut unknown = Vec::new();
    for operation in operations {
        let intent = Intent::decode(&operation)?;
        if let Some(receipt) = reply.selection.receipt(operation.operation_id) {
            check_receipt(&intent, receipt)?;
            let mut recorded = reply.clone();
            recorded.binding = intent.binding;
            recorded.observed = Some(receipt.clone());
            let result = serde_json::to_value(recorded)
                .map_err(|_| Status::internal("runtime recovery encoding failed"))?;
            decode_result(&operation, &result)?;
            store
                .resolve_interrupted_cw_runtime(&operation, &result)
                .map_err(SupervisorError::from)
                .map_err(Status::from)?;
        } else {
            unknown.push(operation.request_id.to_string());
        }
    }
    Ok(unknown)
}

/// Only a terminal observation may use a newer trusted VM birth. Same-birth
/// queries still retain the complete original runner/VMM/socket admission.
fn query_uses_retained_history(
    operation: &OperationRecord,
    intent: &Intent,
    current: &RuntimeBinding,
    cancel: bool,
) -> Result<bool, Status> {
    current.validate().map_err(Status::failed_precondition)?;
    if cancel && operation.phase == OperationPhase::Interrupted {
        return Err(Status::failed_precondition(
            "cannot cancel an uncertain operation from a different VM birth; observe it",
        ));
    }
    if intent.binding.environment_id != current.environment_id
        || intent.binding.bootstrap_catalog_sha256 != current.bootstrap_catalog_sha256
        || intent.binding.generation > current.generation
    {
        return Err(Status::failed_precondition(
            "retained runtime request belongs to a different environment, bootstrap or future VM",
        ));
    }
    if intent.binding.generation == current.generation {
        return Ok(false);
    }
    if !cancel && operation.phase.terminal() {
        return Ok(true);
    }
    Err(Status::failed_precondition(
        "runtime mutation belongs to a different VM birth; observe the retained request",
    ))
}

fn check_receipt(intent: &Intent, receipt: &SelectionReceipt) -> Result<(), Status> {
    if receipt.generation != intent.binding.generation
        || receipt.expected_revision != intent.expected_revision
        || receipt.target_sha256 != intent.target.payload.sha256
    {
        return Err(Status::failed_precondition(
            "runtime receipt does not match the approved intent",
        ));
    }
    Ok(())
}

pub(super) fn decode_result(
    operation: &OperationRecord,
    result: &serde_json::Value,
) -> Result<RuntimeReply, Status> {
    let reply: RuntimeReply = serde_json::from_value(result.clone())
        .map_err(|_| Status::failed_precondition("invalid runtime result"))?;
    let intent = Intent::decode(operation)?;
    reply
        .validate(&intent.binding)
        .map_err(Status::failed_precondition)?;
    let receipt = reply
        .observed
        .as_ref()
        .filter(|receipt| receipt.operation_id == operation.operation_id)
        .ok_or_else(|| {
            Status::failed_precondition("runtime result lacks an exact operation receipt")
        })?;
    check_receipt(&intent, receipt)?;
    Ok(reply)
}

pub(super) fn status(
    reply: &RuntimeReply,
    operation: Option<&OperationRecord>,
) -> Result<v1::LinuxCwRuntimeStatus, Status> {
    Ok(v1::LinuxCwRuntimeStatus {
        environment_id: reply.binding.environment_id.to_string(),
        generation: reply.binding.generation,
        selection_json: serde_json::to_vec(&reply.selection)
            .map_err(|_| Status::internal("runtime status encoding failed"))?,
        operation_id: operation
            .map(|operation| operation.operation_id.to_string())
            .unwrap_or_default(),
        request_id: operation
            .map(|operation| operation.request_id.to_string())
            .unwrap_or_default(),
        phase: operation
            .map(|operation| operation.phase.as_str().to_owned())
            .unwrap_or_default(),
        error_code: operation
            .and_then(|operation| operation.error_code.clone())
            .unwrap_or_default(),
        interrupted_request_ids: Vec::new(),
    })
}

fn finish(
    core: &SupervisorCore,
    operation: &OperationRecord,
    reply: &RuntimeReply,
) -> Result<OperationRecord, Status> {
    approve_reply(core, reply)?;
    let intent = Intent::decode(operation)?;
    let receipt = reply
        .observed
        .as_ref()
        .filter(|receipt| receipt.operation_id == operation.operation_id)
        .ok_or_else(unknown)?;
    check_receipt(&intent, receipt)?;
    let result = serde_json::to_value(reply)
        .map_err(|_| Status::internal("runtime result encoding failed"))?;
    core.store
        .advance_operation(
            operation.operation_id,
            operation.checkpoint,
            OperationPhase::Completed,
            Some(&result),
            None,
        )
        .map_err(SupervisorError::from)
        .map_err(Status::from)
}

/// Crash recovery NEVER republishes or reissues Select. If no receipt exists,
/// durable Cancel races the old in-flight request at the guest commit lock.
pub(super) async fn recover(
    core: &mut SupervisorCore,
    operation: &OperationRecord,
) -> Result<(), SupervisorError> {
    let intent = Intent::decode(operation).map_err(|_| SupervisorError::InvalidState)?;
    let (endpoint, _) =
        match admit_endpoint(core, intent.binding.environment_id, Some(&intent)).await {
            Ok(endpoint) => endpoint,
            Err(_) => {
                // Only an authoritative stopped record for this exact UUID
                // and generation closes a lost birth. No socket error or
                // permission failure is treated as process death.
                let vmm_exited = matches!(
                    LiveProcess::recover(&intent.vmm),
                    Err(RecoveryError::ProcessExited)
                );
                if vmm_exited
                    && core.state.environments.values().any(|environment| {
                        environment.id == intent.binding.environment_id
                            && environment.generation == intent.binding.generation
                            && environment.state == StoredEnvironmentState::Stopped
                            && environment.runner.is_none()
                    })
                {
                    core.store.advance_operation(
                        operation.operation_id,
                        operation.checkpoint,
                        OperationPhase::Interrupted,
                        None,
                        Some("runtime_vm_birth_lost"),
                    )?;
                }
                return Ok(());
            }
        };
    let reply = match endpoint
        .call(
            RuntimeAction::Observe {
                operation_id: operation.operation_id,
            },
            None,
        )
        .await
    {
        Ok(reply) if reply.observed.is_some() => reply,
        Ok(_) => match endpoint
            .call(intent.request(operation.operation_id, true).action, None)
            .await
        {
            Ok(reply) => reply,
            Err(_) => return Ok(()),
        },
        Err(_) => return Ok(()),
    };
    // A peer/receipt admission refusal preserves the uncertain intent. It is
    // never converted into a shutdown of this retained supervisor or a false
    // terminal result by the ordinary lifecycle worker.
    let _ = finish(core, operation, &reply);
    Ok(())
}

impl SupervisorRpc {
    async fn runtime_mutate(
        &self,
        request: v1::LinuxCwRuntimeMutation,
        rollback: bool,
    ) -> Result<v1::LinuxCwRuntimeStatus, Status> {
        let id = parse_operation_id(&request.environment_id)?;
        let request_id = parse_operation_id(&request.request_id)?;
        let requested = RuntimeBinding {
            environment_id: id,
            generation: request.generation,
            bootstrap_catalog_sha256: request.bootstrap_catalog_sha256.clone(),
        };
        requested.validate().map_err(Status::invalid_argument)?;
        if request.expected_revision == 0 || !digest(&request.target_sha256) {
            return Err(Status::invalid_argument(
                "invalid runtime selection request",
            ));
        }
        if rollback && (!request.source_lock.is_empty() || !request.image_index_sha256.is_empty()) {
            return Err(Status::invalid_argument(
                "rollback selects only a retained runtime",
            ));
        }
        let engine_path = { self.core.lock().await.config.engine_root() };
        let asset = if rollback {
            None
        } else {
            if !digest(&request.image_index_sha256)
                || !Path::new(&request.source_lock).is_absolute()
            {
                return Err(Status::invalid_argument(
                    "update requires an exact image pin and admitted local source lock",
                ));
            }
            let source = PathBuf::from(&request.source_lock);
            let image = request.image_index_sha256.clone();
            let target = request.target_sha256.clone();
            Some(
                tokio::task::spawn_blocking(move || {
                    let engine = PrivateRoot::open(&engine_path)?;
                    CwRuntimeStore::create(&engine)?.admit_source_pinned(&source, &image, &target)
                })
                .await
                .map_err(|_| Status::internal("runtime admission task failed"))?
                .map_err(|_| {
                    Status::failed_precondition("pinned cw image asset admission failed")
                })?,
            )
        };
        let (operation, endpoint, initial) = {
            let mut core = self.core.lock().await;
            if let Some(operation) = core
                .store
                .operation_by_request(request_id)
                .map_err(SupervisorError::from)
                .map_err(Status::from)?
            {
                let intent = Intent::decode(&operation)?;
                if intent.binding != requested
                    || intent.expected_revision != request.expected_revision
                    || intent.target.payload.sha256 != request.target_sha256
                    || intent.rollback != rollback
                    || asset
                        .as_ref()
                        .is_some_and(|asset| asset.provenance != intent.target)
                {
                    return Err(Status::aborted("runtime request UUID collision"));
                }
                // An existing request is observation only, even with a source.
                drop(core);
                return self
                    .runtime_query(
                        v1::LinuxCwRuntimeQuery {
                            environment_id: id.to_string(),
                            request_id: request_id.to_string(),
                        },
                        false,
                    )
                    .await;
            }
            let (endpoint, runner) = admit_endpoint(&mut core, id, None).await?;
            if endpoint.binding != requested {
                return Err(Status::failed_precondition("runtime VM binding changed"));
            }
            let initial = endpoint.call(RuntimeAction::Info, None).await?;
            approve_reply(&core, &initial)?;
            reconcile_interrupted(&core.store, &initial)?;
            if initial.selection.revision != request.expected_revision {
                return Err(Status::aborted("runtime selection revision changed"));
            }
            if initial.selection.catalog.active_sha256 == request.target_sha256 {
                return Err(Status::failed_precondition(
                    "runtime target is already selected",
                ));
            }
            if initial.selection.operations.len() == LIVE_RUNTIME_MAX_OPERATIONS
                || (initial
                    .selection
                    .catalog
                    .runtime(&request.target_sha256)
                    .is_none()
                    && initial.selection.catalog.runtimes.len()
                        == codewire_vmm_guest_probe::cw_runtime::CW_RUNTIME_MAX_VERSIONS)
            {
                return Err(Status::resource_exhausted(
                    "runtime retention capacity reached",
                ));
            }
            let target = if let Some(asset) = &asset {
                asset.provenance.clone()
            } else {
                if initial.selection.previous_sha256.as_deref() != Some(&request.target_sha256) {
                    return Err(Status::failed_precondition(
                        "rollback target is not the observed previous runtime",
                    ));
                }
                initial
                    .selection
                    .catalog
                    .runtime(&request.target_sha256)
                    .cloned()
                    .ok_or_else(|| Status::failed_precondition("rollback target is not retained"))?
            };
            let intent = Intent {
                binding: requested,
                runner,
                vmm: endpoint.vmm.identity().clone(),
                vsock: endpoint.socket_identity.clone(),
                expected_revision: request.expected_revision,
                target,
                rollback,
            };
            let payload = serde_json::to_value(&intent)
                .map_err(|_| Status::internal("runtime intent encoding failed"))?;
            let kind = if rollback {
                OperationKind::RollbackCwRuntime
            } else {
                OperationKind::UpdateCwRuntime
            };
            let operation = core
                .store
                .begin_operation(request_id, Some(id), kind, &payload)
                .map_err(SupervisorError::from)
                .map_err(Status::from)?;
            core.runtime_operations.insert(operation.operation_id);
            (operation, endpoint, initial)
        };
        let service = self.clone();
        let worker_operation = operation.clone();
        tokio::spawn(async move {
            service
                .runtime_execute(worker_operation, endpoint, asset)
                .await;
        });
        status(&initial, Some(&operation))
    }

    async fn runtime_execute(
        &self,
        operation: OperationRecord,
        endpoint: Endpoint,
        asset: Option<AdmittedCwRuntimeAsset>,
    ) {
        let intent = match Intent::decode(&operation) {
            Ok(intent) => intent,
            Err(_) => return,
        };
        let publish = if let Some(asset) = &asset {
            endpoint
                .call(
                    RuntimeAction::Publish {
                        operation_id: operation.operation_id,
                        pack_size: asset.pack().len() as u64,
                        pack_sha256: asset.pack_sha256.clone(),
                        provenance: Box::new(asset.provenance.clone()),
                    },
                    Some(asset.pack()),
                )
                .await
                .map(|_| ())
        } else {
            Ok(())
        };
        // The entire transfer above holds no global core lock. CAS and exact
        // owner reread below serialize with lifecycle admission and cancellation.
        let mut core = self.core.lock().await;
        let current = match core
            .store
            .cw_runtime_operation_by_id(operation.operation_id)
        {
            Ok(Some(current)) => current,
            _ => {
                core.runtime_operations.remove(&operation.operation_id);
                return;
            }
        };
        if !current.phase.terminal()
            && admit_endpoint(&mut core, intent.binding.environment_id, Some(&intent))
                .await
                .is_ok()
        {
            let result = if publish.is_ok() {
                endpoint
                    .call(intent.request(operation.operation_id, false).action, None)
                    .await
            } else {
                endpoint
                    .call(intent.request(operation.operation_id, true).action, None)
                    .await
            };
            if let Ok(reply) = result {
                let _ = finish(&core, &current, &reply);
            }
            // A failed/lost commit response retains intent and its exact ID.
            // Recovery observes/cancels it; it never issues a second Select.
        }
        if !current.phase.terminal()
            && endpoint.runner.is_exited().ok() == Some(true)
            && endpoint.vmm.is_exited().ok() == Some(true)
        {
            let latest = core
                .store
                .cw_runtime_operation_by_id(operation.operation_id)
                .ok()
                .flatten();
            if let Some(latest) = latest.filter(|operation| !operation.phase.terminal()) {
                let _ = core.store.advance_operation(
                    latest.operation_id,
                    latest.checkpoint,
                    OperationPhase::Interrupted,
                    None,
                    Some("runtime_vm_birth_lost"),
                );
            }
        }
        core.runtime_operations.remove(&operation.operation_id);
        if let Ok(Some(latest)) = core
            .store
            .cw_runtime_operation_by_id(operation.operation_id)
            && !latest.phase.terminal()
        {
            // One bounded recovery attempt observes or durably cancels the
            // original intent; it never retries Publish or Select. A remaining
            // unknown effect is retained for explicit observe/cancel.
            let _ = recover(&mut core, &latest).await;
        }
    }

    async fn runtime_query(
        &self,
        request: v1::LinuxCwRuntimeQuery,
        cancel: bool,
    ) -> Result<v1::LinuxCwRuntimeStatus, Status> {
        let id = parse_operation_id(&request.environment_id)?;
        if cancel && request.request_id.is_empty() {
            return Err(Status::invalid_argument(
                "cancel requires the original request UUID",
            ));
        }
        let mut core = self.core.lock().await;
        let operation = if request.request_id.is_empty() {
            None
        } else {
            Some(
                core.store
                    .operation_by_request(parse_operation_id(&request.request_id)?)
                    .map_err(SupervisorError::from)
                    .map_err(Status::from)?
                    .filter(|operation| {
                        operation.environment_id == Some(id) && operation.kind.cw_runtime()
                    })
                    .ok_or_else(|| {
                        Status::not_found("runtime request UUID was not found for this environment")
                    })?,
            )
        };
        let intent = operation.as_ref().map(Intent::decode).transpose()?;
        // After a reboot, observe the retained old receipt through the new
        // trusted publisher only. No old request may mutate a new VM birth.
        let historical = if let (Some(operation), Some(intent)) = (&operation, &intent) {
            let environment = core
                .state
                .environments
                .values()
                .find(|environment| environment.id == id)
                .ok_or_else(|| Status::not_found("native environment UUID was not found"))?;
            let bootstrap = environment.cw_runtime.as_ref().ok_or_else(|| {
                Status::failed_precondition("VM has no immutable cw bootstrap catalog")
            })?;
            let current = RuntimeBinding {
                environment_id: id,
                generation: environment.generation,
                bootstrap_catalog_sha256: bootstrap.active_catalog_generation.clone(),
            };
            query_uses_retained_history(operation, intent, &current, cancel)?
        } else {
            false
        };
        let expected = intent.as_ref().filter(|_| !historical);
        let (endpoint, _) = admit_endpoint(&mut core, id, expected).await?;
        let action = match (&operation, &intent) {
            (Some(operation), Some(intent)) if cancel && !operation.phase.terminal() => {
                intent.request(operation.operation_id, true).action
            }
            (Some(operation), _) => RuntimeAction::Observe {
                operation_id: operation.operation_id,
            },
            _ => RuntimeAction::Info,
        };
        let reply = endpoint.call(action, None).await?;
        approve_reply(&core, &reply)?;
        let operation = if let Some(operation) = operation {
            if !operation.phase.terminal() && reply.observed.is_some() {
                Some(finish(&core, &operation, &reply)?)
            } else {
                Some(operation)
            }
        } else {
            None
        };
        let interrupted = reconcile_interrupted(&core.store, &reply)?;
        let operation = if let Some(operation) = operation {
            core.store
                .cw_runtime_operation_by_id(operation.operation_id)
                .map_err(SupervisorError::from)
                .map_err(Status::from)?
        } else {
            None
        };
        let mut result = status(&reply, operation.as_ref())?;
        result.interrupted_request_ids = interrupted;
        Ok(result)
    }
}

#[tonic::async_trait]
impl LinuxCwRuntimeService for SupervisorRpc {
    async fn resolve(
        &self,
        request: Request<v1::LinuxCwRuntimeSelector>,
    ) -> Result<Response<v1::LinuxCwRuntimeIdentity>, Status> {
        let core = self.core.lock().await;
        let id = resolve_saved_identity(&core.state, &request.into_inner().selector)?;
        Ok(Response::new(v1::LinuxCwRuntimeIdentity {
            environment_id: id.to_string(),
        }))
    }
    async fn info(
        &self,
        request: Request<v1::LinuxCwRuntimeQuery>,
    ) -> Result<Response<v1::LinuxCwRuntimeStatus>, Status> {
        let request = request.into_inner();
        if !request.request_id.is_empty() {
            return Err(Status::invalid_argument(
                "info does not select an operation",
            ));
        }
        self.runtime_query(request, false).await.map(Response::new)
    }
    async fn update(
        &self,
        request: Request<v1::LinuxCwRuntimeMutation>,
    ) -> Result<Response<v1::LinuxCwRuntimeStatus>, Status> {
        self.runtime_mutate(request.into_inner(), false)
            .await
            .map(Response::new)
    }
    async fn rollback(
        &self,
        request: Request<v1::LinuxCwRuntimeMutation>,
    ) -> Result<Response<v1::LinuxCwRuntimeStatus>, Status> {
        self.runtime_mutate(request.into_inner(), true)
            .await
            .map(Response::new)
    }
    async fn observe(
        &self,
        request: Request<v1::LinuxCwRuntimeQuery>,
    ) -> Result<Response<v1::LinuxCwRuntimeStatus>, Status> {
        let request = request.into_inner();
        if request.request_id.is_empty() {
            return Err(Status::invalid_argument(
                "observe requires the original request UUID",
            ));
        }
        self.runtime_query(request, false).await.map(Response::new)
    }
    async fn cancel(
        &self,
        request: Request<v1::LinuxCwRuntimeQuery>,
    ) -> Result<Response<v1::LinuxCwRuntimeStatus>, Status> {
        self.runtime_query(request.into_inner(), true)
            .await
            .map(Response::new)
    }
}

fn resolve_saved_identity(state: &SupervisorState, selector: &str) -> Result<Uuid, Status> {
    if selector.is_empty() || selector.len() > 63 {
        return Err(Status::invalid_argument(
            "invalid native environment selector",
        ));
    }
    if let Ok(id) = Uuid::parse_str(selector) {
        if id.is_nil() {
            return Err(Status::invalid_argument("invalid native environment UUID"));
        }
        // UUID-shaped names never grant authority over an absent/reused UUID.
        state
            .environments
            .values()
            .find(|environment| environment.id == id)
    } else {
        if !valid_environment_name(selector) {
            return Err(Status::invalid_argument(
                "invalid native environment selector",
            ));
        }
        state.environments.get(selector)
    }
    .map(|environment| environment.id)
    .ok_or_else(|| Status::not_found("explicit native environment was not found"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use codewire_vmm_guest_probe::cw_runtime::{
        CwImageDescriptor, CwImagePayload, CwRuntimeCatalog,
    };
    use std::os::unix::fs::PermissionsExt as _;

    /// A short canonical root for sockets within Darwin's 103-byte limit.
    #[cfg(target_os = "linux")]
    const SOCKET_TMP: &str = "/var/tmp";
    #[cfg(target_os = "macos")]
    const SOCKET_TMP: &str = "/private/var/tmp";
    #[cfg(target_os = "linux")]
    const SLEEP: &str = "/usr/bin/sleep";
    #[cfg(target_os = "macos")]
    const SLEEP: &str = "/bin/sleep";

    fn member(byte: char) -> CwRuntimeProvenance {
        let descriptor = CwImageDescriptor {
            sha256: "a".repeat(64),
            size: 10240,
        };
        CwRuntimeProvenance {
            schema_version: 1,
            image_index_sha256: "b".repeat(64),
            image_manifest: descriptor.clone(),
            image_config: descriptor.clone(),
            image_layer: descriptor,
            layer_diff_id: "a".repeat(64),
            payload: CwImagePayload {
                schema_version: 2,
                protocol_version: 1,
                record_version: 1,
                package_version: "0.1.0".into(),
                target: codewire_vmm_guest_probe::cw_runtime::CW_RUNTIME_TARGET.into(),
                source_revision: "c".repeat(40),
                source_tree_sha256: "d".repeat(64),
                rustc: "rustc 1.93.0 (synthetic protocol fixture)".into(),
                sha256: byte.to_string().repeat(64),
                size: 136,
            },
        }
    }
    fn selection() -> (CwRuntimeCatalog, RuntimeSelection) {
        let bootstrap = CwRuntimeCatalog {
            schema_version: 1,
            active_sha256: "a".repeat(64),
            runtimes: vec![member('a')],
        };
        let selection = RuntimeSelection {
            schema_version: LIVE_RUNTIME_PROTOCOL,
            environment_id: Uuid::new_v4(),
            bootstrap_catalog_sha256: "c".repeat(64),
            revision: 1,
            previous_sha256: None,
            catalog: bootstrap.clone(),
            operations: Vec::new(),
        };
        (bootstrap, selection)
    }
    fn committed(selection: &mut RuntimeSelection, target: char) -> SelectionReceipt {
        let receipt = SelectionReceipt {
            operation_id: Uuid::new_v4(),
            generation: 1,
            expected_revision: selection.revision,
            target_sha256: target.to_string().repeat(64),
            outcome: SelectionOutcome::Committed,
            selection_revision: selection.revision + 1,
        };
        if selection.catalog.runtime(&receipt.target_sha256).is_none() {
            selection.catalog.runtimes.push(member(target));
            selection
                .catalog
                .runtimes
                .sort_by(|a, b| a.payload.sha256.cmp(&b.payload.sha256));
        }
        selection.previous_sha256 = Some(selection.catalog.active_sha256.clone());
        selection.catalog.active_sha256 = receipt.target_sha256.clone();
        selection.revision = receipt.selection_revision;
        selection.operations.push(receipt.clone());
        receipt
    }

    #[test]
    fn live_runtime_boot_confirmation_refuses_lost_or_substituted_default_history() {
        let (bootstrap, mut selected) = selection();
        assert!(check_selection_history(&bootstrap, &selected).is_ok());
        committed(&mut selected, 'b');
        assert!(check_selection_history(&bootstrap, &selected).is_ok());
        for mutate in [0, 1, 2, 3] {
            let mut changed = selected.clone();
            match mutate {
                0 => changed.catalog.active_sha256 = bootstrap.active_sha256.clone(),
                1 => changed.previous_sha256 = Some("b".repeat(64)),
                2 => changed.operations.clear(),
                _ => changed.revision += 1,
            }
            assert!(check_selection_history(&bootstrap, &changed).is_err());
        }
        committed(&mut selected, 'a');
        assert!(check_selection_history(&bootstrap, &selected).is_ok());
        selected.operations.reverse();
        assert!(check_selection_history(&bootstrap, &selected).is_err());
    }

    #[test]
    fn live_runtime_cancelled_receipts_preserve_confirmed_default_and_revision() {
        let (bootstrap, mut selected) = selection();
        let update = committed(&mut selected, 'b');
        selected.operations.push(SelectionReceipt {
            operation_id: Uuid::new_v4(),
            generation: 1,
            expected_revision: 2,
            target_sha256: "f".repeat(64),
            outcome: SelectionOutcome::Cancelled,
            selection_revision: 2,
        });
        assert!(check_selection_history(&bootstrap, &selected).is_ok());
        assert_eq!(selected.receipt(update.operation_id), Some(&update));
        selected.operations.last_mut().unwrap().selection_revision = 1;
        assert!(check_selection_history(&bootstrap, &selected).is_err());
    }

    #[test]
    fn live_runtime_retained_observe_survives_reconciliation_and_later_boots() {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let private = PrivateRoot::open(root.path()).unwrap();
        let (store, _) = SupervisorStore::open(&private).unwrap();
        let socket_path = root.path().join("peer.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        crate::host::path::set_socket_private(&socket_path).unwrap();
        let socket = SocketIdentity::capture(&socket_path).unwrap();
        let process = ProcessIdentity::capture(std::process::id()).unwrap();
        let (_, mut selected) = selection();
        let original = RuntimeBinding {
            environment_id: selected.environment_id,
            generation: 1,
            bootstrap_catalog_sha256: selected.bootstrap_catalog_sha256.clone(),
        };
        let intent = Intent {
            binding: original.clone(),
            runner: RunnerRecord {
                process: process.clone(),
                socket: socket.clone(),
                artifact_generation: "d".repeat(64),
                cw_runtime_catalog_generation: Some(original.bootstrap_catalog_sha256.clone()),
                error_code: None,
            },
            vmm: process,
            vsock: socket,
            expected_revision: 1,
            target: member('b'),
            rollback: false,
        };
        let operation = store
            .begin_operation(
                Uuid::new_v4(),
                Some(original.environment_id),
                OperationKind::UpdateCwRuntime,
                &serde_json::to_value(&intent).unwrap(),
            )
            .unwrap();
        let current = RuntimeBinding {
            generation: 2,
            ..original.clone()
        };
        // Pending mutation and cancellation retain their original birth.
        assert!(query_uses_retained_history(&operation, &intent, &current, false).is_err());
        assert!(query_uses_retained_history(&operation, &intent, &current, true).is_err());
        assert!(!query_uses_retained_history(&operation, &intent, &original, true).unwrap());
        let interrupted = store
            .advance_operation(
                operation.operation_id,
                operation.checkpoint,
                OperationPhase::Interrupted,
                None,
                Some("host_reboot"),
            )
            .unwrap();
        let mut reply = RuntimeReply {
            protocol_version: 1,
            binding: current.clone(),
            selection: selected.clone(),
            observed: None,
        };
        assert!(query_uses_retained_history(&interrupted, &intent, &current, false).unwrap());
        assert!(query_uses_retained_history(&interrupted, &intent, &current, true).is_err());
        assert_eq!(
            reconcile_interrupted(&store, &reply).unwrap(),
            vec![operation.request_id.to_string()]
        );
        assert_eq!(
            store
                .cw_runtime_operation_by_id(operation.operation_id)
                .unwrap()
                .unwrap()
                .phase,
            OperationPhase::Interrupted
        );
        let mut receipt = committed(&mut selected, 'b');
        receipt.operation_id = operation.operation_id;
        selected.operations[0] = receipt.clone();
        reply.selection = selected;
        reply.observed = Some(receipt);
        assert!(reconcile_interrupted(&store, &reply).unwrap().is_empty());
        let completed = store
            .cw_runtime_operation_by_id(operation.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(completed.phase, OperationPhase::Completed);
        assert_eq!(
            decode_result(&completed, completed.result.as_ref().unwrap())
                .unwrap()
                .binding,
            original
        );
        // The former `phase != Interrupted` filter restored the original
        // binding here, rejecting this *second* read after successful recovery.
        let old_expected = (completed.phase != OperationPhase::Interrupted).then_some(&intent);
        assert!(old_expected.is_some_and(|expected| expected.binding != current));
        assert!(query_uses_retained_history(&completed, &intent, &current, false).unwrap());
        assert!(query_uses_retained_history(&completed, &intent, &current, true).is_err());
        assert!(!query_uses_retained_history(&completed, &intent, &original, false).unwrap());
        drop(store);
        let (reopened, _) = SupervisorStore::open(&private).unwrap();
        let durable = reopened
            .cw_runtime_operation_by_id(operation.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(durable, completed);
        let later = RuntimeBinding {
            generation: 3,
            ..current.clone()
        };
        assert!(query_uses_retained_history(&durable, &intent, &later, false).unwrap());
        for foreign in [
            RuntimeBinding {
                generation: 0,
                ..current.clone()
            },
            RuntimeBinding {
                environment_id: Uuid::new_v4(),
                ..current.clone()
            },
            RuntimeBinding {
                bootstrap_catalog_sha256: "f".repeat(64),
                ..current.clone()
            },
        ] {
            assert!(query_uses_retained_history(&durable, &intent, &foreign, false).is_err());
        }
        let mut future = intent.clone();
        future.binding.generation = 3;
        assert!(query_uses_retained_history(&durable, &future, &current, false).is_err());
        assert_eq!(
            reopened
                .cw_runtime_operation_by_id(operation.operation_id)
                .unwrap()
                .unwrap(),
            durable
        );
    }

    #[test]
    fn live_runtime_durable_result_requires_the_exact_original_receipt() {
        let root = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let private = PrivateRoot::open(root.path()).unwrap();
        let (store, _) = SupervisorStore::open(&private).unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(root.path().join("peer.sock")).unwrap();
        crate::host::path::set_socket_private(&root.path().join("peer.sock")).unwrap();
        let socket = SocketIdentity::capture(&root.path().join("peer.sock")).unwrap();
        let process = ProcessIdentity::capture(std::process::id()).unwrap();
        let (_, mut selected) = selection();
        let mut receipt = committed(&mut selected, 'b');
        let binding = RuntimeBinding {
            environment_id: selected.environment_id,
            generation: 1,
            bootstrap_catalog_sha256: selected.bootstrap_catalog_sha256.clone(),
        };
        let intent = Intent {
            binding: binding.clone(),
            runner: RunnerRecord {
                process: process.clone(),
                socket: socket.clone(),
                artifact_generation: "d".repeat(64),
                cw_runtime_catalog_generation: Some(binding.bootstrap_catalog_sha256.clone()),
                error_code: None,
            },
            vmm: process,
            vsock: socket,
            expected_revision: 1,
            target: member('b'),
            rollback: false,
        };
        let operation = store
            .begin_operation(
                Uuid::new_v4(),
                Some(binding.environment_id),
                OperationKind::UpdateCwRuntime,
                &serde_json::to_value(&intent).unwrap(),
            )
            .unwrap();
        receipt.operation_id = operation.operation_id;
        selected.operations[0] = receipt.clone();
        let reply = RuntimeReply {
            protocol_version: 1,
            binding,
            selection: selected,
            observed: Some(receipt),
        };
        let encoded = serde_json::to_value(&reply).unwrap();
        assert_eq!(decode_result(&operation, &encoded).unwrap(), reply);
        for mutate in [0, 1, 2, 3, 4] {
            let mut changed = reply.clone();
            match mutate {
                0 => changed.binding.generation += 1,
                1 => changed.observed.as_mut().unwrap().generation += 1,
                2 => changed.observed.as_mut().unwrap().operation_id = Uuid::new_v4(),
                3 => changed.observed = None,
                _ => changed.observed.as_mut().unwrap().target_sha256 = "a".repeat(64),
            }
            assert!(decode_result(&operation, &serde_json::to_value(changed).unwrap()).is_err());
        }
        let mut wrong = operation.clone();
        wrong.payload["root_exec"] = serde_json::json!("/bin/sh");
        assert!(Intent::decode(&wrong).is_err());
        wrong = operation;
        wrong.environment_id = Some(Uuid::new_v4());
        assert!(Intent::decode(&wrong).is_err());
        drop(listener);
    }

    #[tokio::test]
    async fn live_runtime_host_transport_is_birth_bound_and_rejects_ambiguous_framing() {
        let root = tempfile::Builder::new()
            .prefix("cw-rt-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(SOCKET_TMP)
            .unwrap();
        let socket = root.path().join("vmm.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        crate::host::path::set_socket_private(&socket).unwrap();
        let expected = ProcessIdentity::capture(std::process::id()).unwrap();
        let (_, selected) = selection();
        let binding = RuntimeBinding {
            environment_id: selected.environment_id,
            generation: 1,
            bootstrap_catalog_sha256: selected.bootstrap_catalog_sha256.clone(),
        };
        let reply = RuntimeReply {
            protocol_version: 1,
            binding: binding.clone(),
            selection: selected,
            observed: None,
        };
        let endpoint = Endpoint {
            binding,
            socket: socket.clone(),
            socket_identity: SocketIdentity::capture(&socket).unwrap(),
            runner: recorded(&expected).unwrap(),
            vmm: recorded(&expected).unwrap(),
            runner_pin: None,
        };
        let fixture_reply = reply.clone();
        let worker = tokio::spawn(async move {
            for shape in 0..5 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut handshake = [0_u8; 13];
                stream.read_exact(&mut handshake).await.unwrap();
                assert_eq!(&handshake, b"CONNECT 7778\n");
                stream.write_all(b"OK 7778\n").await.unwrap();
                let size = stream.read_u32().await.unwrap() as usize;
                assert!(size <= LIVE_RUNTIME_MAX_FRAME);
                let mut bytes = vec![0; size];
                stream.read_exact(&mut bytes).await.unwrap();
                let request: RuntimeRequest = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(request.action, RuntimeAction::Info);
                let mut extra = [0];
                assert_eq!(stream.read(&mut extra).await.unwrap(), 0);
                let mut response = RuntimeResponse {
                    reply: Some(fixture_reply.clone()),
                    refusal: None,
                };
                if shape == 1 {
                    response.refusal = Some(RuntimeRefusal::Invalid);
                }
                if shape == 2 {
                    response.reply.as_mut().unwrap().binding.generation += 1;
                }
                let mut frame = encode_frame(&response).unwrap();
                if shape == 3 {
                    frame.push(b'x');
                }
                if shape == 4 {
                    frame.truncate(frame.len() - 2);
                }
                stream.write_all(&frame).await.unwrap();
                stream.shutdown().await.unwrap();
            }
        });
        assert_eq!(
            endpoint.call(RuntimeAction::Info, None).await.unwrap(),
            reply
        );
        for _ in 0..4 {
            assert!(endpoint.call(RuntimeAction::Info, None).await.is_err());
        }
        worker.await.unwrap();
        fs::remove_file(&socket).unwrap();
        let _replacement = tokio::net::UnixListener::bind(&socket).unwrap();
        crate::host::path::set_socket_private(&socket).unwrap();
        assert!(endpoint.call(RuntimeAction::Info, None).await.is_err());
    }

    #[tokio::test]
    async fn live_runtime_resolution_and_refusal_never_dispatch_pending_lifecycle() {
        struct Sentinel(Child);
        impl Drop for Sentinel {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let sentinel = Sentinel(
            crate::test_child(Command::new(SLEEP).arg("60"))
                .spawn()
                .unwrap(),
        );
        // spawn may return before exec; admit the sleeping sentinel only after
        // its actual image is visible, while the unreaped Child owns its birth.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let sentinel_identity = loop {
            let identity = ProcessIdentity::capture(sentinel.0.id()).unwrap();
            if identity.executable == Path::new(SLEEP) {
                break identity;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "sentinel did not exec"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let live = recorded(&sentinel_identity).unwrap();
        for kind in [
            OperationKind::Start,
            OperationKind::Restart,
            OperationKind::Create,
        ] {
            let mut environment = super::super::tests::project_environment();
            environment.state = StoredEnvironmentState::Running;
            environment.cw_runtime = Some(CwRuntimeBinding {
                schema_version: 1,
                active_catalog_generation: "c".repeat(64),
                staging_catalog_generation: None,
                rollback_catalog_generation: None,
            });
            let id = environment.id;
            let name = environment.name.clone();
            let (_parent, mut core) =
                super::super::tests::test_supervisor_core(environment.clone());
            let mut decoy = super::super::tests::project_environment();
            decoy.name = id.to_string();
            let decoy_id = decoy.id;
            core.state.environments.insert(decoy.name.clone(), decoy);
            let mut neighbor = super::super::tests::project_environment();
            neighbor.name = "neighbor".into();
            let neighbor_id = neighbor.id;
            core.state
                .environments
                .insert(neighbor.name.clone(), neighbor);
            core.store.replace_state(&core.state).unwrap();
            let pending = core
                .store
                .begin_operation(
                    Uuid::new_v4(),
                    Some(id),
                    kind,
                    &serde_json::json!({"name":name}),
                )
                .unwrap();
            let other = core
                .store
                .begin_operation(
                    Uuid::new_v4(),
                    Some(neighbor_id),
                    OperationKind::Start,
                    &serde_json::json!({"name":"neighbor"}),
                )
                .unwrap();
            let before_state = SupervisorStore::inspect(&core.root).unwrap().1;
            let before_engine: Vec<_> = fs::read_dir(core.config.engine_root())
                .unwrap()
                .map(|item| item.unwrap().file_name())
                .collect();
            let service = super::super::tests::test_supervisor_service(core);
            for selector in [&name, &id.to_string()] {
                let reply = service
                    .resolve(Request::new(v1::LinuxCwRuntimeSelector {
                        selector: selector.clone(),
                    }))
                    .await
                    .unwrap()
                    .into_inner();
                assert_eq!(reply.environment_id, id.to_string());
            }
            let absent = Uuid::new_v4();
            assert!(
                service
                    .resolve(Request::new(v1::LinuxCwRuntimeSelector {
                        selector: absent.to_string()
                    }))
                    .await
                    .is_err()
            );
            let query = v1::LinuxCwRuntimeQuery {
                environment_id: id.to_string(),
                request_id: String::new(),
            };
            assert_eq!(
                service.info(Request::new(query)).await.unwrap_err().code(),
                tonic::Code::Aborted
            );
            let request = v1::LinuxCwRuntimeMutation {
                environment_id: id.to_string(),
                generation: 1,
                bootstrap_catalog_sha256: "c".repeat(64),
                request_id: Uuid::new_v4().to_string(),
                expected_revision: 1,
                target_sha256: "b".repeat(64),
                image_index_sha256: String::new(),
                source_lock: String::new(),
            };
            assert_eq!(
                service
                    .rollback(Request::new(request))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Aborted
            );
            let mut core = service.core.lock().await;
            assert_eq!(
                SupervisorStore::inspect(&core.root).unwrap().1,
                before_state
            );
            assert_eq!(core.state, before_state);
            assert_eq!(
                core.store.operation_by_request(pending.request_id).unwrap(),
                Some(pending)
            );
            assert_eq!(
                core.store.operation_by_request(other.request_id).unwrap(),
                Some(other)
            );
            assert!(core.children.is_empty());
            assert!(core.live_runners.is_empty());
            assert!(core.runtime_operations.is_empty());
            assert!(!service.worker_running.load(Ordering::Acquire));
            assert_eq!(
                fs::read_dir(core.config.engine_root())
                    .unwrap()
                    .map(|item| item.unwrap().file_name())
                    .collect::<Vec<_>>(),
                before_engine
            );
            assert!(!live.is_exited().unwrap());
            assert_eq!(
                ProcessIdentity::capture(sentinel_identity.pid).unwrap(),
                sentinel_identity
            );
            // Removing the real UUID must not select the UUID-shaped decoy.
            core.state.environments.remove(&name);
            assert_eq!(core.state.environments[&id.to_string()].id, decoy_id);
            assert_eq!(
                resolve_saved_identity(&core.state, &id.to_string())
                    .unwrap_err()
                    .code(),
                tonic::Code::NotFound
            );
            for invalid in [
                String::new(),
                "a".repeat(64),
                "../dev".into(),
                "dev\0neighbor".into(),
                Uuid::nil().to_string(),
            ] {
                assert!(resolve_saved_identity(&core.state, &invalid).is_err());
            }
        }
    }

    #[derive(Clone)]
    struct ObservedRunnerFixture {
        protocol: Arc<std::sync::atomic::AtomicU32>,
        info: Arc<std::sync::Mutex<v1::RunnerInfo>>,
        reads: Arc<std::sync::atomic::AtomicUsize>,
        access_reads: Arc<std::sync::atomic::AtomicUsize>,
        forbidden: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl ObservedRunnerFixture {
        fn forbidden<T>(&self) -> Result<Response<T>, Status> {
            self.forbidden.fetch_add(1, Ordering::SeqCst);
            Err(Status::unimplemented(
                "lifecycle or general daemon access must not be called",
            ))
        }
    }
    #[tonic::async_trait]
    impl v1::environment_runner_service_server::EnvironmentRunnerService for ObservedRunnerFixture {
        async fn get_runner_protocol_info(
            &self,
            _: Request<v1::GetRunnerProtocolInfoRequest>,
        ) -> Result<Response<v1::RunnerProtocolInfo>, Status> {
            Ok(Response::new(v1::RunnerProtocolInfo {
                protocol_version: self.protocol.load(Ordering::SeqCst),
            }))
        }
        async fn get_runner_info(
            &self,
            _: Request<v1::GetRunnerInfoRequest>,
        ) -> Result<Response<v1::RunnerInfo>, Status> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(Response::new(self.info.lock().unwrap().clone()))
        }
        async fn get_generation_daemon_access(
            &self,
            request: Request<v1::GetGenerationDaemonAccessRequest>,
        ) -> Result<Response<v1::DaemonAccess>, Status> {
            let request = request.into_inner();
            let info = self.info.lock().unwrap();
            assert_eq!(request.environment_id, info.environment_id);
            assert_eq!(request.generation, info.generation);
            self.access_reads.fetch_add(1, Ordering::SeqCst);
            Ok(Response::new(v1::DaemonAccess {
                hybrid_socket: "/synthetic/retained/vsock.sock".into(),
                guest_port: DAEMON_VSOCK_PORT,
                generation_capability: "f".repeat(64),
            }))
        }
        async fn adopt_runner(
            &self,
            _: Request<v1::AdoptRunnerRequest>,
        ) -> Result<Response<v1::RunnerInfo>, Status> {
            self.forbidden()
        }
        type WatchRunnerStream =
            Pin<Box<dyn Stream<Item = Result<v1::RunnerEvent, Status>> + Send>>;
        async fn watch_runner(
            &self,
            _: Request<v1::WatchRunnerRequest>,
        ) -> Result<Response<Self::WatchRunnerStream>, Status> {
            self.forbidden()
        }
        async fn start_vm(
            &self,
            _: Request<v1::StartVmRequest>,
        ) -> Result<Response<v1::RunnerInfo>, Status> {
            self.forbidden()
        }
        async fn stop_vm(
            &self,
            _: Request<v1::StopVmRequest>,
        ) -> Result<Response<v1::RunnerInfo>, Status> {
            self.forbidden()
        }
        async fn grow_state_disk(
            &self,
            _: Request<v1::GrowStateDiskRequest>,
        ) -> Result<Response<v1::GrowStateDiskResponse>, Status> {
            self.forbidden()
        }
        async fn set_host_ports(
            &self,
            _: Request<v1::SetHostPortsRequest>,
        ) -> Result<Response<v1::SetHostPortsResponse>, Status> {
            self.forbidden()
        }
        async fn prepare_retire_runner(
            &self,
            _: Request<v1::PrepareRetireRunnerRequest>,
        ) -> Result<Response<v1::PrepareRetireRunnerResponse>, Status> {
            self.forbidden()
        }
        async fn shutdown_runner(
            &self,
            _: Request<v1::ShutdownRunnerRequest>,
        ) -> Result<Response<v1::ShutdownRunnerResponse>, Status> {
            self.forbidden()
        }
        async fn get_daemon_access(
            &self,
            _: Request<v1::GetDaemonAccessRequest>,
        ) -> Result<Response<v1::DaemonAccess>, Status> {
            self.forbidden()
        }
    }

    #[tokio::test]
    async fn live_runtime_retained_runner_observes_exact_birth_and_never_calls_lifecycle() {
        let root = tempfile::Builder::new()
            .prefix("cw-rtr-")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in(SOCKET_TMP)
            .unwrap();
        let socket = root.path().join("runner.sock");
        let (incoming, identity) = crate::uds::bind_owner_only(&socket).unwrap();
        let binding = RuntimeBinding {
            environment_id: Uuid::new_v4(),
            generation: 7,
            bootstrap_catalog_sha256: "c".repeat(64),
        };
        let info = v1::RunnerInfo {
            environment_id: binding.environment_id.to_string(),
            generation: binding.generation,
            state: v1::EnvironmentState::Running as i32,
            artifact_generation: "d".repeat(64),
            error_code: String::new(),
            cw_runtime_catalog_generation: binding.bootstrap_catalog_sha256.clone(),
        };
        let service = ObservedRunnerFixture {
            protocol: Arc::new(std::sync::atomic::AtomicU32::new(6)),
            info: Arc::new(std::sync::Mutex::new(info.clone())),
            reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            access_reads: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            forbidden: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let handler = service.clone();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    v1::environment_runner_service_server::EnvironmentRunnerServiceServer::new(
                        handler,
                    ),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let runner = RunnerRecord {
            process: ProcessIdentity::capture(std::process::id()).unwrap(),
            socket: identity,
            artifact_generation: info.artifact_generation.clone(),
            cw_runtime_catalog_generation: Some(binding.bootstrap_catalog_sha256.clone()),
            error_code: None,
        };
        let (access, pin) = observe_retained_runner(socket.clone(), &binding, &runner)
            .await
            .unwrap();
        assert_ne!(
            unsafe { libc::fcntl(pin.peer.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        pin.require_live_peer().unwrap();
        assert_eq!(access.hybrid_socket, "/synthetic/retained/vsock.sock");
        assert_eq!(access.guest_port, DAEMON_VSOCK_PORT);
        assert_eq!(service.reads.load(Ordering::SeqCst), 2);
        assert_eq!(service.access_reads.load(Ordering::SeqCst), 1);
        for protocol in [0, 5, 7] {
            service.protocol.store(protocol, Ordering::SeqCst);
            let reads = service.reads.load(Ordering::SeqCst);
            assert!(
                observe_retained_runner(socket.clone(), &binding, &runner)
                    .await
                    .is_err()
            );
            assert_eq!(service.reads.load(Ordering::SeqCst), reads);
        }
        service.protocol.store(6, Ordering::SeqCst);
        for mismatch in 0..6 {
            let mut changed = info.clone();
            match mismatch {
                0 => changed.environment_id = Uuid::new_v4().to_string(),
                1 => changed.generation += 1,
                2 => changed.state = v1::EnvironmentState::Stopped as i32,
                3 => changed.artifact_generation = "e".repeat(64),
                4 => changed.cw_runtime_catalog_generation = "f".repeat(64),
                _ => changed.error_code = "invalid_running".into(),
            }
            *service.info.lock().unwrap() = changed;
            let accesses = service.access_reads.load(Ordering::SeqCst);
            assert!(
                observe_retained_runner(socket.clone(), &binding, &runner)
                    .await
                    .is_err()
            );
            assert_eq!(service.access_reads.load(Ordering::SeqCst), accesses);
        }
        *service.info.lock().unwrap() = info;
        let mut foreign = runner.clone();
        foreign.process.start_time_ticks += 1;
        let reads = service.reads.load(Ordering::SeqCst);
        assert!(
            observe_retained_runner(socket.clone(), &binding, &foreign)
                .await
                .is_err()
        );
        assert_eq!(service.reads.load(Ordering::SeqCst), reads);
        assert_eq!(service.forbidden.load(Ordering::SeqCst), 0);
        fs::remove_file(&socket).unwrap();
        let _replacement = tokio::net::UnixListener::bind(&socket).unwrap();
        crate::host::path::set_socket_private(&socket).unwrap();
        assert!(pin.connect().await.is_err());
        assert!(
            observe_retained_runner(socket, &binding, &runner)
                .await
                .is_err()
        );
        assert_eq!(service.forbidden.load(Ordering::SeqCst), 0);
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
}
