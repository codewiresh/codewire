//! Original authenticated Pod service and target-owned durable intent. This is
//! not control-plane authorization: every public dispatch must still recheck its
//! current actor/grant and complete captured binding before its Issued journal.
use super::*;
use crate::durable_session::SessionEngine;
use codewire_gateway_proto::daemon::v1::platform_managed_service_server::PlatformManagedService;
use codewire_gateway_proto::{DAEMON_AUTH_TOKEN_HEADER, daemon::v1, platform_managed as wire};
use prost::Message;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
mod book;
use book::Stored;
pub(crate) use book::{CleanupLink, RestartAdvance};

#[derive(Clone)]
pub(crate) struct Service {
    inner: Arc<Inner>,
}
struct Inner {
    config: Config,
    engine: SessionEngine,
    gate: Mutex<()>,
    active: std::sync::Mutex<BTreeSet<String>>,
}
#[derive(Clone)]
pub(crate) struct Owner {
    service: Service,
    request: v1::PlatformManagedMutationRequest,
    fingerprint: String,
}
fn status(_: Error) -> Status {
    Status::failed_precondition("platform managed incarnation or outcome refused")
}
fn invalid(_: &'static str) -> Status {
    Status::invalid_argument("invalid closed platform operation")
}
pub(crate) fn scope_origin(
    scope: &v1::PlatformManagedScope,
    driver: &str,
    agent: Agent,
    provider: ProviderIdentity,
    parent_generation: Option<u64>,
) -> Result<Origin, Error> {
    let origin = Origin {
        version: 1,
        environment_id: scope.environment_id.clone(),
        org_id: scope.org_id.clone(),
        pod_uid: scope.pod_uid.clone(),
        binding_generation: scope.binding_generation,
        projection_selection_sha256: scope
            .projection_selection_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Error::Refused)?,
        support_image_sha256: scope
            .support_image_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Error::Refused)?,
        support_image_size: scope.support_image_size,
        driver_id: driver.into(),
        agent,
        provider,
        parent_generation,
    };
    origin.validate(&format!("session-{driver}"))?;
    Ok(origin)
}
impl Origin {
    pub(crate) fn same_scope(&self, scope: &v1::PlatformManagedScope) -> bool {
        self.environment_id == scope.environment_id
            && self.org_id == scope.org_id
            && self.pod_uid == scope.pod_uid
            && self.binding_generation == scope.binding_generation
            && self.projection_selection_sha256.as_slice() == scope.projection_selection_sha256
            && self.support_image_sha256.as_slice() == scope.support_image_sha256
            && self.support_image_size == scope.support_image_size
    }
}
impl Service {
    pub(crate) fn available(config: &Config) -> bool {
        config.host.is_none()
            && config.process_execution == ProcessExecution::Native
            && config.home_root == Path::new(HOME)
            && config.credential_bridge.as_ref().is_some_and(|b| {
                b.transport == CredentialBridgeTransport::Hosted
                    && b.ingress_uid == 1000
                    && b.ingress_gid == 1000
            })
            && config.launch_projection.is_some()
            && unsafe { libc::geteuid() } == 1000
            && unsafe { libc::getegid() } == 1000
    }
    pub(crate) fn new(config: Config, engine: SessionEngine) -> Option<Self> {
        Self::available(&config).then(|| Self {
            inner: Arc::new(Inner {
                config,
                engine,
                gate: Mutex::new(()),
                active: std::sync::Mutex::new(BTreeSet::new()),
            }),
        })
    }
    fn authorize<T>(&self, r: &Request<T>) -> Result<(), Status> {
        let Some(actual) = r
            .metadata()
            .get(DAEMON_AUTH_TOKEN_HEADER)
            .and_then(|s| s.to_str().ok())
        else {
            return Err(Status::unauthenticated("missing original daemon authority"));
        };
        if !bool::from(
            actual
                .as_bytes()
                .ct_eq(self.inner.config.auth_token.expose_secret().as_bytes()),
        ) {
            return Err(Status::unauthenticated("invalid original daemon authority"));
        }
        if !Self::available(&self.inner.config) {
            return Err(status(Error::Refused));
        }
        Ok(())
    }
    fn check_info(&self, r: &v1::PlatformManagedInfoRequest) -> Result<(), Error> {
        wire::validate_info(r).map_err(|_| Error::Refused)?;
        let bridge = self
            .inner
            .config
            .credential_bridge
            .as_ref()
            .ok_or(Error::Refused)?;
        let projection = self
            .inner
            .config
            .launch_projection
            .as_ref()
            .ok_or(Error::Refused)?;
        if bridge.environment_id.to_string() != r.environment_id
            || bridge.environment_generation != r.binding_generation
            || projection.selection_sha256.as_slice() != r.projection_selection_sha256
        {
            return Err(Error::Refused);
        }
        Ok(())
    }
    fn check_scope(&self, scope: &v1::PlatformManagedScope) -> Result<(), Error> {
        wire::validate_scope(scope).map_err(|_| Error::Refused)?;
        self.check_info(&v1::PlatformManagedInfoRequest {
            environment_id: scope.environment_id.clone(),
            binding_generation: scope.binding_generation,
            projection_selection_sha256: scope.projection_selection_sha256.clone(),
        })?;
        let (hash, size) = ImagePin::identity()?;
        if hash.as_slice() != scope.support_image_sha256 || size != scope.support_image_size {
            return Err(Error::Refused);
        }
        Ok(())
    }
    fn root(&self) -> Result<PathBuf, Error> {
        Ok(Path::new(STATE)
            .join(
                self.inner
                    .config
                    .credential_bridge
                    .as_ref()
                    .ok_or(Error::Refused)?
                    .environment_id
                    .to_string(),
            )
            .join("requests"))
    }
    fn read_row(tree: &files::Tree, id: &str) -> Result<Option<v1::PlatformManagedReceipt>, Error> {
        Stored::read(tree, id)?.map(|saved| saved.row()).transpose()
    }
    fn books(tree: &files::Tree, root: &Path) -> Result<Vec<Stored>, Error> {
        tree.count()?;
        let mut rows = Vec::new();
        for entry in std::fs::read_dir(root).map_err(|_| Error::Refused)? {
            let name = entry.map_err(|_| Error::Refused)?.file_name();
            let name = name.to_str().ok_or(Error::Refused)?;
            if name == "requests.lock" || name == "scope.bin" {
                continue;
            }
            let id = name.strip_suffix(".bin").ok_or(Error::Refused)?;
            rows.push(Stored::read(tree, id)?.ok_or(Error::Refused)?);
        }
        tree.check()?;
        Ok(rows)
    }
    fn cleanup_link(
        &self,
        books: &[Stored],
        request: &v1::PlatformManagedMutationRequest,
    ) -> Result<Option<CleanupLink>, Error> {
        let Some(v1::platform_managed_mutation_request::Operation::Control(c)) = &request.operation
        else {
            return Ok(None);
        };
        let Some(id) = &c.cleanup_of_request_id else {
            return Ok(None);
        };
        let active = self.inner.active.lock().map_err(|_| Error::Unknown)?;
        if active.contains(id)
            || books.iter().any(|b| {
                b.row().is_ok_and(|r| {
                    r.request_id != request.request_id
                        && matches!(r.phase, 1 | 2 | 5)
                        && r.cleanup_of_request_id.as_ref() == Some(id)
                        && active.contains(&r.request_id)
                })
            })
        {
            return Err(Error::Refused);
        }
        let original = books
            .iter()
            .find(|b| b.row().is_ok_and(|r| r.request_id == *id))
            .ok_or(Error::Refused)?;
        Ok(Some(original.cleanup_for(request)?))
    }
    fn enforce_barriers(
        books: &[Stored],
        request: &v1::PlatformManagedMutationRequest,
        link: Option<&CleanupLink>,
    ) -> Result<(), Error> {
        for old in books {
            let row = old.row()?;
            if !matches!(row.phase, 1 | 2 | 5) {
                continue;
            }
            let root_id = row
                .cleanup_of_request_id
                .as_deref()
                .unwrap_or(&row.request_id);
            let original = books
                .iter()
                .find(|b| b.row().is_ok_and(|r| r.request_id == root_id))
                .ok_or(Error::Refused)?;
            if row.cleanup_of_request_id.is_some() {
                original.cleanup_for(&old.stop_request()?)?;
            }
            if books.iter().try_fold(false, |resolved, stop| {
                Ok::<_, Error>(resolved || original.resolved_by(stop)?)
            })? {
                continue;
            }
            if link.is_none_or(|l| l.original != root_id)
                || row.scope != request.scope
                || row.session_id != original.row()?.session_id
                || row.driver_id != original.row()?.driver_id
            {
                return Err(Error::Refused);
            }
        }
        Ok(())
    }
    async fn claim(
        &self,
        request: v1::PlatformManagedMutationRequest,
    ) -> Result<(Owner, v1::PlatformManagedReceipt, bool), Error> {
        let fingerprint =
            wire::platform_managed_request_fingerprint(&request).map_err(|_| Error::Refused)?;
        let scope = request.scope.as_ref().ok_or(Error::Refused)?;
        self.check_scope(scope)?;
        // Proxy selection and fixed original native bytes precede reservation.
        match request.operation.as_ref().ok_or(Error::Refused)? {
            v1::platform_managed_mutation_request::Operation::Launch(l) => {
                let agent = Agent::try_from(l.agent)?;
                let provider = ProviderIdentity {
                    sha256: l
                        .expected_provider_sha256
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Refused)?,
                    size: l.expected_provider_size,
                    version: l.expected_provider_version.clone(),
                };
                let origin = scope_origin(
                    scope,
                    &request.request_id,
                    agent,
                    provider.clone(),
                    (!l.parent_session_id.is_empty())
                        .then_some(l.expected_parent_launch_generation),
                )?;
                ImagePin::admit(&self.inner.config, &origin)?;
                ProviderPin::admit(agent, &provider)?;
            }
            v1::platform_managed_mutation_request::Operation::Control(c) => {
                let origin = self
                    .inner
                    .engine
                    .platform_origin(scope, &c.session_id, c.expected_launch_generation, false)
                    .await?;
                ImagePin::admit(&self.inner.config, &origin)?;
            }
        }
        let _guard = self.inner.gate.lock().await;
        let tree = files::Tree::open(&self.root()?, true)?;
        let _lock = tree.lock()?;
        let scope_bytes = scope.encode_to_vec();
        match tree.read("scope.bin", 4096)? {
            Some(saved) if saved == scope_bytes => {}
            None => tree.write("scope.bin", &scope_bytes, false)?,
            _ => return Err(Error::Refused),
        }
        let owner = Owner {
            service: self.clone(),
            request: request.clone(),
            fingerprint: fingerprint.clone(),
        };
        if let Some(mut row) = Self::read_row(&tree, &request.request_id)? {
            if row.scope.as_ref() != Some(scope) || row.fingerprint_sha256 != fingerprint {
                return Err(Error::Refused);
            }
            if matches!(row.phase, 1 | 2)
                && !self
                    .inner
                    .active
                    .lock()
                    .map_err(|_| Error::Unknown)?
                    .contains(&request.request_id)
            {
                row.phase = v1::PlatformManagedRequestPhase::Unknown as i32;
                row.reason = "target-owner-lost".into();
            }
            return Ok((owner, row, false));
        }
        if tree.count()? >= 1024 {
            return Err(Error::Refused);
        }
        let books = Self::books(&tree, &self.root()?)?;
        let link = self.cleanup_link(&books, &request)?;
        Self::enforce_barriers(&books, &request, link.as_ref())?;
        let (driver, message, generation) =
            match request.operation.as_ref().ok_or(Error::Refused)? {
                v1::platform_managed_mutation_request::Operation::Launch(l) => (
                    request.request_id.clone(),
                    if l.prompt.is_some() {
                        wire::platform_managed_initial_prompt_id(&request.request_id)
                            .map_err(|_| Error::Refused)?
                    } else {
                        String::new()
                    },
                    1,
                ),
                v1::platform_managed_mutation_request::Operation::Control(c) => (
                    c.driver_id.clone(),
                    if matches!(c.action, 1..=3) {
                        request.request_id.clone()
                    } else {
                        String::new()
                    },
                    c.expected_launch_generation,
                ),
            };
        let row = v1::PlatformManagedReceipt {
            request_id: request.request_id.clone(),
            scope: Some(scope.clone()),
            fingerprint_sha256: fingerprint,
            phase: v1::PlatformManagedRequestPhase::Pending as i32,
            session_id: format!("session-{driver}"),
            driver_id: driver,
            message_id: message,
            launch_generation: generation,
            session_state: v1::SessionLifecycleState::Unspecified as i32,
            exit_code: None,
            cleanup_unknown: true,
            pipe_acknowledged: false,
            native_acknowledged: false,
            reason: "pending".into(),
            cleanup_of_request_id: link.as_ref().map(|l| l.original.clone()),
            cleanup_previous_generation: link.as_ref().map_or(0, |l| l.previous_generation),
            cleanup_previous_cleanup_known: false,
        };
        Stored::new(&request, &row)?.write(&tree, false)?;
        self.inner
            .active
            .lock()
            .map_err(|_| Error::Unknown)?
            .insert(request.request_id.clone());
        Ok((owner, row, true))
    }
    async fn observe(
        &self,
        request: &v1::PlatformManagedObserveRequest,
    ) -> Result<v1::PlatformManagedReceipt, Error> {
        if !wire::valid_uuid(&request.request_id) {
            return Err(Error::Refused);
        }
        let scope = request.scope.as_ref().ok_or(Error::Refused)?;
        self.check_scope(scope)?;
        let _guard = self.inner.gate.lock().await;
        let tree = files::Tree::open(&self.root()?, false)?;
        let mut row = Self::read_row(&tree, &request.request_id)?.ok_or(Error::Refused)?;
        if row.scope.as_ref() != Some(scope)
            || tree.read("scope.bin", 4096)?.as_deref() != Some(scope.encode_to_vec().as_slice())
        {
            return Err(Error::Refused);
        }
        if matches!(row.phase, 1 | 2)
            && !self
                .inner
                .active
                .lock()
                .map_err(|_| Error::Unknown)?
                .contains(&request.request_id)
        {
            row.phase = 5;
            row.reason = "target-owner-lost".into();
        }
        Ok(row)
    }
}
impl Owner {
    pub(crate) fn request(&self) -> &v1::PlatformManagedMutationRequest {
        &self.request
    }
    pub(crate) fn launch_origin(&self) -> Result<Origin, Error> {
        let Some(v1::platform_managed_mutation_request::Operation::Launch(l)) =
            &self.request.operation
        else {
            return Err(Error::Refused);
        };
        scope_origin(
            self.request.scope.as_ref().ok_or(Error::Refused)?,
            &self.request.request_id,
            Agent::try_from(l.agent)?,
            ProviderIdentity {
                sha256: l
                    .expected_provider_sha256
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Refused)?,
                size: l.expected_provider_size,
                version: l.expected_provider_version.clone(),
            },
            (!l.parent_session_id.is_empty()).then_some(l.expected_parent_launch_generation),
        )
    }
    pub(crate) fn release(&self) {
        if let Ok(mut active) = self.service.inner.active.lock() {
            active.remove(&self.request.request_id);
        }
    }
    pub(crate) async fn issue(&self) -> Result<(), Error> {
        let _guard = self.service.inner.gate.lock().await;
        let tree = files::Tree::open(&self.service.root()?, false)?;
        let _lock = tree.lock()?;
        let mut stored = Stored::read(&tree, &self.request.request_id)?.ok_or(Error::Unknown)?;
        let mut row = stored.row()?;
        if row.fingerprint_sha256 != self.fingerprint
            || row.scope != self.request.scope
            || row.phase != 1
        {
            return Err(Error::Unknown);
        }
        self.service
            .check_scope(self.request.scope.as_ref().ok_or(Error::Refused)?)?;
        let books = Service::books(&tree, &self.service.root()?)?;
        self.service.cleanup_link(&books, &self.request)?;
        row.phase = 2;
        row.reason = "issued".into();
        stored.set_row(&row);
        stored.write(&tree, true)
    }
    pub(crate) async fn cleanup_link(&self) -> Result<Option<CleanupLink>, Error> {
        let _guard = self.service.inner.gate.lock().await;
        let tree = files::Tree::open(&self.service.root()?, false)?;
        let _lock = tree.lock()?;
        let books = Service::books(&tree, &self.service.root()?)?;
        self.service.cleanup_link(&books, &self.request)
    }
    pub(crate) async fn record_advance(&self, witness: RestartAdvance) -> Result<(), Error> {
        let _guard = self.service.inner.gate.lock().await;
        let tree = files::Tree::open(&self.service.root()?, false)?;
        let _lock = tree.lock()?;
        let mut stored = Stored::read(&tree, &self.request.request_id)?.ok_or(Error::Unknown)?;
        stored.record_advance(&self.request, witness)?;
        stored.write(&tree, true)
    }
    pub(crate) async fn finish(
        &self,
        result: Result<(v1::SessionRecord, bool, bool), Error>,
    ) -> Result<v1::PlatformManagedReceipt, Error> {
        let _guard = self.service.inner.gate.lock().await;
        let tree = files::Tree::open(&self.service.root()?, false)?;
        let _lock = tree.lock()?;
        let mut stored = Stored::read(&tree, &self.request.request_id)?.ok_or(Error::Unknown)?;
        let mut row = stored.row()?;
        if row.fingerprint_sha256 != self.fingerprint
            || row.scope != self.request.scope
            || !matches!(row.phase, 1 | 2)
        {
            return Err(Error::Unknown);
        }
        match result {
            Ok((record, pipe, native))
                if row.phase == 2
                    && valid_settlement(&self.request, &row, &record, pipe, native) =>
            {
                row.phase = 3;
                row.reason = "settled".into();
                row.launch_generation = record.launch_generation;
                row.session_state = record.state;
                row.exit_code = record.exit_code;
                row.cleanup_unknown = record.cleanup_unknown;
                row.pipe_acknowledged = pipe;
                row.native_acknowledged = native;
                if row.cleanup_of_request_id.is_some() {
                    let books = Service::books(&tree, &self.service.root()?)?;
                    let link = self
                        .service
                        .cleanup_link(&books, &self.request)?
                        .ok_or(Error::Unknown)?;
                    if row.cleanup_previous_generation != link.previous_generation {
                        return Err(Error::Unknown);
                    }
                    row.cleanup_previous_cleanup_known = true;
                }
            }
            Err(_) if row.phase == 1 => {
                row.phase = 4;
                row.reason = "refused-before-issue".into();
                row.cleanup_unknown = false;
            }
            _ => {
                row.phase = 5;
                row.reason = "issued-outcome-unknown".into();
            }
        }
        stored.set_row(&row);
        stored.write(&tree, true)?;
        self.service
            .inner
            .active
            .lock()
            .map_err(|_| Error::Unknown)?
            .remove(&row.request_id);
        Ok(row)
    }
}
fn valid_settlement(
    request: &v1::PlatformManagedMutationRequest,
    row: &v1::PlatformManagedReceipt,
    r: &v1::SessionRecord,
    pipe: bool,
    native: bool,
) -> bool {
    use v1::PlatformManagedAction as A;
    use v1::SessionLifecycleState as S;
    if r.session_id != row.session_id || r.cleanup_unknown {
        return false;
    }
    match request.operation.as_ref() {
        Some(v1::platform_managed_mutation_request::Operation::Launch(_)) => {
            r.launch_generation == 1 && r.state == S::Running as i32 && !pipe && !native
        }
        Some(v1::platform_managed_mutation_request::Operation::Control(c)) => {
            let generation = if c.action == A::Restart as i32 {
                c.expected_launch_generation.checked_add(1)
            } else {
                Some(c.expected_launch_generation)
            };
            if generation != Some(r.launch_generation) {
                return false;
            }
            match A::try_from(c.action) {
                Ok(A::Message | A::Steer) => r.state == S::Running as i32 && pipe,
                Ok(A::Interrupt) => {
                    matches!(S::try_from(r.state), Ok(S::Running | S::Interrupted))
                        && pipe
                        && native
                }
                Ok(A::Stop) => {
                    ((r.state == S::Stopped as i32 && r.exit_code.is_none())
                        || (r.state == S::Exited as i32 && r.exit_code == Some(0)))
                        && !pipe
                        && !native
                }
                Ok(A::Restart) => r.state == S::Running as i32 && !pipe && !native,
                _ => false,
            }
        }
        _ => false,
    }
}

#[tonic::async_trait]
impl PlatformManagedService for Service {
    type ReadPlatformManagedSessionStream =
        ReceiverStream<Result<v1::PlatformManagedRecordChunk, Status>>;
    async fn get_platform_managed_info(
        &self,
        r: Request<v1::PlatformManagedInfoRequest>,
    ) -> Result<Response<v1::PlatformManagedInfoResponse>, Status> {
        self.authorize(&r)?;
        let r = r.into_inner();
        self.check_info(&r).map_err(status)?;
        let (hash, size) = ImagePin::identity().map_err(status)?;
        let mut agents = Vec::new();
        for (agent, slot) in [
            (Agent::Codex, ManagedCredentialClient::OpenAi),
            (Agent::Claude, ManagedCredentialClient::Anthropic),
        ] {
            if self.inner.config.managed_credential_clients.contains(slot) {
                let pin = ProviderPin::discover(agent).map_err(status)?;
                agents.push(v1::PlatformManagedAgentSupport {
                    agent: agent.wire(),
                    provider_sha256: pin.identity.sha256.to_vec(),
                    provider_size: pin.identity.size,
                    provider_version: pin.identity.version.clone(),
                    proxy_only_qualified: true,
                    steer: agent == Agent::Codex,
                    interrupt: true,
                });
            }
        }
        Ok(Response::new(v1::PlatformManagedInfoResponse {
            protocol_version: wire::PROTOCOL,
            environment_id: r.environment_id,
            binding_generation: r.binding_generation,
            projection_selection_sha256: r.projection_selection_sha256,
            support_image_sha256: hash.to_vec(),
            support_image_size: size,
            support_image_version: env!("CARGO_PKG_VERSION").into(),
            agents,
        }))
    }
    async fn mutate_platform_managed_session(
        &self,
        r: Request<v1::PlatformManagedMutationRequest>,
    ) -> Result<Response<v1::PlatformManagedReceipt>, Status> {
        self.authorize(&r)?;
        wire::validate_mutation(r.get_ref()).map_err(invalid)?;
        let (owner, row, dispatch) = self.claim(r.into_inner()).await.map_err(status)?;
        if !dispatch {
            return Ok(Response::new(row));
        }
        let receipt = self
            .inner
            .engine
            .platform_mutation(owner)
            .await
            .map_err(status)?;
        Ok(Response::new(receipt))
    }
    async fn observe_platform_managed_request(
        &self,
        r: Request<v1::PlatformManagedObserveRequest>,
    ) -> Result<Response<v1::PlatformManagedReceipt>, Status> {
        self.authorize(&r)?;
        Ok(Response::new(
            self.observe(&r.into_inner()).await.map_err(status)?,
        ))
    }
    async fn list_platform_managed_sessions(
        &self,
        r: Request<v1::PlatformManagedListRequest>,
    ) -> Result<Response<v1::PlatformManagedListResponse>, Status> {
        self.authorize(&r)?;
        let r = r.into_inner();
        let scope = r.scope.as_ref().ok_or_else(|| invalid("missing scope"))?;
        self.check_scope(scope).map_err(status)?;
        if r.page_limit > 8
            || (!r.after_session_id.is_empty() && !wire::valid_session(&r.after_session_id))
        {
            return Err(invalid("invalid page"));
        }
        let response = self
            .inner
            .engine
            .platform_list(
                scope,
                &r.after_session_id,
                if r.page_limit == 0 {
                    8
                } else {
                    r.page_limit as usize
                },
            )
            .await
            .map_err(status)?;
        if response.encoded_len() > wire::FRAME_BYTES {
            return Err(Status::resource_exhausted("platform page exceeds frame"));
        }
        Ok(Response::new(response))
    }
    async fn read_platform_managed_session(
        &self,
        r: Request<v1::PlatformManagedReadRequest>,
    ) -> Result<Response<Self::ReadPlatformManagedSessionStream>, Status> {
        self.authorize(&r)?;
        let r = r.into_inner();
        wire::validate_read(&r).map_err(invalid)?;
        self.check_scope(r.scope.as_ref().ok_or_else(|| invalid("missing scope"))?)
            .map_err(status)?;
        let bytes = self.inner.engine.platform_read(&r).await.map_err(status)?;
        if bytes.is_empty() || bytes.len() > wire::RECORD_BYTES {
            return Err(Status::resource_exhausted("platform record exceeds bound"));
        }
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let total = bytes.len() as u64;
        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            for (i, data) in bytes.chunks(wire::FRAME_BYTES - 4096).enumerate() {
                let row = v1::PlatformManagedRecordChunk {
                    scope: r.scope.clone(),
                    session_id: r.session_id.clone(),
                    driver_id: r.driver_id.clone(),
                    launch_generation: r.expected_launch_generation,
                    message_id: r.message_id.clone(),
                    offset: (i * (wire::FRAME_BYTES - 4096)) as u64,
                    total_bytes: total,
                    payload_sha256: digest.clone(),
                    data: data.to_vec(),
                };
                if tx.send(Ok(row)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn platform_service_settlement_keeps_pipe_native_and_exact_clean_generation_distinct() {
        let driver = uuid::Uuid::new_v4().to_string();
        let session = format!("session-{driver}");
        let mut c = v1::PlatformManagedControl {
            action: 1,
            session_id: session.clone(),
            driver_id: driver,
            expected_launch_generation: 1,
            ..Default::default()
        };
        let mut request = v1::PlatformManagedMutationRequest {
            operation: Some(v1::platform_managed_mutation_request::Operation::Control(
                c.clone(),
            )),
            ..Default::default()
        };
        let row = v1::PlatformManagedReceipt {
            session_id: session.clone(),
            ..Default::default()
        };
        let mut record = v1::SessionRecord {
            session_id: session,
            launch_generation: 1,
            state: v1::SessionLifecycleState::Running as i32,
            cleanup_unknown: false,
            ..Default::default()
        };
        assert!(valid_settlement(&request, &row, &record, true, false));
        assert!(!valid_settlement(&request, &row, &record, false, false));
        c.action = 3;
        request.operation = Some(v1::platform_managed_mutation_request::Operation::Control(
            c.clone(),
        ));
        assert!(!valid_settlement(&request, &row, &record, true, false));
        assert!(valid_settlement(&request, &row, &record, true, true));
        c.action = 5;
        request.operation = Some(v1::platform_managed_mutation_request::Operation::Control(
            c.clone(),
        ));
        assert!(!valid_settlement(&request, &row, &record, false, false));
        record.launch_generation = 2;
        assert!(valid_settlement(&request, &row, &record, false, false));
        record.cleanup_unknown = true;
        assert!(!valid_settlement(&request, &row, &record, false, false));
        record.cleanup_unknown = false;
        c.action = 4;
        c.expected_launch_generation = 2;
        request.operation = Some(v1::platform_managed_mutation_request::Operation::Control(c));
        record.state = v1::SessionLifecycleState::Stopped as i32;
        assert!(valid_settlement(&request, &row, &record, false, false));
        record.exit_code = Some(0);
        assert!(!valid_settlement(&request, &row, &record, false, false));
        record.state = v1::SessionLifecycleState::Exited as i32;
        assert!(valid_settlement(&request, &row, &record, false, false));
        record.exit_code = Some(1);
        assert!(!valid_settlement(&request, &row, &record, false, false));
        record.session_id.push('x');
        assert!(!valid_settlement(&request, &row, &record, false, false));
    }
}
