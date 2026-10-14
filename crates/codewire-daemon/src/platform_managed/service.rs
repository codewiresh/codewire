//! Original authenticated Pod service and target-owned durable intent. This is
//! not control-plane authorization: every public dispatch must still recheck its
//! current actor/grant and complete captured binding before its Issued journal.
use super::*;
use crate::durable_session::SessionEngine;
use codewire_daemon_proto::daemon::v1::platform_managed_service_server::PlatformManagedService;
use codewire_daemon_proto::{DAEMON_AUTH_TOKEN_HEADER, daemon::v1, platform_managed as wire};
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
    /// This daemon's own Pod UID, from the downward API and checked against
    /// its binding. Its request book is this Pod's alone (#2651), and a scope
    /// naming any other Pod is refused.
    pod_uid: String,
    gate: Mutex<()>,
    active: std::sync::Mutex<BTreeSet<String>>,
}
#[derive(Clone)]
pub(crate) struct Owner {
    service: Service,
    request: v1::PlatformManagedMutationRequest,
    fingerprint: String,
}
fn status(error: Error) -> Status {
    match error {
        // Material-free and refused before any effect, so it says why.
        Error::EarlierProvider(_) | Error::DeniedBeforeRun | Error::ResumeRefused(_) => {
            Status::failed_precondition(error.to_string())
        }
        _ => Status::failed_precondition("platform managed incarnation or outcome refused"),
    }
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
    /// Only a bound daemon, which knows its own Pod, serves managed agents;
    /// orchestration reaches them only through a Pod-scope binding.
    pub(crate) fn new(
        config: Config,
        engine: SessionEngine,
        pod_uid: Option<&str>,
    ) -> Option<Self> {
        let pod_uid = pod_uid.filter(|uid| wire::valid_uuid(uid))?.to_owned();
        Self::available(&config).then(|| Self {
            inner: Arc::new(Inner {
                config,
                engine,
                pod_uid,
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
        this_pod(scope, &self.inner.pod_uid)?;
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
        let environment = self
            .inner
            .config
            .credential_bridge
            .as_ref()
            .ok_or(Error::Refused)?
            .environment_id;
        Ok(book_root(
            Path::new(STATE),
            environment,
            &self.inner.pod_uid,
        ))
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
        let session = match request.operation.as_ref() {
            Some(v1::platform_managed_mutation_request::Operation::Control(c)) => {
                Some(c.session_id.as_str())
            }
            _ => None,
        };
        for old in books {
            let row = old.row()?;
            if !matches!(row.phase, 1 | 2 | 5) {
                continue;
            }
            // An unresolved Resume bars only its own conversation (#2705):
            // the platform ends that conversation, and no cleanup Stop can
            // resolve a Resume, so it must not hold every other conversation
            // and launch in this Pod.
            if old.is_resume() && session != Some(row.session_id.as_str()) {
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
            v1::platform_managed_mutation_request::Operation::Control(c)
                if c.action == v1::PlatformManagedAction::Resume as i32 =>
            {
                // The record must name exactly the earlier Pod the control
                // plane proved absent, and the resumed origin is admitted as
                // a launch's is (#2705).
                let origin = resume_origin(scope, c)?;
                ImagePin::admit(&self.inner.config, &origin)?;
                ProviderPin::admit(origin.agent, &origin.provider)
                    .map_err(|_| Error::ResumeRefused(super::PROVIDER_NOT_ADMITTED))?;
                origin
                    .agent
                    .route(self.inner.config.managed_credential_clients)
                    .ok_or(Error::Refused)?;
                self.inner.engine.platform_resumable(scope, c).await?;
            }
            v1::platform_managed_mutation_request::Operation::Control(c) => {
                if c.action == v1::PlatformManagedAction::Restart as i32 {
                    self.inner
                        .engine
                        .platform_restartable(&c.session_id)
                        .await?;
                }
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
        admit_scope(&tree, scope)?;
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
    /// A Resume's origin in this Pod: this scope, the same driver, the
    /// agent and the image's pinned provider. No parent: a child is never
    /// resumed.
    pub(crate) fn resume_origin(&self) -> Result<Origin, Error> {
        let Some(v1::platform_managed_mutation_request::Operation::Control(c)) =
            &self.request.operation
        else {
            return Err(Error::Refused);
        };
        resume_origin(self.request.scope.as_ref().ok_or(Error::Refused)?, c)
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
            // A Resume refused before issue keeps its plain reason (#2705).
            Err(Error::ResumeRefused(reason)) if row.phase == 1 && resume(&self.request) => {
                row.phase = 4;
                row.reason = reason.into();
                row.cleanup_unknown = false;
            }
            Err(_) if row.phase == 1 => {
                row.phase = 4;
                row.reason = "refused-before-issue".into();
                row.cleanup_unknown = false;
            }
            Err(Error::DeniedBeforeRun) if issued_launch(&self.request, &row) => {
                row.phase = 4;
                row.reason = "denied-before-run".into();
                row.session_state = v1::SessionLifecycleState::Failed as i32;
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
/// One request book per Pod incarnation (#2651), as orchestration keys its
/// journal by Pod. A Start, repair, resize or replacement brings a new Pod
/// and so a new book; a daemon restart inside one Pod keeps its book, whose
/// barriers still guard processes an earlier daemon there started. Books of
/// earlier Pods, and the book from before this layout at
/// `<environment>/requests`, stay on disk unread: every process they concern
/// went with their Pod.
fn book_root(state: &Path, environment: uuid::Uuid, pod_uid: &str) -> PathBuf {
    state
        .join(environment.to_string())
        .join("pods")
        .join(pod_uid)
        .join("requests")
}

/// A scope names the Pod it was captured for; only this daemon's own Pod is
/// served, so no caller can open another Pod's book or a fresh one.
fn this_pod(scope: &v1::PlatformManagedScope, pod_uid: &str) -> Result<(), Error> {
    if scope.pod_uid != pod_uid {
        return Err(Error::Refused);
    }
    Ok(())
}

/// A book holds exactly one scope: the first request records it and every
/// later one must repeat it byte for byte.
fn admit_scope(tree: &files::Tree, scope: &v1::PlatformManagedScope) -> Result<(), Error> {
    let scope_bytes = scope.encode_to_vec();
    match tree.read("scope.bin", 4096)? {
        Some(saved) if saved == scope_bytes => Ok(()),
        None => tree.write("scope.bin", &scope_bytes, false),
        _ => Err(Error::Refused),
    }
}

fn resume_origin(
    scope: &v1::PlatformManagedScope,
    c: &v1::PlatformManagedControl,
) -> Result<Origin, Error> {
    if c.action != v1::PlatformManagedAction::Resume as i32
        || c.predecessor_pod_uid.is_empty()
        || c.predecessor_pod_uid == scope.pod_uid
    {
        return Err(Error::Refused);
    }
    scope_origin(
        scope,
        &c.driver_id,
        Agent::try_from(c.agent)?,
        ProviderIdentity {
            sha256: c
                .expected_provider_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Error::Refused)?,
            size: c.expected_provider_size,
            version: c.expected_provider_version.clone(),
        },
        None,
    )
}

/// An issued launch: the only request a denial before its agent ran settles
/// as refused.
fn issued_launch(
    request: &v1::PlatformManagedMutationRequest,
    row: &v1::PlatformManagedReceipt,
) -> bool {
    row.phase == 2
        && matches!(
            request.operation,
            Some(v1::platform_managed_mutation_request::Operation::Launch(_))
        )
}

/// A Resume, whose plain refusals before issue carry their reason (#2705).
fn resume(request: &v1::PlatformManagedMutationRequest) -> bool {
    matches!(
        &request.operation,
        Some(v1::platform_managed_mutation_request::Operation::Control(c))
            if c.action == v1::PlatformManagedAction::Resume as i32
    )
}

/// The receipt of a launch or a Resume refused before its claim wrote
/// anything: the same row one refused before issue settles to, never stored.
/// A Resume refused here keeps its conversation resumable and may name its
/// plain reason (#2705); a launch's reason is always `refused-before-issue`.
fn refused_launch(
    request: &v1::PlatformManagedMutationRequest,
    reason: &str,
) -> Option<v1::PlatformManagedReceipt> {
    if reason != "refused-before-issue" && !(resume(request) && wire::resume_refusal(reason)) {
        return None;
    }
    let (driver_id, message_id, launch_generation) = match request.operation.as_ref()? {
        v1::platform_managed_mutation_request::Operation::Launch(launch) => (
            request.request_id.clone(),
            match launch.prompt {
                Some(_) => wire::platform_managed_initial_prompt_id(&request.request_id).ok()?,
                None => String::new(),
            },
            1,
        ),
        v1::platform_managed_mutation_request::Operation::Control(c)
            if c.action == v1::PlatformManagedAction::Resume as i32 =>
        {
            (
                c.driver_id.clone(),
                String::new(),
                c.expected_launch_generation,
            )
        }
        _ => return None,
    };
    let receipt = v1::PlatformManagedReceipt {
        request_id: request.request_id.clone(),
        scope: Some(request.scope.clone()?),
        fingerprint_sha256: wire::platform_managed_request_fingerprint(request).ok()?,
        phase: v1::PlatformManagedRequestPhase::Rejected as i32,
        session_id: format!("session-{driver_id}"),
        driver_id,
        message_id,
        launch_generation,
        session_state: v1::SessionLifecycleState::Unspecified as i32,
        exit_code: None,
        cleanup_unknown: false,
        pipe_acknowledged: false,
        native_acknowledged: false,
        reason: reason.into(),
        cleanup_of_request_id: None,
        cleanup_previous_generation: 0,
        cleanup_previous_cleanup_known: false,
    };
    wire::validate_receipt(&receipt).ok()?;
    Some(receipt)
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
            let generation = if c.action == A::Restart as i32 || c.action == A::Resume as i32 {
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
                Ok(A::Restart | A::Resume) => r.state == S::Running as i32 && !pipe && !native,
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
        for agent in [Agent::Codex, Agent::Claude] {
            if agent
                .route(self.inner.config.managed_credential_clients)
                .is_some()
            {
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
        let request = r.into_inner();
        let (owner, row, dispatch) = match self.claim(request.clone()).await {
            Ok(claimed) => claimed,
            // A refused claim wrote nothing and started nothing. For a launch
            // or a Resume, say so with a definite refusal instead of an error
            // that leaves orchestration an unknown outcome and its deletion
            // lease unresolved (#2705). Other controls keep the error: a
            // cleanup Stop's receipt must carry generations only its book has.
            Err(error @ (Error::Refused | Error::EarlierProvider(_) | Error::ResumeRefused(_))) => {
                let reason = match &error {
                    Error::ResumeRefused(reason) => reason,
                    _ => "refused-before-issue",
                };
                return match refused_launch(&request, reason) {
                    Some(receipt) => Ok(Response::new(receipt)),
                    None => Err(status(error)),
                };
            }
            Err(error) => return Err(status(error)),
        };
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
    use std::os::unix::fs::PermissionsExt;

    fn scope(environment: uuid::Uuid, pod: &str) -> v1::PlatformManagedScope {
        v1::PlatformManagedScope {
            environment_id: environment.to_string(),
            org_id: "fixture-org".into(),
            pod_uid: pod.into(),
            binding_generation: 7,
            projection_selection_sha256: vec![1; 32],
            support_image_sha256: vec![2; 32],
            support_image_size: 1024,
        }
    }
    fn launch(scope: &v1::PlatformManagedScope) -> v1::PlatformManagedMutationRequest {
        v1::PlatformManagedMutationRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            scope: Some(scope.clone()),
            operation: Some(v1::platform_managed_mutation_request::Operation::Launch(
                v1::PlatformManagedLaunch {
                    agent: v1::PlatformManagedAgent::Codex as i32,
                    model: "fixture-model".into(),
                    expected_provider_sha256: vec![3; 32],
                    expected_provider_size: 1024,
                    expected_provider_version: "0.160.0".into(),
                    ..Default::default()
                },
            )),
        }
    }
    /// The row `claim` writes for a launch, after the daemon issued it: an
    /// outcome still open in its book.
    fn issued(request: &v1::PlatformManagedMutationRequest) -> Stored {
        let row = v1::PlatformManagedReceipt {
            request_id: request.request_id.clone(),
            scope: request.scope.clone(),
            fingerprint_sha256: wire::platform_managed_request_fingerprint(request).unwrap(),
            phase: 2,
            session_id: format!("session-{}", request.request_id),
            driver_id: request.request_id.clone(),
            launch_generation: 1,
            cleanup_unknown: true,
            reason: "issued".into(),
            ..Default::default()
        };
        Stored::new(request, &row).unwrap()
    }
    /// The book's lock. A child another test forks in this process holds a
    /// copy of a just-closed lock descriptor until its exec, so a quick
    /// relock may briefly find it held.
    fn lock(tree: &files::Tree) -> std::fs::File {
        for _ in 0..200 {
            if let Ok(lock) = tree.lock() {
                return lock;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("the request book lock stayed held");
    }
    fn files_of(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect::<Vec<_>>();
        files.sort();
        files
    }

    /// #2651: `claim`'s book steps (open, lock, scope, existing books,
    /// barriers, the new row) on real held files, in the paths `root()` uses.
    #[test]
    fn platform_book_is_one_per_pod_and_kept_across_a_daemon_restart_in_that_pod() {
        let state = tempfile::tempdir().unwrap();
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let environment = uuid::Uuid::new_v4();
        let (pod_a, pod_b) = (
            uuid::Uuid::new_v4().to_string(),
            uuid::Uuid::new_v4().to_string(),
        );
        let (scope_a, scope_b) = (scope(environment, &pod_a), scope(environment, &pod_b));
        let root_a = book_root(state.path(), environment, &pod_a);
        let root_b = book_root(state.path(), environment, &pod_b);
        assert_eq!(
            root_a,
            state
                .path()
                .join(environment.to_string())
                .join("pods")
                .join(&pod_a)
                .join("requests")
        );
        assert_ne!(root_a, root_b);

        // Pod A's daemon admits a launch whose outcome stays open.
        let first = launch(&scope_a);
        {
            let tree = files::Tree::open(&root_a, true).unwrap();
            let _lock = lock(&tree);
            admit_scope(&tree, &scope_a).unwrap();
            let books = Service::books(&tree, &root_a).unwrap();
            Service::enforce_barriers(&books, &first, None).unwrap();
            issued(&first).write(&tree, false).unwrap();
        }
        // A daemon restart inside Pod A opens the same book: its scope is
        // admitted again and its open outcome still bars another request.
        let tree = files::Tree::open(&root_a, false).unwrap();
        let _lock = lock(&tree);
        admit_scope(&tree, &scope_a).unwrap();
        let books = Service::books(&tree, &root_a).unwrap();
        assert_eq!(books.len(), 1);
        assert!(matches!(
            Service::enforce_barriers(&books, &launch(&scope_a), None),
            Err(Error::Refused)
        ));
        // A's book keeps refusing any other scope, as the single book did.
        assert!(matches!(admit_scope(&tree, &scope_b), Err(Error::Refused)));
        drop(_lock);
        let a_before = files_of(&root_a);

        // Pod B gets a fresh book: A's open row no longer bars it, and B
        // admits and records its own launch.
        let second = launch(&scope_b);
        let tree = files::Tree::open(&root_b, true).unwrap();
        let _lock = lock(&tree);
        admit_scope(&tree, &scope_b).unwrap();
        let books = Service::books(&tree, &root_b).unwrap();
        assert!(books.is_empty());
        Service::enforce_barriers(&books, &second, None).unwrap();
        issued(&second).write(&tree, false).unwrap();
        assert_eq!(
            tree.read("scope.bin", 4096).unwrap().unwrap(),
            scope_b.encode_to_vec()
        );
        // Pod A's book is left exactly as it was.
        assert_eq!(files_of(&root_a), a_before);
    }

    /// Only this daemon's own Pod is served: a scope that names any other
    /// Pod, including the same UID spelled differently, is refused.
    #[test]
    fn platform_scope_naming_another_pod_is_refused() {
        let environment = uuid::Uuid::new_v4();
        let pod = uuid::Uuid::new_v4().to_string();
        this_pod(&scope(environment, &pod), &pod).unwrap();
        for other in [
            uuid::Uuid::new_v4().to_string(),
            pod.to_uppercase(),
            String::new(),
        ] {
            assert!(matches!(
                this_pod(&scope(environment, &other), &pod),
                Err(Error::Refused)
            ));
        }
    }

    #[test]
    fn platform_service_names_only_an_earlier_provider_and_keeps_other_refusals_opaque() {
        for (agent, message) in [
            (
                Agent::Claude,
                "this managed agent was started with an earlier Claude Code; start a new conversation",
            ),
            (
                Agent::Codex,
                "this managed agent was started with an earlier Codex; start a new conversation",
            ),
        ] {
            let refused = status(Error::EarlierProvider(agent));
            assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
            assert_eq!(refused.message(), message);
        }
        for error in [Error::Refused, Error::Unknown] {
            let refused = status(error);
            assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
            assert_eq!(
                refused.message(),
                "platform managed incarnation or outcome refused"
            );
        }
    }

    #[test]
    fn platform_service_refuses_a_launch_claim_definitely_and_a_control_claim_opaquely() {
        let scope = scope(uuid::Uuid::new_v4(), &uuid::Uuid::new_v4().to_string());
        let mut request = launch(&scope);
        let refused = refused_launch(&request, "refused-before-issue").unwrap();
        assert_eq!(
            refused.phase,
            v1::PlatformManagedRequestPhase::Rejected as i32
        );
        assert_eq!(refused.reason, "refused-before-issue");
        assert!(!refused.cleanup_unknown);
        assert_eq!(
            refused.session_id,
            format!("session-{}", request.request_id)
        );
        assert_eq!(refused.driver_id, request.request_id);
        assert_eq!(refused.launch_generation, 1);
        assert!(refused.message_id.is_empty());
        assert_eq!(
            refused.fingerprint_sha256,
            wire::platform_managed_request_fingerprint(&request).unwrap()
        );
        wire::validate_receipt(&refused).unwrap();
        // A launch with a prompt names its initial message, as the stored row does.
        if let Some(v1::platform_managed_mutation_request::Operation::Launch(l)) =
            request.operation.as_mut()
        {
            l.prompt = Some("fixture task".into());
        }
        assert_eq!(
            refused_launch(&request, "refused-before-issue")
                .unwrap()
                .message_id,
            wire::platform_managed_initial_prompt_id(&request.request_id).unwrap()
        );
        let driver = uuid::Uuid::new_v4().to_string();
        let control = v1::PlatformManagedMutationRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            scope: Some(scope),
            operation: Some(v1::platform_managed_mutation_request::Operation::Control(
                v1::PlatformManagedControl {
                    action: 4,
                    session_id: format!("session-{driver}"),
                    driver_id: driver,
                    expected_launch_generation: 1,
                    ..Default::default()
                },
            )),
        };
        assert!(refused_launch(&control, "refused-before-issue").is_none());
        // Only a Resume carries a plain reason, and only a closed one (#2705).
        assert!(refused_launch(&request, "resume-driver-alive").is_none());
    }

    #[test]
    fn platform_service_an_unknown_resume_bars_only_its_own_conversation() {
        // #2705: an unknown Resume ends its conversation and no cleanup Stop
        // can resolve it, so it must not hold the rest of the Pod's book.
        let scope = scope(uuid::Uuid::new_v4(), &uuid::Uuid::new_v4().to_string());
        let control = |action: v1::PlatformManagedAction, driver: &str| {
            let mut c = v1::PlatformManagedControl {
                action: action as i32,
                session_id: format!("session-{driver}"),
                driver_id: driver.to_owned(),
                expected_launch_generation: 3,
                ..Default::default()
            };
            if action == v1::PlatformManagedAction::Resume {
                c.predecessor_pod_uid = uuid::Uuid::new_v4().to_string();
                c.agent = v1::PlatformManagedAgent::Codex as i32;
                c.expected_provider_sha256 = vec![3; 32];
                c.expected_provider_size = 1024;
                c.expected_provider_version = "0.160.0".into();
            }
            if action == v1::PlatformManagedAction::Message {
                c.text = "synthetic".into();
            }
            v1::PlatformManagedMutationRequest {
                request_id: uuid::Uuid::new_v4().to_string(),
                scope: Some(scope.clone()),
                operation: Some(v1::platform_managed_mutation_request::Operation::Control(c)),
            }
        };
        let unknown = |request: &v1::PlatformManagedMutationRequest, driver: &str| {
            let row = v1::PlatformManagedReceipt {
                request_id: request.request_id.clone(),
                scope: request.scope.clone(),
                fingerprint_sha256: wire::platform_managed_request_fingerprint(request).unwrap(),
                phase: 5,
                session_id: format!("session-{driver}"),
                driver_id: driver.to_owned(),
                message_id: match request.operation.as_ref() {
                    Some(v1::platform_managed_mutation_request::Operation::Control(c))
                        if matches!(c.action, 1..=3) =>
                    {
                        request.request_id.clone()
                    }
                    _ => String::new(),
                },
                launch_generation: 3,
                cleanup_unknown: true,
                reason: "issued-outcome-unknown".into(),
                ..Default::default()
            };
            Stored::new(request, &row).unwrap()
        };
        let resumed = uuid::Uuid::new_v4().to_string();
        let other = uuid::Uuid::new_v4().to_string();
        let resume = control(v1::PlatformManagedAction::Resume, &resumed);
        let books = [unknown(&resume, &resumed)];
        // A new launch and another conversation's controls are admitted.
        Service::enforce_barriers(&books, &launch(&scope), None).unwrap();
        Service::enforce_barriers(
            &books,
            &control(v1::PlatformManagedAction::Message, &other),
            None,
        )
        .unwrap();
        // Its own conversation stays barred.
        for action in [
            v1::PlatformManagedAction::Message,
            v1::PlatformManagedAction::Stop,
            v1::PlatformManagedAction::Restart,
            v1::PlatformManagedAction::Resume,
        ] {
            assert!(
                Service::enforce_barriers(&books, &control(action, &resumed), None).is_err(),
                "{action:?}"
            );
        }
        // Any other unknown request still bars the whole Pod until its
        // cleanup, as before.
        let restart = control(v1::PlatformManagedAction::Restart, &other);
        let books = [unknown(&restart, &other)];
        assert!(Service::enforce_barriers(&books, &launch(&scope), None).is_err());
        assert!(
            Service::enforce_barriers(
                &books,
                &control(v1::PlatformManagedAction::Message, &resumed),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn platform_service_refuses_a_resume_claim_with_its_plain_reason() {
        let scope = scope(uuid::Uuid::new_v4(), &uuid::Uuid::new_v4().to_string());
        let driver = uuid::Uuid::new_v4().to_string();
        let resume_request = v1::PlatformManagedMutationRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            scope: Some(scope),
            operation: Some(v1::platform_managed_mutation_request::Operation::Control(
                v1::PlatformManagedControl {
                    action: v1::PlatformManagedAction::Resume as i32,
                    session_id: format!("session-{driver}"),
                    driver_id: driver.clone(),
                    expected_launch_generation: 3,
                    predecessor_pod_uid: uuid::Uuid::new_v4().to_string(),
                    agent: v1::PlatformManagedAgent::Codex as i32,
                    expected_provider_sha256: vec![3; 32],
                    expected_provider_size: 1024,
                    expected_provider_version: "0.160.0".into(),
                    ..Default::default()
                },
            )),
        };
        assert!(resume(&resume_request));
        for reason in wire::RESUME_REFUSALS
            .into_iter()
            .chain(["refused-before-issue"])
        {
            let refused = refused_launch(&resume_request, reason).unwrap();
            assert_eq!(refused.reason, reason);
            assert_eq!(
                refused.phase,
                v1::PlatformManagedRequestPhase::Rejected as i32
            );
            // A refused Resume keeps the predecessor's generation.
            assert_eq!(refused.launch_generation, 3);
            assert_eq!(refused.driver_id, driver);
            assert!(!refused.cleanup_unknown);
            wire::validate_receipt(&refused).unwrap();
            if reason != "refused-before-issue" {
                assert_eq!(
                    status(Error::ResumeRefused(reason)).message(),
                    format!("platform managed resume refused: {reason}")
                );
            }
        }
        for reason in ["", "denied-before-run", "resume-anything", "issued"] {
            assert!(
                refused_launch(&resume_request, reason).is_none(),
                "{reason}"
            );
        }
    }

    #[test]
    fn platform_service_settles_only_an_issued_launch_denied_before_run_as_refused() {
        let scope = scope(uuid::Uuid::new_v4(), &uuid::Uuid::new_v4().to_string());
        let request = launch(&scope);
        let mut row = issued(&request).row().unwrap();
        assert!(issued_launch(&request, &row));
        row.phase = 1;
        assert!(!issued_launch(&request, &row));
        row.phase = 2;
        let mut control = request.clone();
        control.operation = Some(v1::platform_managed_mutation_request::Operation::Control(
            v1::PlatformManagedControl::default(),
        ));
        assert!(!issued_launch(&control, &row));
        // The settled row is a valid private receipt.
        row.phase = 4;
        row.reason = "denied-before-run".into();
        row.session_state = v1::SessionLifecycleState::Failed as i32;
        row.cleanup_unknown = false;
        wire::validate_receipt(&row).unwrap();
        row.cleanup_unknown = true;
        assert!(wire::validate_receipt(&row).is_err());
        let refused = status(Error::DeniedBeforeRun);
        assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            refused.message(),
            "the environment launch was denied before the managed agent started"
        );
    }

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
