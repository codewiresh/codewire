//! The host agent's lifecycle operations (#3609, slice 2). Each runs through
//! this computer's local VM supervisor, the one `cw --local` uses.
//!
//! The supervisor's journal is the host's only record of them. An
//! operation's ID is its supervisor request ID, so the same operation sent
//! again is found there and answered with how it ended, however long ago.
//! The control plane's generation fence is checked only for an operation not
//! yet journaled, because one already sent may itself have moved the
//! generation since.
//!
//! A VM the control plane placed is named `cw-<host tag>-<environment
//! UUID>`, the tag coming from the enrollment's host ID, so the host keeps no
//! mapping, its inventory is the supervisor's list, and a VM an earlier
//! enrollment of this computer placed is never this one's.
//!
//! A failure's message reaches the control plane and the members the host is
//! granted to, so it names no path on this computer; the detail is printed
//! here, for the host's owner.
//!
//! Only a definitive outcome is reported: the control plane records the
//! first one for good. When the supervisor cannot be reached, the agent tries
//! again; every step is idempotent by the operation's ID.

use codewire_client::hosts::{
    HostCreate, HostEnvironmentObservation, HostEnvironmentState, HostOperation,
    HostOperationFailure, HostOperationResult, HostStaleGeneration, host_operation,
    host_operation_result,
};
use codewire_local_vmm::control::v1 as local;
use codewire_local_vmm::supervisor::NativeSupervisorClient;
use codewire_local_vmm::supervisor_client::operation_error_code;
use sha2::{Digest as _, Sha256};
use tonic::Code;
use uuid::Uuid;

use super::*;

/// How many hex digits of the host ID's SHA-256 tag a VM name.
const HOST_TAG_HEX: usize = 12;
/// Bounds on a failure's code and message, as the contract states.
const MAX_CODE_BYTES: usize = 64;
const MAX_MESSAGE_BYTES: usize = 1024;
/// Between attempts while the supervisor cannot be reached.
const RETRY_AFTER: Duration = Duration::from_secs(5);

/// The VMs one enrollment places: their names start with `cw-` and a tag of
/// the host ID.
#[derive(Clone, Debug)]
pub(super) struct Placement {
    prefix: String,
}

impl Placement {
    pub(super) fn new(host_id: &str) -> Self {
        let digest = format!("{:x}", Sha256::digest(host_id.as_bytes()));
        Self {
            prefix: format!("cw-{}-", &digest[..HOST_TAG_HEX]),
        }
    }

    /// The supervisor's name for the VM of `environment_id`.
    pub(super) fn vm_name(&self, environment_id: Uuid) -> String {
        format!("{}{environment_id}", self.prefix)
    }

    /// The environment a VM name belongs to, when this enrollment placed it.
    pub(super) fn environment(&self, name: &str) -> Option<Uuid> {
        let id = Uuid::parse_str(name.strip_prefix(&self.prefix)?).ok()?;
        // Only the exact form `vm_name` writes: another spelling of the same
        // UUID is a VM someone named by hand.
        (self.vm_name(id) == name).then_some(id)
    }
}

/// An operation as the agent runs it, parsed once from the wire.
pub(super) struct Operation {
    pub(super) id: Uuid,
    environment_id: Uuid,
    /// The supervisor's name for the environment's VM.
    vm: String,
    expected_generation: u64,
    kind: Kind,
}

/// What to do.
enum Kind {
    Create(Box<HostCreate>),
    /// On the environment with this host ID.
    Lifecycle(Lifecycle, Uuid),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lifecycle {
    Start,
    Stop,
    Destroy,
}

/// A definitive refusal or failure, reported as it is.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Failure {
    code: String,
    message: String,
}

impl Failure {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: bounded(code, MAX_CODE_BYTES),
            message: bounded(&message.into(), MAX_MESSAGE_BYTES),
        }
    }

    fn invalid(message: &str) -> Self {
        Self::new("invalid_operation", message)
    }

    /// A failure whose cause names this computer's paths: `message` is what
    /// the control plane sees, and the cause is printed here for the owner.
    fn local(code: &str, message: &str, cause: &anyhow::Error) -> Self {
        eprintln!("{message}: {cause:#}");
        Self::new(code, message)
    }
}

/// The longest prefix of `text` within `limit` bytes, on a character
/// boundary.
fn bounded(text: &str, limit: usize) -> String {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// How an operation ended.
#[derive(Debug, PartialEq)]
pub(super) enum Outcome {
    Done(Box<HostEnvironmentObservation>),
    Failed(Failure),
    Stale { expected: u64, current: u64 },
}

impl Outcome {
    pub(super) fn into_result(self, operation_id: &str) -> HostOperationResult {
        let outcome = match self {
            Self::Done(observation) => host_operation_result::Outcome::Done(observation),
            Self::Failed(failure) => {
                host_operation_result::Outcome::Failed(Box::new(HostOperationFailure {
                    code: failure.code,
                    message: failure.message,
                    ..Default::default()
                }))
            }
            Self::Stale { expected, current } => {
                host_operation_result::Outcome::StaleGeneration(Box::new(HostStaleGeneration {
                    expected_generation: expected,
                    current_generation: current,
                    ..Default::default()
                }))
            }
        };
        HostOperationResult {
            operation_id: operation_id.to_owned(),
            outcome: Some(outcome),
            ..Default::default()
        }
    }
}

fn uuid(value: &str, what: &str) -> Result<Uuid, Failure> {
    match Uuid::parse_str(value) {
        Ok(id) if !id.is_nil() => Ok(id),
        _ => Err(Failure::invalid(&format!("the {what} is not a UUID"))),
    }
}

impl Operation {
    pub(super) fn parse(operation: HostOperation, placement: &Placement) -> Result<Self, Failure> {
        let id = uuid(&operation.operation_id, "operation ID")?;
        let environment_id = uuid(&operation.environment_id, "environment ID")?;
        let local = || uuid(&operation.local_environment_id, "host's environment ID");
        let kind = match operation.kind {
            Some(host_operation::Kind::Create(create)) => {
                if !operation.local_environment_id.is_empty() || operation.expected_generation != 0
                {
                    return Err(Failure::invalid(
                        "a create names no host environment and no generation",
                    ));
                }
                Kind::Create(create)
            }
            Some(host_operation::Kind::Start(_)) => Kind::Lifecycle(Lifecycle::Start, local()?),
            Some(host_operation::Kind::Stop(_)) => Kind::Lifecycle(Lifecycle::Stop, local()?),
            Some(host_operation::Kind::Destroy(_)) => Kind::Lifecycle(Lifecycle::Destroy, local()?),
            None => return Err(Failure::invalid("the operation has no kind")),
        };
        Ok(Self {
            id,
            environment_id,
            vm: placement.vm_name(environment_id),
            expected_generation: operation.expected_generation,
            kind,
        })
    }
}

/// One try at an operation.
pub(super) enum Attempt {
    Finished(Outcome),
    /// The supervisor could not be reached, or stopped answering; why.
    Retry(String),
}

/// Whether a supervisor status says nothing about the operation itself.
fn transient(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        Code::Unavailable | Code::DeadlineExceeded | Code::Cancelled | Code::Unknown
    )
}

/// A supervisor refusal as the control plane sees it: the operation's own
/// error code when the supervisor gives one, else the status code. Its
/// words can name this computer's paths, so they are printed here instead.
fn status_failure(status: &tonic::Status) -> Failure {
    eprintln!("the local VM supervisor refused: {}", status.message());
    let code = match operation_error_code(status) {
        Some(code) if !code.is_empty() => code.to_owned(),
        _ => snake_case(&format!("{:?}", status.code())),
    };
    Failure::new(&code, "this host's VM supervisor refused the operation")
}

/// `Code`'s names are CamelCase; the contract's codes are snake_case.
fn snake_case(name: &str) -> String {
    let mut snake = String::with_capacity(name.len() + 4);
    for (index, character) in name.chars().enumerate() {
        if character.is_ascii_uppercase() && index > 0 {
            snake.push('_');
        }
        snake.push(character.to_ascii_lowercase());
    }
    snake
}

/// How an attempt ends on a supervisor error.
fn ended(status: tonic::Status) -> Attempt {
    if transient(&status) {
        Attempt::Retry(status.message().to_owned())
    } else {
        Attempt::Finished(Outcome::Failed(status_failure(&status)))
    }
}

fn failed(failure: Failure) -> Attempt {
    Attempt::Finished(Outcome::Failed(failure))
}

/// Runs `operation` to a definitive outcome, trying again while the
/// supervisor cannot be reached. It ends only with an outcome, or when the
/// caller drops it.
pub(super) async fn run(operation: &Operation) -> Outcome {
    loop {
        match attempt(operation).await {
            Attempt::Finished(outcome) => return outcome,
            Attempt::Retry(reason) => {
                eprintln!(
                    "operation {}: the local VM supervisor is unavailable ({reason}); retrying in {}s",
                    operation.id,
                    RETRY_AFTER.as_secs()
                );
                tokio::time::sleep(RETRY_AFTER).await;
            }
        }
    }
}

/// The supervisor calls an operation makes, so tests can stand in for the
/// supervisor.
pub(super) trait Supervisor {
    async fn operation_for_request(
        &mut self,
        request_id: Uuid,
    ) -> Result<Option<local::Operation>, tonic::Status>;
    async fn follow(&mut self, operation: local::Operation) -> Result<(), tonic::Status>;
    /// Installs the VM runtime this cw pins, as `cw --local create` does
    /// before a create.
    async fn ensure_runtime(&mut self) -> Result<(), Failure>;
    /// The empty workspace a create starts from: its source path and path
    /// mode.
    fn empty_workspace(&mut self) -> Result<(String, String), Failure>;
    async fn create(
        &mut self,
        request: local::CreateEnvironmentRequest,
    ) -> Result<(), tonic::Status>;
    async fn get(&mut self, name: &str) -> Result<local::Environment, tonic::Status>;
    async fn change(
        &mut self,
        lifecycle: Lifecycle,
        selector: local::EnvironmentSelector,
    ) -> Result<(), tonic::Status>;
}

impl Supervisor for NativeSupervisorClient {
    async fn operation_for_request(
        &mut self,
        request_id: Uuid,
    ) -> Result<Option<local::Operation>, tonic::Status> {
        NativeSupervisorClient::operation_for_request(self, request_id).await
    }

    async fn follow(&mut self, operation: local::Operation) -> Result<(), tonic::Status> {
        NativeSupervisorClient::follow(self, operation)
            .await
            .map(drop)
    }

    async fn ensure_runtime(&mut self) -> Result<(), Failure> {
        super::super::native::ensure_pinned_runtime()
            .await
            .map_err(|error| {
                Failure::local(
                    "runtime_unavailable",
                    "this host could not install its VM runtime",
                    &error,
                )
            })
    }

    fn empty_workspace(&mut self) -> Result<(String, String), Failure> {
        super::super::native::host_create::native_empty_workspace_source().map_err(|error| {
            Failure::local(
                "workspace_unavailable",
                "this host could not prepare an empty workspace",
                &error,
            )
        })
    }

    async fn create(
        &mut self,
        request: local::CreateEnvironmentRequest,
    ) -> Result<(), tonic::Status> {
        NativeSupervisorClient::create(self, request)
            .await
            .map(drop)
    }

    async fn get(&mut self, name: &str) -> Result<local::Environment, tonic::Status> {
        NativeSupervisorClient::get(self, name).await
    }

    async fn change(
        &mut self,
        lifecycle: Lifecycle,
        selector: local::EnvironmentSelector,
    ) -> Result<(), tonic::Status> {
        match lifecycle {
            Lifecycle::Start => self.start_selected(selector).await,
            Lifecycle::Stop => self.stop_selected(selector).await,
            Lifecycle::Destroy => self.delete_selected(selector).await,
        }
        .map(drop)
    }
}

async fn supervisor(kind: &Kind) -> Result<NativeSupervisorClient, Attempt> {
    // A boot takes the state root over from an older idle supervisor first,
    // as `cw --local create` and `start` do.
    let client = match kind {
        Kind::Create(_) | Kind::Lifecycle(Lifecycle::Start, _) => {
            super::super::native::native_boot_client_here().await
        }
        Kind::Lifecycle(Lifecycle::Stop | Lifecycle::Destroy, _) => {
            super::super::native::native_client().await
        }
    };
    client.map_err(|error| Attempt::Retry(format!("{error:#}")))
}

async fn attempt(operation: &Operation) -> Attempt {
    let mut client = match supervisor(&operation.kind).await {
        Ok(client) => client,
        Err(attempt) => return attempt,
    };
    attempt_with(&mut client, operation).await
}

/// One try at `operation` against `client`.
pub(super) async fn attempt_with(client: &mut impl Supervisor, operation: &Operation) -> Attempt {
    match journal_then_observe(client, operation).await {
        Ok(observation) => Attempt::Finished(Outcome::Done(Box::new(observation))),
        Err(attempt) => attempt,
    }
}

async fn journal_then_observe(
    client: &mut impl Supervisor,
    operation: &Operation,
) -> Result<HostEnvironmentObservation, Attempt> {
    let journaled = client
        .operation_for_request(operation.id)
        .await
        .map_err(ended)?;
    match (journaled, &operation.kind) {
        // Sent before: how it ended, whatever the generation is now.
        (Some(journaled), kind) => {
            same_operation(&journaled, kind).map_err(failed)?;
            client.follow(journaled).await.map_err(ended)?;
        }
        (None, Kind::Create(create)) => {
            let spec = accepted_project(create).map_err(failed)?;
            let workspace = client.empty_workspace().map_err(failed)?;
            let request = create_request(operation.id, &operation.vm, create, spec, workspace)
                .map_err(failed)?;
            client.ensure_runtime().await.map_err(failed)?;
            created(client.create(request).await)?;
        }
        (None, Kind::Lifecycle(lifecycle, local_id)) => {
            apply(client, operation, *lifecycle, *local_id).await?
        }
    }
    observe(client, operation).await
}

/// How a create ends. A VM with this environment's name already exists only
/// from an earlier create of it by this enrollment (a run started again,
/// say), since the name carries both, so the create is satisfied and the VM
/// is reported in whatever state it is in now: running, stopped, starting or
/// in error. A second VM can't exist: the name is taken.
fn created(result: Result<(), tonic::Status>) -> Result<(), Attempt> {
    match result {
        Ok(()) => Ok(()),
        Err(status) if status.code() == Code::AlreadyExists => Ok(()),
        Err(status) => Err(ended(status)),
    }
}

/// A journaled operation with this ID must be the same operation: its kind,
/// and for a lifecycle operation its environment.
fn same_operation(journaled: &local::Operation, kind: &Kind) -> Result<(), Failure> {
    let (expected, environment) = match kind {
        Kind::Create(_) => (local::OperationKind::Create, None),
        Kind::Lifecycle(Lifecycle::Start, local_id) => {
            (local::OperationKind::Start, Some(local_id))
        }
        Kind::Lifecycle(Lifecycle::Stop, local_id) => (local::OperationKind::Stop, Some(local_id)),
        Kind::Lifecycle(Lifecycle::Destroy, local_id) => {
            (local::OperationKind::Delete, Some(local_id))
        }
    };
    let same_kind = local::OperationKind::try_from(journaled.kind) == Ok(expected);
    let same_environment =
        environment.is_none_or(|local_id| journaled.environment_id == local_id.to_string());
    if same_kind && same_environment {
        Ok(())
    } else {
        Err(Failure::invalid(
            "this operation ID was used before for a different operation",
        ))
    }
}

async fn apply(
    client: &mut impl Supervisor,
    operation: &Operation,
    lifecycle: Lifecycle,
    local_id: Uuid,
) -> Result<(), Attempt> {
    let environment = match client.get(&operation.vm).await {
        Ok(environment) => environment,
        // Already gone: a destroy is done; anything else has nothing to act on.
        Err(status) if status.code() == Code::NotFound => {
            return match lifecycle {
                Lifecycle::Destroy => Ok(()),
                Lifecycle::Start | Lifecycle::Stop => Err(failed(Failure::new(
                    "environment_absent",
                    "this host no longer has the environment",
                ))),
            };
        }
        Err(status) => return Err(ended(status)),
    };
    check_fence(&environment, local_id, operation.expected_generation)
        .map_err(Attempt::Finished)?;
    let selector = local::EnvironmentSelector {
        name: operation.vm.clone(),
        request_id: operation.id.to_string(),
        environment_id: environment.id.clone(),
        start_with_uncleared_disk: false,
    };
    client.change(lifecycle, selector).await.map_err(ended)
}

/// The host's environment must be the one the control plane names, at the
/// generation it last saw.
fn check_fence(
    environment: &local::Environment,
    local_id: Uuid,
    expected_generation: u64,
) -> Result<(), Outcome> {
    if environment.id != local_id.to_string() {
        return Err(Outcome::Failed(Failure::new(
            "environment_mismatch",
            "this host's environment of that name is a different one",
        )));
    }
    if environment.generation != expected_generation {
        return Err(Outcome::Stale {
            expected: expected_generation,
            current: environment.generation,
        });
    }
    Ok(())
}

/// The project `create` carries, if this host can build it. It asks for
/// nothing from this computer: no image, repositories, credentials, secrets
/// or skills (a skill would copy the owner's own files into the VM), and
/// nothing `cw --local create` refuses.
fn accepted_project(create: &HostCreate) -> Result<codewire_project::ProjectSpec, Failure> {
    let digest = format!("{:x}", Sha256::digest(&create.project_spec_json));
    if digest != create.project_spec_sha256 {
        return Err(Failure::invalid(
            "the project's SHA-256 does not match its JSON",
        ));
    }
    let spec: codewire_project::ProjectSpec = serde_json::from_slice(&create.project_spec_json)
        .map_err(|_| Failure::invalid("the project is not a valid project"))?;
    if !spec.image.is_empty() {
        return Err(Failure::new(
            "unsupported_project",
            "a host runs its own runtime's image; the project must name none",
        ));
    }
    if !spec.repositories.is_empty()
        || spec.credentials.is_some()
        || !spec.secrets.is_empty()
        || !spec.skills.is_empty()
    {
        return Err(Failure::new(
            "unsupported_project",
            "this host cannot yet set up repositories, credentials, secrets or skills; create with an empty workspace",
        ));
    }
    let unsupported = super::super::native::host_create::unsupported_project_fields(&spec, false);
    if !unsupported.is_empty() {
        return Err(Failure::new(
            "unsupported_project",
            format!(
                "a local VM does not support these project fields: {}",
                unsupported.join(", ")
            ),
        ));
    }
    Ok(spec)
}

/// The supervisor's create request, built as `cw --local create` builds it:
/// this host's default image, the empty workspace, and resources matching
/// the VM's size.
fn create_request(
    operation_id: Uuid,
    name: &str,
    create: &HostCreate,
    spec: codewire_project::ProjectSpec,
    (source_path, implicit_path_mode): (String, String),
) -> Result<local::CreateEnvironmentRequest, Failure> {
    let (project_spec_json, project_spec_sha256) =
        super::super::native::canonical_native_project_intent(
            spec,
            create.vcpus,
            create.memory_mib,
            create.disk_bytes,
        )
        .map_err(|error| {
            Failure::local(
                "invalid_operation",
                "the project cannot run on this host",
                &error,
            )
        })?;
    Ok(local::CreateEnvironmentRequest {
        name: name.to_owned(),
        source_path,
        vcpus: create.vcpus,
        memory_mib: create.memory_mib,
        disk_bytes: create.disk_bytes,
        docker_disk_bytes: create.docker_disk_bytes,
        request_id: operation_id.to_string(),
        project_spec_json,
        project_spec_sha256,
        implicit_path_mode,
        ..Default::default()
    })
}

/// The environment as the supervisor has it now, after `operation`. When
/// it is gone, it is reported absent under the host ID the operation named,
/// at the generation the control plane last saw, so the report is not older
/// than the one it replaces.
async fn observe(
    client: &mut impl Supervisor,
    operation: &Operation,
) -> Result<HostEnvironmentObservation, Attempt> {
    match client.get(&operation.vm).await {
        Ok(environment) => Ok(observation(operation.environment_id, &environment)),
        Err(status) if status.code() == Code::NotFound => match operation.kind {
            Kind::Lifecycle(_, local_id) => Ok(HostEnvironmentObservation {
                environment_id: operation.environment_id.to_string(),
                local_environment_id: local_id.to_string(),
                generation: operation.expected_generation,
                state: HostEnvironmentState::HOST_ENVIRONMENT_STATE_ABSENT.into(),
                ..Default::default()
            }),
            // A create that finished leaves a VM; one already gone is lost.
            Kind::Create(_) => Err(failed(Failure::new(
                "environment_absent",
                "the environment was created, then removed from this host",
            ))),
        },
        Err(status) => Err(ended(status)),
    }
}

pub(super) fn observation(
    environment_id: Uuid,
    environment: &local::Environment,
) -> HostEnvironmentObservation {
    let (state, error_code) = match local::EnvironmentState::try_from(environment.state) {
        Ok(local::EnvironmentState::Stopped) => (
            HostEnvironmentState::HOST_ENVIRONMENT_STATE_STOPPED,
            String::new(),
        ),
        Ok(local::EnvironmentState::Starting) => (
            HostEnvironmentState::HOST_ENVIRONMENT_STATE_STARTING,
            String::new(),
        ),
        Ok(local::EnvironmentState::Running) => (
            HostEnvironmentState::HOST_ENVIRONMENT_STATE_RUNNING,
            String::new(),
        ),
        Ok(local::EnvironmentState::Error) if environment.error_code.is_empty() => (
            HostEnvironmentState::HOST_ENVIRONMENT_STATE_ERROR,
            "unknown".to_owned(),
        ),
        Ok(local::EnvironmentState::Error) => (
            HostEnvironmentState::HOST_ENVIRONMENT_STATE_ERROR,
            environment.error_code.clone(),
        ),
        // The supervisor no longer owns its runner, or reports a state this
        // cw does not know: either way, not one the control plane can use.
        Ok(local::EnvironmentState::Orphaned) => (
            HostEnvironmentState::HOST_ENVIRONMENT_STATE_ERROR,
            "orphaned".to_owned(),
        ),
        Ok(local::EnvironmentState::Unspecified) | Err(_) => (
            HostEnvironmentState::HOST_ENVIRONMENT_STATE_ERROR,
            "unknown_state".to_owned(),
        ),
    };
    HostEnvironmentObservation {
        environment_id: environment_id.to_string(),
        local_environment_id: environment.id.clone(),
        generation: environment.generation,
        state: state.into(),
        error_code: bounded(&error_code, MAX_CODE_BYTES),
        vcpus: environment.vcpus,
        memory_mib: environment.memory_mib,
        disk_bytes: environment.disk_bytes,
        ..Default::default()
    }
}

/// Every environment the control plane placed here, as it is now: none when
/// the local VM runtime was never set up.
pub(super) async fn inventory(
    placement: &Placement,
) -> anyhow::Result<Vec<HostEnvironmentObservation>> {
    if !super::super::native::native_state_exists()? {
        return Ok(Vec::new());
    }
    let environments = super::super::native::native_environments().await?;
    Ok(environments
        .iter()
        .filter_map(|environment| {
            placement
                .environment(&environment.name)
                .map(|environment_id| observation(environment_id, environment))
        })
        .collect())
}

#[cfg(test)]
mod tests;
