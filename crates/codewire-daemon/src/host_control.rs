//! Target-owned control for a Linux trusted-host environment.
//!
//! This is private owner-token IPC. Only the authenticated host-peer adapter
//! may delegate a network principal; network callers never choose that identity
//! or receive the daemon token. Grant administration is local owner IPC only.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use codewire_daemon_proto::daemon::v1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex as AsyncMutex, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use uuid::Uuid;

use crate::durable_session::SessionEngine;

pub(crate) mod managed;
mod service;
mod store;
#[cfg(test)]
pub(crate) mod tests;

pub(crate) use service::HostControlService;
use store::Store;

pub const HOST_CONTROL_PROTOCOL: u32 = 1;
pub const HOST_CONTROL_MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const HOST_CONTROL_MAX_OUTPUT_BYTES: u64 = 256 * 1024;
const MAX_IN_FLIGHT: usize = 16;
const OWNER_DRAIN_TIMEOUT: Duration = Duration::from_secs(50);

/// Canonical saved host identity supplied by its owning lifecycle, not inferred
/// from a mutable name, directory or remote request.
#[derive(Clone)]
pub struct HostControlBinding {
    environment_id: String,
    managed_agents: bool,
}

impl HostControlBinding {
    pub fn new(environment_id: String) -> Result<Self, tonic::Status> {
        canonical_uuid(&environment_id).map_err(Error::status)?;
        Ok(Self {
            environment_id,
            managed_agents: false,
        })
    }

    /// Only a cw-bearing host owner implements the fixed private helper role.
    /// Standalone/library owners remain terminal-only without an executable fallback.
    pub fn with_managed_agents(mut self) -> Self {
        self.managed_agents = true;
        self
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("invalid host control request")]
    Invalid,
    #[error("host control grant or session ownership was refused")]
    Denied,
    #[error("host control identity or revision conflicts")]
    Conflict,
    #[error("host control capacity is exhausted")]
    Capacity,
    #[error("host control storage is unavailable; retain the original request")]
    Storage,
    #[error("host control owner is shutting down")]
    Closed,
    #[error("host control session generation or process is unavailable")]
    Unavailable,
}

impl Error {
    fn status(self) -> tonic::Status {
        let text = self.to_string();
        match self {
            Self::Invalid => tonic::Status::invalid_argument(text),
            Self::Denied => tonic::Status::permission_denied(text),
            Self::Conflict => tonic::Status::failed_precondition(text),
            Self::Capacity => tonic::Status::resource_exhausted(text),
            Self::Storage | Self::Unavailable => tonic::Status::unavailable(text),
            Self::Closed => tonic::Status::failed_precondition(text),
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Invalid => "invalid_request",
            Self::Denied => "grant_or_origin_refused",
            Self::Conflict => "identity_or_revision_conflict",
            Self::Capacity => "capacity_exhausted",
            Self::Storage => "storage_unknown",
            Self::Closed => "owner_closed",
            Self::Unavailable => "generation_or_process_unavailable",
        }
    }
}

pub(crate) fn canonical_uuid(value: &str) -> Result<(), Error> {
    let id = Uuid::parse_str(value).map_err(|_| Error::Invalid)?;
    if id.is_nil() || id.to_string() != value {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn identifier(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

pub(crate) fn session_id(value: &str) -> Result<(), Error> {
    canonical_uuid(value.strip_prefix("session-").ok_or(Error::Invalid)?)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scope {
    pub environment_id: String,
    pub org_id: String,
    pub network_id: String,
    pub caller_key: [u8; 32],
    pub target_key: [u8; 32],
    pub grant_id: String,
    pub grant_revision: u64,
}

impl Scope {
    pub(crate) fn from_wire(value: v1::HostControlScope) -> Result<Self, Error> {
        let scope = Self {
            environment_id: value.environment_id,
            org_id: value.org_id,
            network_id: value.network_id,
            caller_key: value.caller_key.try_into().map_err(|_| Error::Invalid)?,
            target_key: value.target_key.try_into().map_err(|_| Error::Invalid)?,
            grant_id: value.grant_id,
            grant_revision: value.expected_grant_revision,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        canonical_uuid(&self.environment_id)?;
        canonical_uuid(&self.grant_id)?;
        identifier(&self.org_id)?;
        identifier(&self.network_id)?;
        if self.grant_revision == 0 || self.caller_key == [0; 32] || self.target_key == [0; 32] {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub(crate) fn same_principal(&self, other: &Self) -> bool {
        self.environment_id == other.environment_id
            && self.org_id == other.org_id
            && self.network_id == other.network_id
            && self.caller_key == other.caller_key
            && self.target_key == other.target_key
            && self.grant_id == other.grant_id
    }

    pub(crate) fn to_wire(&self) -> v1::HostControlScope {
        v1::HostControlScope {
            environment_id: self.environment_id.clone(),
            org_id: self.org_id.clone(),
            network_id: self.network_id.clone(),
            caller_key: self.caller_key.to_vec(),
            target_key: self.target_key.to_vec(),
            grant_id: self.grant_id.clone(),
            expected_grant_revision: self.grant_revision,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Origin {
    pub request_id: String,
    pub fingerprint: String,
    pub scope: Scope,
}

impl Origin {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        canonical_uuid(&self.request_id)?;
        valid_sha256(&self.fingerprint)?;
        self.scope.validate()
    }
}

pub(crate) fn valid_sha256(value: &str) -> Result<(), Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

// Deliberately no Debug/Serialize: stdin and command arguments are held only by
// the original owning task, never by this request journal or its diagnostics.
#[derive(Clone)]
pub(crate) enum Operation {
    Launch(v1::HostControlLaunch),
    Input(v1::HostControlInput),
    Stop(v1::HostControlStop),
    ManagedLaunch(v1::HostControlManagedLaunch),
    ManagedControl(v1::HostControlManagedControl),
}

#[derive(Clone)]
pub(crate) struct Mutation {
    pub request_id: String,
    pub scope: Scope,
    pub fingerprint: String,
    pub operation: Operation,
}

impl Mutation {
    pub(crate) fn from_wire(value: v1::HostControlMutationRequest) -> Result<Self, Error> {
        canonical_uuid(&value.request_id)?;
        let scope = Scope::from_wire(value.scope.ok_or(Error::Invalid)?)?;
        let operation = match value.operation.ok_or(Error::Invalid)? {
            v1::host_control_mutation_request::Operation::Launch(request) => {
                if request.command.is_empty()
                    || request.command.len() > 128
                    || request.command[0].trim().is_empty()
                    || request
                        .command
                        .iter()
                        .any(|v| v.len() > 4096 || v.contains('\0'))
                    || request.command.iter().map(|v| v.len() + 1).sum::<usize>() > 64 * 1024
                    || request.working_dir.len() > 4096
                    || request.working_dir.contains('\0')
                    || (!request.working_dir.is_empty()
                        && !std::path::Path::new(&request.working_dir).is_absolute())
                    || !codewire_daemon_proto::valid_session_name(&request.name)
                    || request.term.len() > 64
                    || request.term.chars().any(char::is_control)
                    || !(0..=4096).contains(&request.width)
                    || !(0..=4096).contains(&request.height)
                {
                    return Err(Error::Invalid);
                }
                Operation::Launch(request)
            }
            v1::host_control_mutation_request::Operation::Input(request) => {
                session_id(&request.session_id)?;
                if request.expected_launch_generation == 0
                    || request.data.is_empty()
                    || request.data.len() > codewire_daemon_proto::SESSION_INPUT_MAX_BYTES
                {
                    return Err(Error::Invalid);
                }
                Operation::Input(request)
            }
            v1::host_control_mutation_request::Operation::Stop(request) => {
                session_id(&request.session_id)?;
                if request.expected_launch_generation == 0 {
                    return Err(Error::Invalid);
                }
                Operation::Stop(request)
            }
            v1::host_control_mutation_request::Operation::ManagedLaunch(request) => {
                managed::validate_launch(&request)?;
                Operation::ManagedLaunch(request)
            }
            v1::host_control_mutation_request::Operation::ManagedControl(request) => {
                managed::validate_control(&request)?;
                Operation::ManagedControl(request)
            }
        };
        let mut request = Self {
            request_id: value.request_id,
            scope,
            fingerprint: String::new(),
            operation,
        };
        request.fingerprint = request.make_fingerprint();
        Ok(request)
    }

    pub(crate) fn verb(&self) -> v1::HostControlVerb {
        match self.operation {
            Operation::Launch(_) => v1::HostControlVerb::Launch,
            Operation::Input(_) => v1::HostControlVerb::Input,
            Operation::Stop(_) => v1::HostControlVerb::Stop,
            Operation::ManagedLaunch(_) => v1::HostControlVerb::ManagedLaunch,
            Operation::ManagedControl(ref value) => managed::verb(value),
        }
    }

    pub(crate) fn origin(&self) -> Origin {
        Origin {
            request_id: self.request_id.clone(),
            fingerprint: self.fingerprint.clone(),
            scope: self.scope.clone(),
        }
    }

    fn make_fingerprint(&self) -> String {
        fn part(hash: &mut Sha256, bytes: &[u8]) {
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        let mut hash = Sha256::new();
        hash.update(b"codewire.host-control.request.v1\0");
        for value in [
            &self.request_id,
            &self.scope.environment_id,
            &self.scope.org_id,
            &self.scope.network_id,
            &self.scope.grant_id,
        ] {
            part(&mut hash, value.as_bytes());
        }
        hash.update(self.scope.caller_key);
        hash.update(self.scope.target_key);
        hash.update(self.scope.grant_revision.to_le_bytes());
        hash.update((self.verb() as i32).to_le_bytes());
        match &self.operation {
            Operation::Launch(request) => {
                hash.update((request.command.len() as u64).to_le_bytes());
                for argument in &request.command {
                    part(&mut hash, argument.as_bytes());
                }
                for value in [&request.working_dir, &request.term, &request.name] {
                    part(&mut hash, value.as_bytes());
                }
                hash.update([u8::from(request.pty)]);
                hash.update(request.width.to_le_bytes());
                hash.update(request.height.to_le_bytes());
            }
            Operation::Input(request) => {
                part(&mut hash, request.session_id.as_bytes());
                hash.update(request.expected_launch_generation.to_le_bytes());
                part(&mut hash, &request.data);
            }
            Operation::Stop(request) => {
                part(&mut hash, request.session_id.as_bytes());
                hash.update(request.expected_launch_generation.to_le_bytes());
            }
            Operation::ManagedLaunch(request) => {
                use prost::Message;
                part(&mut hash, &request.encode_to_vec());
            }
            Operation::ManagedControl(request) => {
                use prost::Message;
                part(&mut hash, &request.encode_to_vec());
            }
        }
        format!("{:x}", hash.finalize())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Receipt {
    pub origin: Origin,
    pub verb: i32,
    pub phase: i32,
    pub session_id: String,
    pub generation: u64,
    pub session_state: i32,
    pub exit_code: Option<i32>,
    pub cleanup_unknown: bool,
    pub input_acknowledged: bool,
    pub reason: String,
    #[serde(default)]
    pub driver_id: String,
    #[serde(default)]
    pub message_id: String,
    #[serde(default)]
    pub requested_generation: u64,
}

impl Receipt {
    pub(crate) fn pending(request: &Mutation) -> Self {
        let (session_id, generation) = match &request.operation {
            Operation::Launch(_) | Operation::ManagedLaunch(_) => {
                (format!("session-{}", request.request_id), 1)
            }
            Operation::Input(value) => (value.session_id.clone(), value.expected_launch_generation),
            Operation::Stop(value) => (value.session_id.clone(), value.expected_launch_generation),
            Operation::ManagedControl(value) => {
                (value.session_id.clone(), value.expected_launch_generation)
            }
        };
        let (driver_id, message_id) = match &request.operation {
            Operation::ManagedLaunch(value) => (
                request.request_id.clone(),
                value
                    .prompt
                    .as_ref()
                    .map(|_| request.request_id.clone())
                    .unwrap_or_default(),
            ),
            Operation::ManagedControl(value) => (
                value.driver_id.clone(),
                if matches!(
                    v1::HostManagedAction::try_from(value.action),
                    Ok(v1::HostManagedAction::Message
                        | v1::HostManagedAction::Steer
                        | v1::HostManagedAction::Interrupt)
                ) {
                    request.request_id.clone()
                } else {
                    String::new()
                },
            ),
            _ => (String::new(), String::new()),
        };
        Self {
            origin: request.origin(),
            verb: request.verb() as i32,
            phase: v1::HostControlRequestPhase::Pending as i32,
            session_id,
            generation,
            session_state: v1::SessionLifecycleState::Unspecified as i32,
            exit_code: None,
            cleanup_unknown: false,
            input_acknowledged: false,
            reason: "pending".into(),
            driver_id,
            message_id,
            requested_generation: generation,
        }
    }

    pub(crate) fn unsettled(&self) -> bool {
        matches!(
            v1::HostControlRequestPhase::try_from(self.phase),
            Ok(v1::HostControlRequestPhase::Pending | v1::HostControlRequestPhase::Issued)
        )
    }

    pub(crate) fn to_wire(&self) -> v1::HostControlReceipt {
        v1::HostControlReceipt {
            request_id: self.origin.request_id.clone(),
            scope: Some(self.origin.scope.to_wire()),
            fingerprint_sha256: self.origin.fingerprint.clone(),
            verb: self.verb,
            phase: self.phase,
            session_id: self.session_id.clone(),
            launch_generation: self.generation,
            session_state: self.session_state,
            exit_code: self.exit_code,
            cleanup_unknown: self.cleanup_unknown,
            input_acknowledged: self.input_acknowledged,
            reason: self.reason.clone(),
            driver_id: self.driver_id.clone(),
            message_id: self.message_id.clone(),
        }
    }
}

struct State {
    store: Store,
    live: BTreeMap<String, watch::Sender<Receipt>>,
}

struct Inner {
    engine: SessionEngine,
    state: AsyncMutex<State>,
    // Registration and owner shutdown share this short synchronous gate. No
    // await separates durable Pending from spawning its sole target task.
    admission: Mutex<()>,
    tasks: TaskTracker,
    shutdown: CancellationToken,
    environment_id: String,
    managed_agents: bool,
}

#[derive(Clone)]
pub(crate) struct Owner(Arc<Inner>);

pub(crate) struct CloseGuard(Owner);

impl Drop for CloseGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

impl Owner {
    pub(crate) async fn new(
        config: &crate::Config,
        binding: HostControlBinding,
        engine: SessionEngine,
    ) -> Result<Self, Error> {
        let host = config.host.as_ref().ok_or(Error::Denied)?;
        config.validate_host().map_err(|_| Error::Denied)?;
        let store = Store::open(&host.state_root, &binding.environment_id)?;
        engine
            .initialize_host_control()
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(Self(Arc::new(Inner {
            engine,
            state: AsyncMutex::new(State {
                store,
                live: BTreeMap::new(),
            }),
            admission: Mutex::new(()),
            tasks: TaskTracker::new(),
            shutdown: CancellationToken::new(),
            environment_id: binding.environment_id,
            managed_agents: binding.managed_agents,
        })))
    }

    pub(crate) fn environment_id(&self) -> &str {
        &self.0.environment_id
    }
    pub(crate) fn managed_agents(&self) -> bool {
        self.0.managed_agents
    }
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.0.shutdown.clone()
    }
    pub(crate) fn close_on_drop(&self) -> CloseGuard {
        CloseGuard(self.clone())
    }

    pub(crate) fn close(&self) {
        let _gate = self.0.admission.lock().unwrap_or_else(|e| e.into_inner());
        self.0.shutdown.cancel();
        self.0.tasks.close();
    }

    pub(crate) async fn drain(&self) -> Result<(), Error> {
        self.close();
        tokio::time::timeout(OWNER_DRAIN_TIMEOUT, self.0.tasks.wait())
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }

    pub(crate) async fn mutate(&self, request: Mutation) -> Result<Receipt, Error> {
        if managed::is_managed(request.verb() as i32) && !self.managed_agents() {
            return Err(Error::Unavailable);
        }
        let (mut receiver, admitted) = {
            let mut state = self.0.state.lock().await;
            let _gate = self.0.admission.lock().unwrap_or_else(|e| e.into_inner());
            if self.0.shutdown.is_cancelled() {
                return Err(Error::Closed);
            }
            if let Some(existing) = state.store.find(&request.request_id)? {
                if existing.origin != request.origin() {
                    return Err(Error::Conflict);
                }
                match state.live.get(&request.request_id) {
                    Some(sender) => (sender.subscribe(), existing),
                    None => return Ok(existing),
                }
            } else {
                if state.live.len() >= MAX_IN_FLIGHT {
                    return Err(Error::Capacity);
                }
                let pending = state.store.register(&request)?;
                let (sender, receiver) = watch::channel(pending.clone());
                state.live.insert(request.request_id.clone(), sender);
                let owner = self.clone();
                self.0.tasks.spawn(async move {
                    owner.execute(request).await;
                });
                (receiver, pending)
            }
        };
        // A zero join (a test bound only) replies with the receipt as
        // admitted, never waits, and never reads the live one: `execute`
        // cannot settle while the state lock above is held, so this reply
        // always precedes the settle. `tokio::time::timeout` polls its future
        // before its deadline, so a zero timeout could still return a settled
        // receipt under load (#3774).
        let rpc_join = self.0.engine.host_bounds().rpc_join;
        if rpc_join.is_zero() {
            return Ok(admitted);
        }
        // The RPC merely joins the target task. Dropping/timing out this waiter
        // has no cancellation, journal removal, or second-effect authority.
        let joined = async {
            loop {
                let receipt = receiver.borrow().clone();
                if !receipt.unsettled() {
                    return receipt;
                }
                if receiver.changed().await.is_err() {
                    return receiver.borrow().clone();
                }
            }
        };
        match tokio::time::timeout(rpc_join, joined).await {
            Ok(receipt) => Ok(receipt),
            Err(_) => Ok(receiver.borrow().clone()),
        }
    }

    async fn execute(&self, request: Mutation) {
        let result = self
            .0
            .engine
            .execute_host_control(self.clone(), request.clone())
            .await;
        let mut state = self.0.state.lock().await;
        let receipt = state.store.finish(&request, result);
        if let Some(sender) = state.live.remove(&request.request_id) {
            match receipt {
                Ok(receipt) => {
                    sender.send_replace(receipt);
                }
                Err(_) => {
                    // Persistence failure is never an ACK. The original
                    // admitted request remains fenced and is never retried.
                    let mut receipt = Receipt::pending(&request);
                    receipt.phase = v1::HostControlRequestPhase::Unknown as i32;
                    receipt.reason = "storage_unknown".into();
                    receipt.cleanup_unknown = true;
                    sender.send_replace(receipt);
                }
            }
        }
    }

    /// Called only under the authoritative session/retention guards.
    pub(crate) async fn issue(&self, request: &Mutation) -> Result<(), Error> {
        let mut state = self.0.state.lock().await;
        if self.0.shutdown.is_cancelled() {
            return Err(Error::Closed);
        }
        let receipt = state.store.issue(request)?;
        if let Some(sender) = state.live.get(&request.request_id) {
            sender.send_replace(receipt);
        }
        Ok(())
    }

    pub(crate) async fn publish_session(
        &self,
        request: &Mutation,
        metadata: &[u8],
    ) -> Result<(), Error> {
        self.0
            .state
            .lock()
            .await
            .store
            .publish_session(request, metadata)
    }

    pub(crate) async fn observe(&self, request_id: &str, scope: &Scope) -> Result<Receipt, Error> {
        canonical_uuid(request_id)?;
        scope.validate()?;
        if scope.environment_id != self.0.environment_id {
            return Err(Error::Denied);
        }
        let state = self.0.state.lock().await;
        let receipt = state.store.find(request_id)?.ok_or(Error::Unavailable)?;
        if receipt.origin.scope != *scope {
            return Err(Error::Denied);
        }
        Ok(receipt)
    }

    pub(crate) async fn grants(&self) -> Result<v1::HostControlGrantsResponse, Error> {
        self.0.state.lock().await.store.grants()
    }
    pub(crate) async fn put_grant(
        &self,
        request: v1::HostControlPutGrantRequest,
    ) -> Result<v1::HostControlGrantsResponse, Error> {
        if self.0.shutdown.is_cancelled() {
            return Err(Error::Closed);
        }
        self.0.state.lock().await.store.put_grant(request)
    }
    pub(crate) async fn revoke_grant(
        &self,
        request: v1::HostControlRevokeGrantRequest,
    ) -> Result<v1::HostControlGrantsResponse, Error> {
        if self.0.shutdown.is_cancelled() {
            return Err(Error::Closed);
        }
        self.0.state.lock().await.store.revoke_grant(request)
    }
    pub(crate) async fn authorize_read(&self, scope: &Scope) -> Result<(), Error> {
        self.0
            .state
            .lock()
            .await
            .store
            .authorize(scope, v1::HostControlVerb::Read)
    }
    pub(crate) async fn list(&self, scope: &Scope) -> Result<Vec<v1::SessionRecord>, Error> {
        self.authorize_read(scope).await?;
        self.0.engine.list_host_control(scope).await
    }
    pub(crate) async fn get(
        &self,
        scope: &Scope,
        session: &str,
    ) -> Result<v1::SessionRecord, Error> {
        self.authorize_read(scope).await?;
        self.0.engine.get_host_control(scope, session).await
    }
    pub(crate) async fn output(
        &self,
        scope: &Scope,
        request: v1::ReadSessionOutputRequest,
    ) -> Result<v1::ReadSessionOutputResponse, Error> {
        self.authorize_read(scope).await?;
        self.0
            .engine
            .get_host_control(scope, &request.session_id)
            .await?;
        self.0
            .engine
            .read_output(request)
            .await
            .map_err(|_| Error::Unavailable)
    }
    pub(crate) async fn read_managed(
        &self,
        request: &v1::HostControlManagedReadRequest,
        scope: &Scope,
    ) -> Result<Vec<u8>, Error> {
        self.authorize_managed_read(scope).await?;
        self.0.engine.read_host_managed(self, request, scope).await
    }
    pub(crate) async fn authorize_managed_read(&self, scope: &Scope) -> Result<(), Error> {
        if !self.managed_agents() {
            return Err(Error::Unavailable);
        }
        self.0
            .state
            .lock()
            .await
            .store
            .authorize(scope, v1::HostControlVerb::ManagedRead)
    }
}
