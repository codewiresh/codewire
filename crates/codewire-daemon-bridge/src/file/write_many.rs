//! `WriteFiles`: many small files in one call (SPEC.md, "File transfer";
//! #5804).
//!
//! Each file is written as an upload is: staged beside its destination, then
//! renamed into place. No file is put in place until every file is staged, so
//! a failure while staging leaves no file in place, though parent folders it
//! made may remain. Once the first rename is issued the call puts the rest in
//! place too, stopping only at a failure, which names the files already
//! written.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use codewire_daemon_proto::DAEMON_CAPABILITY_FILES;
use codewire_proto::codewire::v1 as proto;
use connectrpc::{RequestContext, ServiceRequest, ServiceResult};
use futures::FutureExt as _;
use tokio::sync::oneshot;

use super::admission::{BodyCharge, BodyPermit};
use super::staged::{StagedWrites, UPLOAD_WRITE_BYTES};
use super::{
    FileBackend, FileBridge, MAX_UPLOAD_PATH_BYTES, UPLOAD_MODE, UploadStaging,
    coordinate_violations, ensure_upload_parent, owned_request_id, reserved_upload_path,
    restart_deadline, staging_path, upload_canceled, upload_mutation, worker_reply,
};
use crate::client::{DaemonClient, DaemonClientError, v1};
use crate::drain::RestartSignal;
use crate::session::FieldViolation;

/// The most files one `WriteFiles` call names.
pub const WRITE_FILES_MAX_FILES: usize = 1_000;
/// The most content bytes one `WriteFiles` call carries, all files together.
/// A larger file goes through `UploadFilePart`.
pub const WRITE_FILES_MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024;
/// The largest `WriteFiles` message a server reads: the content as JSON's
/// base64 spells it, since the TypeScript SDK sends JSON, every path at its
/// longest, and room for each file's framing. So the bridge, not the
/// transport, refuses a request over the content limit, and the caller learns
/// which rule it broke.
pub const WRITE_FILES_MAX_MESSAGE_BYTES: usize = WRITE_FILES_MAX_CONTENT_BYTES.div_ceil(3) * 4
    + WRITE_FILES_MAX_FILES * (MAX_UPLOAD_PATH_BYTES + WRITE_FILE_FRAMING_BYTES)
    + 64 * 1024;
const WRITE_FILE_FRAMING_BYTES: usize = 64;
/// Each call may hold 16 MiB until it finishes, so an environment runs at most
/// this many at once in one process, and an organization at most
/// [`MAX_ORGANIZATION_WRITES`] across its environments. Another is refused
/// rather than queued.
const MAX_ENVIRONMENT_WRITES: usize = 2;
const MAX_ORGANIZATION_WRITES: usize = 4;
/// How long a `WriteFiles` worker may spend checking the daemon is ready,
/// staging its files and putting them in place. Writing 16 MiB to an
/// in-cluster daemon takes seconds, so a worker still running after two
/// minutes is stalled, most likely on a daemon
/// the caller's own environment controls; abandoning it releases the body's
/// charge and the call's permits, which it would otherwise hold indefinitely.
pub const WRITE_FILES_WORKER_TIMEOUT: Duration = Duration::from_secs(120);
/// How long an abandoned worker spends removing its staging files. Removal
/// needs only their paths, so it holds neither the charge nor the permits.
const WRITE_FILES_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const NO_BODY_BUDGET: &str = "this server is missing the WriteFiles memory budget";
pub(super) const WRITES_TIMED_OUT: &str = "writing these files did not finish within two minutes, \
     so Codewire stopped";
const WRITES_RESTARTED: &str = "Codewire restarted the server writing these files before any \
     was put in place; no file was written, send them again";
const TOO_MANY_WRITES: &str = "this environment is already writing two batches of files; \
     send this one when one of them finishes";
pub(super) const TOO_MANY_ORGANIZATION_WRITES: &str = "this organization is already writing four batches \
     of files across its environments; send this one when one of them finishes";

/// The route `WriteFiles` is served on, which reads messages up to
/// [`WRITE_FILES_MAX_MESSAGE_BYTES`]; every other file route keeps the
/// transport's default. The daemon's own limit stays as it is, since no daemon
/// message carries more than one [`UPLOAD_WRITE_BYTES`] write; the 16 MiB test
/// in `tests/write_many.rs` runs through the actual daemon server and its
/// limit.
pub(super) fn with_write_files_limit(router: connectrpc::Router) -> connectrpc::Router {
    router.with_route_limits(
        proto::FILE_SERVICE_WRITE_FILES_SPEC.procedure,
        connectrpc::Limits::default()
            .with_max_request_body_size(WRITE_FILES_MAX_MESSAGE_BYTES)
            .with_max_message_size(WRITE_FILES_MAX_MESSAGE_BYTES),
    )
}

/// The most paths a partial-write message names, and the most bytes they may
/// take as the message spells them. A call may have written 999 paths of 4 KiB
/// each, and a message is logged and, for gRPC clients, sent in a trailer, so
/// it counts the rest; the cloud lists every path in the error's `written`
/// metadata.
const WRITTEN_NAMED_FILES: usize = 5;
const WRITTEN_NAMED_BYTES: usize = 1024;

/// The message for a failed `WriteFiles` call that had already put files in
/// place, after the reply's own `message`: how many, and the first few.
pub fn written_files_message(message: Option<&str>, written: &[String]) -> String {
    let mut named = Vec::new();
    let mut bytes = 0;
    for path in written.iter().take(WRITTEN_NAMED_FILES) {
        let spelled = format!("{path:?}");
        bytes += spelled.len();
        if bytes > WRITTEN_NAMED_BYTES {
            break;
        }
        named.push(spelled);
    }
    let count = written.len();
    let files = if count == 1 { "file was" } else { "files were" };
    let mut text = format!(
        "{}; {count} {files} written before it stopped",
        message.unwrap_or("writing the files failed")
    );
    if !named.is_empty() {
        text.push_str(&format!(": {}", named.join(", ")));
        let more = count - named.len();
        if more > 0 {
            text.push_str(&format!(" and {more} more"));
        }
    }
    text
}

/// One file of a request that passed every rule.
struct PlannedFile {
    destination: String,
    staging_path: String,
    content: Vec<u8>,
}

/// A file staged beside its destination, its mode set, not yet in place.
struct StagedFile {
    staging: UploadStaging,
    destination: String,
    size: i64,
}

pub(super) async fn write_files<B: FileBackend>(
    bridge: &FileBridge<B>,
    ctx: RequestContext,
    request: ServiceRequest<'_, proto::WriteFilesRequest>,
) -> ServiceResult<proto::WriteFilesResponse> {
    let backend = &bridge.backend;
    backend.authorize(&ctx)?;
    let request_id = owned_request_id(&ctx);
    let request = request.to_owned_message();
    let mut violations = coordinate_violations(
        &request.org_id,
        &request.environment_id,
        None,
        "/org_id",
        "/environment_id",
        "/files",
    );
    let files = plan(request.files).unwrap_or_else(|refused| {
        violations.extend(refused);
        Vec::new()
    });
    if !violations.is_empty() {
        return Err(backend.validation_error(violations, request_id.as_deref()));
    }
    let daemon = backend
        .daemon(&ctx, &request.org_id, &request.environment_id)
        .await?;
    // Taken only once the backend has admitted the caller to the environment,
    // so a caller without access can never hold its permits.
    let permit = bridge
        .writes
        .try_acquire(&request.org_id, &request.environment_id)
        .map_err(connectrpc::ConnectError::resource_exhausted)?;
    let charge = organization_charge(&ctx, &request.org_id)?;
    // As for UploadFile, the worker owns every issued mutation until its reply
    // or the restart deadline, and the permits until its cleanup is done. At
    // its own deadline it drops both at once and cleans up by path. It holds
    // the decoded files, so it holds the body's charge too, even after the
    // caller leaves; a caller that leaves before this point releases it with
    // the handler.
    let worker = Worker {
        daemon,
        backend: backend.clone(),
        request_id,
        timeout: bridge.write_timeout,
        permit,
        charge,
    };
    let (response_tx, response_rx) = oneshot::channel();
    tokio::spawn(worker.run(files, response_tx));
    worker_reply(response_rx, None).await
}

/// What a `WriteFiles` worker holds besides the files: the daemon, and the
/// call's permits, released when it ends.
struct Worker<B> {
    daemon: DaemonClient,
    backend: B,
    request_id: Option<String>,
    timeout: Duration,
    permit: WritePermit,
    charge: BodyPermit,
}

impl<B: FileBackend> Worker<B> {
    async fn run(
        self,
        files: Vec<PlannedFile>,
        response: oneshot::Sender<ServiceResult<proto::WriteFilesResponse>>,
    ) {
        let staging = files
            .iter()
            .map(|file| file.staging_path.clone())
            .collect::<Vec<_>>();
        let mut written = Vec::new();
        // The readiness check is a daemon call the caller's environment can
        // leave unanswered, so it runs under the deadline with the write.
        let work = async {
            self.daemon
                .require_ready(&[DAEMON_CAPABILITY_FILES])
                .await
                .map_err(|error| self.backend.daemon_error(error, self.request_id.as_deref()))?;
            write_to_daemon(
                self.daemon.clone(),
                files,
                self.backend.clone(),
                self.request_id.clone(),
                &response,
                &mut written,
            )
            .await
        };
        let outcome = tokio::time::timeout(self.timeout, work).await;
        // At the deadline the work is dropped, with the files' contents and
        // every daemon call it had issued; none is left to finish.
        let expired = outcome.is_err();
        let result = outcome.unwrap_or_else(|_| {
            Err(timed_out(
                &self.backend,
                &written,
                self.request_id.as_deref(),
            ))
        });
        // Released before the reply, so the caller's next call is not refused.
        drop(self.permit);
        drop(self.charge);
        // A caller that left has nothing to receive; its staging is cleaned.
        let _ = response.send(result);
        if expired {
            remove_staging(&self.daemon, staging).await;
        }
    }
}

/// The reply to a write abandoned at its deadline, naming the files it had
/// already put in place as a failed write names them.
fn timed_out<B: FileBackend>(
    backend: &B,
    written: &[proto::UploadFileResponse],
    request_id: Option<&str>,
) -> connectrpc::ConnectError {
    if written.is_empty() {
        return connectrpc::ConnectError::deadline_exceeded(WRITES_TIMED_OUT);
    }
    let paths = written
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    let status = tonic::Status::deadline_exceeded(WRITES_TIMED_OUT);
    let mut reply =
        backend.written_files_error(DaemonClientError::Status(status), &paths, request_id);
    reply.code = connectrpc::ErrorCode::DeadlineExceeded;
    reply.message = Some(written_files_message(Some(WRITES_TIMED_OUT), &paths));
    reply
}

/// Removes an abandoned write's staging files by path, within
/// [`WRITE_FILES_CLEANUP_TIMEOUT`], since the daemon may be why the write was
/// abandoned. A staging file never made, or already put in place, is not
/// found, which leaves nothing to remove.
async fn remove_staging(daemon: &DaemonClient, paths: Vec<String>) {
    let removals = async {
        for path in paths {
            // Best effort: a name left behind is a hidden staging file.
            let _ = daemon.remove(v1::RemoveRequest { path, dir: false }).await;
        }
    };
    // Past the deadline the rest are left as hidden staging files.
    let _ = tokio::time::timeout(WRITE_FILES_CLEANUP_TIMEOUT, removals).await;
}

/// The body's charge, taken from the admission that made it and counted in
/// `org_id`'s share too. The organization is named only in the decoded
/// request, so this runs once the backend has admitted the caller to it,
/// before any daemon call. A call over the organization's share is refused,
/// and its charge released at once. A request no admission charged is
/// refused as `internal`: its mount lacks `write_files_admission`, and it
/// would otherwise go unbudgeted.
fn organization_charge(
    ctx: &RequestContext,
    org_id: &str,
) -> Result<BodyPermit, connectrpc::ConnectError> {
    let mut charge = ctx
        .extensions()
        .get::<BodyCharge>()
        .and_then(BodyCharge::take)
        .ok_or_else(|| connectrpc::ConnectError::internal(NO_BODY_BUDGET))?;
    charge
        .charge_organization(org_id)
        .map_err(connectrpc::ConnectError::resource_exhausted)?;
    Ok(charge)
}

/// Checks every rule before anything is written, so a request that breaks
/// one is refused whole.
fn plan(files: Vec<proto::WriteFile>) -> Result<Vec<PlannedFile>, Vec<FieldViolation>> {
    if files.is_empty() || files.len() > WRITE_FILES_MAX_FILES {
        return Err(vec![FieldViolation {
            path: Cow::Borrowed("/files"),
            message: "must name 1 to 1,000 files",
        }]);
    }
    let mut violations = Vec::new();
    let total = files
        .iter()
        .try_fold(0_usize, |total, file| total.checked_add(file.content.len()));
    if total.is_none_or(|total| total > WRITE_FILES_MAX_CONTENT_BYTES) {
        violations.push(FieldViolation {
            path: Cow::Borrowed("/files"),
            message: "must hold at most 16 MiB of content in all",
        });
    }
    let mut named = HashSet::with_capacity(files.len());
    let mut planned = Vec::with_capacity(files.len());
    for (index, file) in files.into_iter().enumerate() {
        match plan_file(&file.path, &mut named) {
            Ok((destination, staging_path)) => planned.push(PlannedFile {
                destination,
                staging_path,
                content: file.content,
            }),
            Err(message) => violations.push(FieldViolation {
                path: Cow::Owned(format!("/files/{index}/path")),
                message,
            }),
        }
    }
    if violations.is_empty() {
        Ok(planned)
    } else {
        Err(violations)
    }
}

/// One path's destination and staging name, by the rules `UploadFile`
/// applies, plus that it is absolute and names no file an earlier path did.
fn plan_file(path: &str, named: &mut HashSet<PathBuf>) -> Result<(String, String), &'static str> {
    let destination = path.trim();
    if destination.is_empty() {
        return Err("must not be empty");
    }
    if reserved_upload_path(destination) {
        return Err("uses a reserved internal name");
    }
    if !Path::new(destination).is_absolute() {
        return Err("must be an absolute path");
    }
    let staging = staging_path(destination).map_err(|violation| violation.message)?;
    if !named.insert(lexical(destination)) {
        return Err("names the same file as an earlier path");
    }
    Ok((destination.to_owned(), staging))
}

/// `path` with `.` and `..` resolved by name, as the daemon resolves it, so
/// two spellings of one file are seen as one.
fn lexical(path: &str) -> PathBuf {
    let mut resolved = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            other => resolved.push(other),
        }
    }
    resolved
}

/// Stages every file, then puts each in place in the request's order, adding
/// each to `written` once it is in place.
async fn write_to_daemon<B: FileBackend>(
    daemon: DaemonClient,
    files: Vec<PlannedFile>,
    backend: B,
    request_id: Option<String>,
    response: &oneshot::Sender<ServiceResult<proto::WriteFilesResponse>>,
    written: &mut Vec<proto::UploadFileResponse>,
) -> ServiceResult<proto::WriteFilesResponse> {
    let request_id = request_id.as_deref();
    let mut interrupt = Interrupt {
        response,
        restart: restart_deadline(&backend),
    };
    let mut staged = Vec::with_capacity(files.len());
    for file in files {
        match stage_file(&daemon, file, &backend, request_id, &mut interrupt).await {
            Ok(file) => staged.push(file),
            Err(error) => {
                abort_staged(staged).await;
                return Err(error);
            }
        }
    }
    if let Err(error) = interrupt.check() {
        abort_staged(staged).await;
        return Err(error);
    }
    put_in_place(staged, &backend, request_id, written).await
}

/// Stages one file as an upload stages it. On any failure its own staging
/// file is removed before the error returns.
async fn stage_file<B: FileBackend>(
    daemon: &DaemonClient,
    file: PlannedFile,
    backend: &B,
    request_id: Option<&str>,
    interrupt: &mut Interrupt<'_>,
) -> Result<StagedFile, connectrpc::ConnectError> {
    interrupt.check()?;
    ensure_upload_parent(daemon, &file.staging_path, backend, request_id).await?;
    interrupt.check()?;
    upload_mutation(daemon.open_file(v1::OpenFileRequest {
        path: file.staging_path.clone(),
        options: Some(v1::FileOpenOptions {
            write: true,
            create: true,
            truncate: true,
            exclusive: true,
            ..Default::default()
        }),
        perm: 0o600,
    }))
    .await
    .map_err(|error| backend.daemon_error(error, request_id))?;
    let mut staging = UploadStaging::new(daemon.clone(), file.staging_path);
    match fill_staging(&staging, &file.content, backend, request_id, interrupt).await {
        Ok(size) => Ok(StagedFile {
            staging,
            destination: file.destination,
            size,
        }),
        Err(error) => {
            staging.abort().await;
            Err(error)
        }
    }
}

/// Writes `content` to the staging file and sets its mode, returning the
/// bytes written.
async fn fill_staging<B: FileBackend>(
    staging: &UploadStaging,
    content: &[u8],
    backend: &B,
    request_id: Option<&str>,
    interrupt: &mut Interrupt<'_>,
) -> Result<i64, connectrpc::ConnectError> {
    let daemon_error = |error| backend.daemon_error(error, request_id);
    let mut writes = StagedWrites::new(staging.path().to_owned(), 0);
    for chunk in content.chunks(UPLOAD_WRITE_BYTES) {
        interrupt.check()?;
        writes
            .push(&staging.client, chunk)
            .await
            .map_err(daemon_error)?;
    }
    writes.flush(&staging.client).await.map_err(daemon_error)?;
    interrupt.check()?;
    upload_mutation(staging.client.set_stat(v1::SetStatRequest {
        path: staging.path().to_owned(),
        mode: Some(UPLOAD_MODE),
        ..Default::default()
    }))
    .await
    .map_err(daemon_error)?;
    Ok(writes.written())
}

/// Renames each staged file into place in order, adding each to `written`.
/// At the first failure the rest are abandoned and the error names the files
/// already written.
async fn put_in_place<B: FileBackend>(
    staged: Vec<StagedFile>,
    backend: &B,
    request_id: Option<&str>,
    written: &mut Vec<proto::UploadFileResponse>,
) -> ServiceResult<proto::WriteFilesResponse> {
    let mut pending = staged.into_iter();
    while let Some(mut file) = pending.next() {
        let renamed = upload_mutation(file.staging.client.rename(v1::RenameRequest {
            old_path: file.staging.path().to_owned(),
            new_path: file.destination.clone(),
        }))
        .await;
        if let Err(error) = renamed {
            file.staging.abort().await;
            abort_staged(pending.collect()).await;
            if written.is_empty() {
                return Err(backend.daemon_error(error, request_id));
            }
            let written = written
                .iter()
                .map(|file| file.path.clone())
                .collect::<Vec<_>>();
            return Err(backend.written_files_error(error, &written, request_id));
        }
        file.staging.commit();
        written.push(proto::UploadFileResponse {
            path: file.destination,
            size: file.size,
            ..Default::default()
        });
    }
    connectrpc::Response::ok(proto::WriteFilesResponse {
        files: std::mem::take(written),
        ..Default::default()
    })
}

async fn abort_staged(staged: Vec<StagedFile>) {
    for mut file in staged {
        file.staging.abort().await;
    }
}

/// The public request's cancellation and the server's restart deadline,
/// observed between daemon mutations and never by dropping an issued one.
/// Only the worker's own deadline drops an issued mutation.
struct Interrupt<'a> {
    response: &'a oneshot::Sender<ServiceResult<proto::WriteFilesResponse>>,
    restart: RestartSignal,
}

impl Interrupt<'_> {
    fn check(&mut self) -> Result<(), connectrpc::ConnectError> {
        if self.response.is_closed() {
            return Err(upload_canceled());
        }
        if (&mut self.restart).now_or_never().is_some() {
            // A completed future is never polled again.
            self.restart = Box::pin(std::future::pending());
            return Err(connectrpc::ConnectError::unavailable(WRITES_RESTARTED));
        }
        Ok(())
    }
}

/// How many `WriteFiles` calls run for each organization and each environment
/// in this process.
#[derive(Clone, Default)]
pub(super) struct WriteLimiter {
    running: Arc<Mutex<Running>>,
}

#[derive(Default)]
struct Running {
    organizations: HashMap<String, usize>,
    environments: HashMap<(String, String), usize>,
}

impl WriteLimiter {
    /// A permit to run one call, or the reason it is refused: the environment
    /// already runs [`MAX_ENVIRONMENT_WRITES`] or its organization
    /// [`MAX_ORGANIZATION_WRITES`]. Dropping the permit releases both.
    pub(super) fn try_acquire(
        &self,
        org_id: &str,
        environment_id: &str,
    ) -> Result<WritePermit, &'static str> {
        let environment = (org_id.to_owned(), environment_id.to_owned());
        // A panic while holding the lock cannot leave a count half-changed.
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        if running.environments.get(&environment).copied().unwrap_or(0) >= MAX_ENVIRONMENT_WRITES {
            return Err(TOO_MANY_WRITES);
        }
        if running.organizations.get(org_id).copied().unwrap_or(0) >= MAX_ORGANIZATION_WRITES {
            return Err(TOO_MANY_ORGANIZATION_WRITES);
        }
        *running.environments.entry(environment.clone()).or_default() += 1;
        *running.organizations.entry(org_id.to_owned()).or_default() += 1;
        Ok(WritePermit {
            running: Arc::clone(&self.running),
            environment,
        })
    }
}

pub(super) struct WritePermit {
    running: Arc<Mutex<Running>>,
    environment: (String, String),
}

impl Drop for WritePermit {
    fn drop(&mut self) {
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        release(&mut running.environments, &self.environment);
        release(&mut running.organizations, &self.environment.0);
    }
}

/// Takes one from `key`'s count, removing a count that reaches zero so the map
/// holds only what runs.
fn release<K, Q>(counts: &mut HashMap<K, usize>, key: &Q)
where
    K: std::borrow::Borrow<Q> + std::hash::Hash + Eq,
    Q: std::hash::Hash + Eq + ?Sized,
{
    if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(key);
        }
    }
}
