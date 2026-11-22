//! Local environment lifecycle results: the start/create summary and its
//! working context, stop and remove outcomes, and failures that name the
//! stage that stopped.

use codewire_project::{ProjectSpec, StoragePlacement};

use super::*;
use crate::commands::lifecycle_output::{
    Already, InterruptNotice, ResultBlock, already_line, bounded, credential_ref,
    environment_command, exact_reference_id, location_label, next_shell_command, print_context,
    print_summary, secret_refs,
};
use crate::output::{
    Allocation, Capabilities, LifecycleSummary, MeshPlacement, NetworkRef, Outcome, SourceRef,
    Status, Style, VmLocation, render_next,
};

/// The stored source selection, when the environment reports a valid one.
fn stored_spec(environment: &v1::Environment) -> Option<ProjectSpec> {
    (!environment.project_spec_json.is_empty())
        .then(|| sources::project_from_environment(environment).ok())
        .flatten()
}

/// The saved Mesh attachment: a network on the platform's hosted Mesh reads
/// `cloud:NAME`, one on a self-managed local Mesh `local:NAME`. Not a
/// connectivity claim.
pub(crate) fn network_ref(mesh: Option<&v1::MeshAttachment>) -> NetworkRef {
    let Some(mesh) = mesh else {
        return NetworkRef::NotAttached;
    };
    let network = mesh.network_id.trim();
    if network.is_empty() {
        return NetworkRef::NotAttached;
    }
    let placement = match v1::MeshEnrollmentAuthSource::try_from(mesh.auth_source) {
        Ok(v1::MeshEnrollmentAuthSource::HostedCurrent) => MeshPlacement::Cloud,
        Ok(v1::MeshEnrollmentAuthSource::StandaloneLocal) => MeshPlacement::Local,
        // Every stored attachment names its owner store; an unknown one is
        // still attached, and the local supervisor owns it.
        _ => MeshPlacement::Local,
    };
    NetworkRef::Attached {
        mesh: placement,
        network: network.to_owned(),
    }
}

/// The credential profile an environment selected, by name: the stored
/// reference's placement and the logical `access_profile` it reports.
pub(super) fn environment_credentials(
    environment: &v1::Environment,
    spec: Option<&ProjectSpec>,
) -> SourceRef {
    let reported = Some(environment.access_profile.as_str()).filter(|name| !name.is_empty());
    match spec {
        Some(spec) => credential_ref(
            spec.credentials
                .as_ref()
                .map(|binding| binding.profile.as_str()),
            reported,
        ),
        None => reported.map_or(SourceRef::None, |name| {
            SourceRef::Unresolved(name.to_owned())
        }),
    }
}

/// The credential profile a local VM selected, by name, read from its own
/// metadata: the lifecycle summary's rendering, for inventory rows.
pub(crate) fn local_vm_credentials(environment: &v1::Environment) -> SourceRef {
    environment_credentials(environment, stored_spec(environment).as_ref())
}

/// A summary of `environment` with the secrets reference the caller
/// resolved.
pub(super) fn local_summary(
    environment: &v1::Environment,
    outcome: Outcome,
    secrets: SourceRef,
) -> LifecycleSummary {
    let spec = stored_spec(environment);
    LifecycleSummary {
        outcome,
        name: environment.name.clone(),
        location: VmLocation::Local,
        allocation: Allocation::local(
            environment.vcpus,
            environment.memory_mib,
            environment.disk_bytes,
        ),
        credentials: environment_credentials(environment, spec.as_ref()),
        credentials_note: super::error_view::InterceptionView::of(environment)
            .and_then(super::error_view::InterceptionView::note),
        secrets,
        network: network_ref(environment.mesh.as_ref()),
        policy: None,
        next: Some(next_shell_command(VmLocation::Local, &environment.name)),
    }
}

/// The application-secret sources an environment selected, naming its
/// project through the store that holds it. Best effort: an unreachable
/// store or a missing project shows the stored reference.
pub(super) async fn environment_secrets(
    globals: &Globals,
    environment: &v1::Environment,
) -> SourceRef {
    let Some(spec) = stored_spec(environment) else {
        return SourceRef::None;
    };
    let name = match exact_reference_id(&spec.secrets.project) {
        Some((placement, id)) => bounded(secret_project_name(globals, environment, placement, id))
            .await
            .flatten(),
        None => None,
    };
    secret_refs(&spec.secrets, name.as_deref())
}

async fn secret_project_name(
    globals: &Globals,
    environment: &v1::Environment,
    placement: StoragePlacement,
    id: &str,
) -> anyhow::Result<Option<String>> {
    match placement {
        StoragePlacement::Local => {
            let mut client = connect_local_credential_authority().await?;
            let projects = client
                .list_secret_projects()
                .await
                .context("list local secret project metadata")?;
            Ok(projects
                .into_iter()
                .find(|project| project.id.to_string() == id)
                .map(|project| project.name))
        }
        StoragePlacement::Platform => {
            // Only the platform and organization the selection was made in
            // can name it.
            let Some(authority) = environment.platform_source_authority.as_ref() else {
                return Ok(None);
            };
            let env = OsEnv;
            let paths = ResolvePaths::from_env(&env)?;
            let platform = config::resolve_platform(
                config::PlatformResolveOptions {
                    server_url: globals.server.clone(),
                    org: globals.org.clone(),
                },
                &paths,
                &env,
            )?;
            if config::normalize_server_url(&platform.server_url) != authority.server_url {
                return Ok(None);
            }
            let projects = SecretClient::new(&platform)?
                .list_secret_projects(&authority.organization_id)
                .await
                .context("list platform secret project metadata")?;
            Ok(projects
                .into_iter()
                .find(|project| project.id == id && project.org_id == authority.organization_id)
                .map(|project| project.name))
        }
    }
}

/// A lifecycle wait that lost contact with the local runtime before its
/// operation finished, as when the supervisor exits during an image pull
/// (#4418). The supervisor journals the operation and the next one resumes
/// it, so this never says the operation failed.
#[derive(Debug)]
pub(super) struct LostContact(String);

impl std::fmt::Display for LostContact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for LostContact {}

/// The error for a lost wait on `name`'s `noun` (`creation`, `start`), at
/// `stage` when one was showing, with `cw --local info NAME` as its next
/// step.
pub(super) fn lost_contact(noun: &str, name: &str, stage: Option<&str>) -> anyhow::Error {
    let during = stage
        .map(|stage| format!(" during {stage:?}"))
        .unwrap_or_default();
    crate::error_report::with_next_step(
        anyhow::Error::new(LostContact(format!(
            "lost contact with the local runtime{during} before the {noun} of {name} \
             finished; it may still finish"
        ))),
        environment_command(VmLocation::Local, "info", name),
    )
}

/// After a wait that lost the supervisor, asks the next one, once, what its
/// journal holds for the operation (#5144). A finished operation's outcome is
/// returned as the wait would have delivered it, with a client of the new
/// supervisor, so a start that failed names its step and reason instead of
/// "lost contact". One still running stays lost, and one with no record is
/// said so, never reported as pending.
pub(super) async fn journaled_after_lost(
    lost: tonic::Status,
) -> Result<(NativeSupervisorClient, v1::Operation), tonic::Status> {
    use codewire_local_vmm::supervisor_client::{Journaled, lost_operation_id};

    let Some(operation_id) = lost_operation_id(&lost).map(str::to_owned) else {
        return Err(lost);
    };
    let Ok(mut client) = native_client().await else {
        return Err(lost);
    };
    match client.journaled(&operation_id).await {
        Ok(Journaled::Finished(outcome)) => outcome.map(|operation| (client, operation)),
        Ok(Journaled::Unrecorded) => Err(tonic::Status::failed_precondition(
            "the local runtime restarted with no record of this operation",
        )),
        Ok(Journaled::Running) | Err(_) => Err(lost),
    }
}

/// A wait whose result is the environment `name`, after
/// [`journaled_after_lost`] when it lost the supervisor.
pub(super) async fn environment_after_lost(
    waited: Result<v1::Environment, tonic::Status>,
    name: &str,
) -> Result<v1::Environment, tonic::Status> {
    use codewire_local_vmm::supervisor_client::operation_watch_lost_contact;

    match waited {
        Err(lost) if operation_watch_lost_contact(&lost) => {
            let (mut client, _) = journaled_after_lost(lost).await?;
            client.get(name).await
        }
        waited => waited,
    }
}

/// A create or start wait that ended without success, as the stage to
/// report and the error. A wait that lost the supervisor (#4418) clears the
/// open step and names no stage, since the operation may still finish; a
/// failed operation marks its step failed with the supervisor's reason.
pub(super) fn wait_failure(
    progress: &NativeProgress,
    noun: &str,
    name: &str,
    status: tonic::Status,
) -> (Option<&'static str>, anyhow::Error) {
    use codewire_local_vmm::supervisor_client::{
        operation_error_code, operation_watch_lost_contact,
    };

    if operation_watch_lost_contact(&status) {
        return (None, lost_contact(noun, name, progress.lose()));
    }
    let stage = progress.fail_with_code(operation_error_code(&status));
    let error = native_status(status.clone());
    (
        stage,
        crate::commands::checkpoint::interception::with_switch_step(error, &status),
    )
}

/// A lifecycle call that failed after its progress began: the stage it
/// stopped at, the supervisor's reason, and, for an environment that
/// existed before the call, its state afterwards and where to look. A lost
/// wait ([`LostContact`]) says what it knows on its own.
pub(super) async fn lifecycle_failure(
    verb: &str,
    name: &str,
    stage: Option<&str>,
    error: anyhow::Error,
    inspect: bool,
) -> anyhow::Error {
    if error.is::<LostContact>() {
        return error;
    }
    let head = match stage {
        Some(stage) => format!("{verb} {name} failed at {stage:?}"),
        None => format!("{verb} {name} failed"),
    };
    if !inspect {
        return error.context(head);
    }
    let after = match native_client().await {
        Ok(mut client) => match client.get(name).await {
            Ok(environment) => format!(
                "{name} reports state {}; inspect it with `{}`",
                native_state_label(environment.state),
                environment_command(VmLocation::Local, "info", name)
            ),
            Err(status) if status.code() == tonic::Code::NotFound => {
                format!("{name} is no longer listed; check `cw --local ls`")
            }
            Err(_) => format!("the state of {name} is unknown; check `cw --local ls`"),
        },
        Err(_) => format!("the state of {name} is unknown; check `cw --local ls`"),
    };
    with_state(&head, &error, &after)
}

/// `error` under `head`, followed by the environment's state line, keeping
/// the next step `error` carries as the error's own.
fn with_state(head: &str, error: &anyhow::Error, after: &str) -> anyhow::Error {
    let message = anyhow::anyhow!("{head}: {}\n{after}", crate::error_report::sentence(error));
    match crate::error_report::next_step(error) {
        Some(step) => crate::error_report::with_next_step(message, step),
        None => message,
    }
}

/// The environment `name`, for a command that boots it. Where it has a
/// credential profile or secrets, the credential authority must be one whose
/// brokers serve a VM this cw starts: the command is refused here, before it
/// stops or starts anything, while another cw's must keep serving (#5238).
pub(super) async fn environment_for_boot(
    client: &mut NativeSupervisorClient,
    name: &str,
) -> anyhow::Result<v1::Environment> {
    let environment = get_native_environment_with_required_authority(client, name).await?;
    if environment.requires_credential_authority {
        drop(connect_local_credential_authority_for_boot().await?);
    }
    Ok(environment)
}

/// `cw start` on a local environment.
pub(crate) async fn start_native_environment(
    globals: &Globals,
    name: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    host_support::require_local_vm_host()?;
    let caps = crate::commands::lifecycle_output::capabilities(output);
    let mut client = native_boot_client().await?;
    let environment = prepare_native_start(&mut client, name).await?;
    if environment.state == v1::EnvironmentState::Running as i32 {
        return print_already(&environment, Already::Running, output);
    }
    let secrets = if caps.is_machine() {
        SourceRef::None
    } else {
        environment_secrets(globals, &environment).await
    };
    print_context(
        &local_summary(&environment, Outcome::Started, secrets.clone()),
        &caps,
    );
    let progress = NativeProgress::new(&caps).interruptible(
        &caps,
        InterruptNotice::new(VmLocation::Local, "start", &environment.name),
    );
    let started = run_native_start(client, &environment.name, &progress).await?;
    let (started, moved) = match started {
        Ok(started) => started,
        Err((stage, error)) => {
            return Err(lifecycle_failure("start", &environment.name, stage, error, true).await);
        }
    };
    let withheld = super::profile::withheld_credentials(&started).await;
    match output {
        OutputFormat::Json => {
            super::profile::print_withheld(&withheld);
            print_native_environment(&started, output)
        }
        OutputFormat::Text => {
            let mut summary = local_summary(&started, Outcome::Started, secrets);
            // The move and the credentials its agents can't use are part of
            // the result, so they come before the next step.
            let next = summary.next.take();
            print_summary(&summary, &caps);
            if let Some(moved) = &moved {
                println!(
                    "\n{}",
                    runtime_move_line(&started.name, moved, caps.stdout_style())
                );
            }
            super::profile::print_withheld(&withheld);
            if let Some(next) = next {
                print!("{}", render_next(&next, caps.stdout_style()));
            }
            Ok(())
        }
    }
}

/// The start of a local VM: its environment and, when the start moved it
/// onto the installed runtime (#4980), that move; or the stage it stopped
/// at and why.
pub(super) type NativeStart =
    Result<(v1::Environment, Option<v1::RuntimeMove>), (Option<&'static str>, anyhow::Error)>;

/// Starts `name` with its stages on `progress`. The outer error is an
/// interrupted wait; the inner one a failed start with its stage. The
/// completed operation's result says whether the start moved the runtime.
pub(super) async fn run_native_start(
    mut client: NativeSupervisorClient,
    name: &str,
    progress: &NativeProgress,
) -> anyhow::Result<NativeStart> {
    let mut observe = |operation: &v1::Operation| progress.observe(operation);
    let started = match progress
        .tick_while(client.start_observed(name, &mut observe))
        .await?
    {
        Err(lost) if codewire_local_vmm::supervisor_client::operation_watch_lost_contact(&lost) => {
            match journaled_after_lost(lost).await {
                Ok((mut client, completed)) => client
                    .get(name)
                    .await
                    .map(|environment| (environment, completed)),
                Err(status) => Err(status),
            }
        }
        started => started,
    };
    Ok(match started {
        Ok((environment, completed)) => {
            progress.complete();
            Ok((environment, runtime_move_of(&completed)))
        }
        Err(status) => Err(wait_failure(progress, "start", name, status)),
    })
}

/// The runtime move a completed start's result records, if it moved.
fn runtime_move_of(completed: &v1::Operation) -> Option<v1::RuntimeMove> {
    match completed.result.as_ref()?.value.as_ref()? {
        v1::operation_result::Value::Environment(result) => result.runtime_move.clone(),
        _ => None,
    }
}

/// The line a start prints after moving an environment onto this cw's VM
/// runtime: what changed in the guest runtime it speaks, and the VM
/// checkpoints the move leaves unrestorable.
fn runtime_move_line(name: &str, moved: &v1::RuntimeMove, style: Style) -> String {
    let moved_to = format!(
        "Moved {} to this cw's VM runtime ({})",
        terminal_text(name),
        terminal_text(&abi_change(&moved.from_guest_abi, &moved.to_guest_abi)),
    );
    match moved.unrestorable_checkpoints {
        0 => format!("{} {moved_to}", style.status(Status::Done)),
        count => format!(
            "{} {moved_to}; its {count} VM checkpoint{} from before can't be restored (`cw --local checkpoint ls` lists {})",
            style.status(Status::Attention),
            if count == 1 { "" } else { "s" },
            if count == 1 { "it" } else { "them" },
        ),
    }
}

/// What differs between two declared guest ABIs, key by key, such as
/// "guest net none to 2" for `seed=9;cw_catalog=1` to
/// `seed=9;cw_catalog=1;net=2`. A key missing on one side is "none". A
/// declaration that isn't `key=value` pairs, or two that don't differ, is
/// said as given.
fn abi_change(from: &str, to: &str) -> String {
    let keys = |abi: &str| -> Option<Vec<(String, String)>> {
        abi.split(';')
            .filter(|part| !part.trim().is_empty())
            .map(|part| {
                part.split_once('=')
                    .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
            })
            .collect()
    };
    let as_given = || format!("guest {from} to {to}");
    let (Some(before), Some(after)) = (keys(from), keys(to)) else {
        return as_given();
    };
    let value = |pairs: &[(String, String)], key: &str| {
        pairs
            .iter()
            .find(|(name, _)| name == key)
            .map_or_else(|| "none".to_owned(), |(_, value)| value.clone())
    };
    let mut names: Vec<&str> = after.iter().map(|(key, _)| key.as_str()).collect();
    for (key, _) in &before {
        if !names.contains(&key.as_str()) {
            names.push(key);
        }
    }
    let changes: Vec<String> = names
        .into_iter()
        .filter_map(|key| {
            let (was, now) = (value(&before, key), value(&after, key));
            (was != now).then(|| format!("{key} {was} to {now}"))
        })
        .collect();
    if changes.is_empty() {
        return as_given();
    }
    format!("guest {}", changes.join(", "))
}

/// `cw restart` on a local environment.
pub(crate) async fn restart_native_environment(
    globals: &Globals,
    name: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    host_support::require_local_vm_host()?;
    let caps = crate::commands::lifecycle_output::capabilities(output);
    let mut client = native_boot_client().await?;
    ensure_pinned_runtime().await?;
    let environment = environment_for_boot(&mut client, name).await?;
    let secrets = if caps.is_machine() {
        SourceRef::None
    } else {
        environment_secrets(globals, &environment).await
    };
    print_context(
        &local_summary(&environment, Outcome::Restarted, secrets.clone()),
        &caps,
    );
    let progress = NativeProgress::new(&caps).interruptible(
        &caps,
        InterruptNotice::new(VmLocation::Local, "restart", &environment.name),
    );
    progress.begin("restart", "Restarting the VM");
    let restarted = progress
        .tick_while(client.restart(&environment.name, &environment.id))
        .await?;
    let restarted = match restarted {
        Ok(restarted) => {
            progress.complete();
            restarted
        }
        Err(status) => {
            let stage = progress.fail();
            return Err(lifecycle_failure(
                "restart",
                &environment.name,
                stage,
                native_status(status),
                true,
            )
            .await);
        }
    };
    match output {
        OutputFormat::Json => print_native_environment(&restarted, output),
        OutputFormat::Text => {
            print_summary(
                &local_summary(&restarted, Outcome::Restarted, secrets),
                &caps,
            );
            Ok(())
        }
    }
}

/// `cw stop` on a whole local environment.
pub(crate) async fn stop_native_environment(
    name: &str,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let caps = crate::commands::lifecycle_output::capabilities(output);
    let mut client = native_client().await?;
    let environment = get_native_environment_with_authority_recovery(&mut client, name).await?;
    if environment.state == v1::EnvironmentState::Stopped as i32 {
        return print_already(&environment, Already::Stopped, output);
    }
    let progress = NativeProgress::new(&caps).interruptible(
        &caps,
        InterruptNotice::new(VmLocation::Local, "stop", &environment.name),
    );
    progress.begin("stop", "Stopping the VM");
    let stopped = match progress.tick_while(client.stop(&environment.name)).await? {
        Ok(stopped) => {
            progress.complete();
            stopped
        }
        Err(status) => {
            let stage = progress.fail();
            return Err(lifecycle_failure(
                "stop",
                &environment.name,
                stage,
                native_status(status),
                true,
            )
            .await);
        }
    };
    match output {
        OutputFormat::Json => print_native_environment(&stopped, output),
        OutputFormat::Text => {
            stop_result(&stopped).print(&caps);
            Ok(())
        }
    }
}

/// A stop or start that found the environment as asked: the one line both
/// placements print, and in JSON the environment, as a finished one prints.
fn print_already(
    environment: &v1::Environment,
    already: Already,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => print_native_environment(environment, output),
        OutputFormat::Text => {
            print!(
                "{}",
                already_line(
                    &crate::commands::progress::terminal_text(&environment.name),
                    already
                )
            );
            Ok(())
        }
    }
}

/// The observed state after a local stop: stopped with its disk kept, or
/// whatever state the VM reports instead.
pub(super) fn stop_result(environment: &v1::Environment) -> ResultBlock {
    let name = &environment.name;
    if environment.state == v1::EnvironmentState::Stopped as i32 {
        ResultBlock::new(Status::Done, format!("Environment {name} stopped"))
            .detail(format!(
                "{} · environment disk retained",
                location_label(VmLocation::Local)
            ))
            .next(environment_command(VmLocation::Local, "start", name))
    } else {
        ResultBlock::new(
            Status::Attention,
            format!("Environment {name} did not report stopped"),
        )
        .detail(format!(
            "{} · state: {}",
            location_label(VmLocation::Local),
            native_state_label(environment.state)
        ))
        .next(environment_command(VmLocation::Local, "info", name))
    }
}

/// `cw rm` on a local environment.
pub(crate) async fn remove_native_environment(
    name: &str,
    yes: bool,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let caps = crate::commands::lifecycle_output::capabilities(output);
    let mut client = native_client().await?;
    let environment = get_native_environment_with_authority_recovery(&mut client, name).await?;
    if !crate::commands::confirm_removal(&environment.name, "local VM", yes, output)? {
        return Ok(());
    }
    // Delete stops the environment's credential broker through the authority
    // whenever it selected a profile or secrets.
    ensure_native_credential_authority(&environment).await?;
    let progress = NativeProgress::new(&caps).interruptible(
        &caps,
        InterruptNotice::new(VmLocation::Local, "removal", &environment.name),
    );
    progress.begin("remove", "Removing the environment");
    let removed = match progress
        .tick_while(client.delete(&environment.name))
        .await?
    {
        Ok(removed) => {
            progress.complete();
            removed
        }
        Err(status) => {
            let stage = progress.fail();
            return Err(lifecycle_failure(
                "remove",
                &environment.name,
                stage,
                native_status(status),
                true,
            )
            .await);
        }
    };
    // An unconfirmed removal may have left the VM: it stays selected.
    if removed.removed {
        reconcile_native_current_after_delete(&removed.name).await;
    }
    // A confirmed removal of a Mesh-attached VM revokes its node (#2697).
    let node = match environment.mesh.as_ref() {
        Some(mesh) if removed.removed && !mesh.network_id.trim().is_empty() => {
            Some((mesh, revoke_removed_environment_node(mesh).await))
        }
        _ => None,
    };
    report_removal(
        output,
        &caps,
        &removed,
        node.as_ref().map(|(mesh, node)| (*mesh, node)),
    )
}

/// Prints the removal. A node that could not be revoked never changes the
/// exit status: the environment is gone either way.
pub(super) fn report_removal(
    output: OutputFormat,
    caps: &Capabilities,
    removed: &v1::DeleteEnvironmentResponse,
    node: Option<(&v1::MeshAttachment, &MeshNodeRemoval)>,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => {
            let mut value = serde_json::json!({
                "name": removed.name,
                "removed": removed.removed,
                "cleanup_pending": removed.cleanup_pending,
            });
            if let Some((mesh, outcome)) = node {
                value["mesh_node"] = match outcome {
                    MeshNodeRemoval::Revoked => serde_json::json!({
                        "network_id": mesh.network_id,
                        "node_name": mesh.node_name,
                        "revoked": true,
                    }),
                    MeshNodeRemoval::Kept(reason) => serde_json::json!({
                        "network_id": mesh.network_id,
                        "node_name": mesh.node_name,
                        "revoked": false,
                        "error": reason,
                        "revoke_command": mesh_revoke_command(mesh),
                    }),
                };
            }
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        OutputFormat::Text => remove_result(removed, node).print(caps),
    }
    Ok(())
}

/// What became of a removed environment's Mesh node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum MeshNodeRemoval {
    Revoked,
    /// Still registered, and why.
    Kept(String),
}

/// The client that deletes a Mesh-attached local environment revokes its
/// node (#2697), with the credential of the attachment's own owner store, the
/// one its enrollments were made with. The supervisor never holds one.
async fn revoke_removed_environment_node(mesh: &v1::MeshAttachment) -> MeshNodeRemoval {
    let auth_source = match v1::MeshEnrollmentAuthSource::try_from(mesh.auth_source) {
        Ok(v1::MeshEnrollmentAuthSource::StandaloneLocal) => {
            codewire_local_vmm::mesh_enrollment::MeshEnrollmentAuthSource::StandaloneLocal
        }
        Ok(v1::MeshEnrollmentAuthSource::HostedCurrent) => {
            codewire_local_vmm::mesh_enrollment::MeshEnrollmentAuthSource::HostedCurrent
        }
        _ => return MeshNodeRemoval::Kept("its attachment names no owner store".into()),
    };
    let Ok(attachment) = codewire_local_vmm::mesh_ingress::MeshAttachment::new_with_auth_source(
        auth_source,
        &mesh.mesh_url,
        &mesh.organization_id,
        &mesh.network_id,
        &mesh.node_name,
        [],
    ) else {
        return MeshNodeRemoval::Kept("its Mesh attachment is not valid".into());
    };
    let Ok(paths) = ResolvePaths::from_env(&OsEnv) else {
        return MeshNodeRemoval::Kept("the owner credential could not be found".into());
    };
    let credentials = NativeMeshEnrollmentCredentials { paths };
    let Ok(token) = codewire_local_vmm::mesh_enrollment::MeshEnrollmentCredentialResolver::resolve(
        &credentials,
        &attachment,
    )
    .await
    else {
        return MeshNodeRemoval::Kept(
            "the credential it was attached with is not available".into(),
        );
    };
    revoke_mesh_node_with(
        &attachment,
        codewire_client::StaticTokenProvider::from_token(token),
    )
    .await
}

/// Revokes the attachment's node at its exact Mesh. A node already gone
/// counts as revoked.
pub(super) async fn revoke_mesh_node_with(
    attachment: &codewire_local_vmm::mesh_ingress::MeshAttachment,
    token: impl codewire_client::TokenProvider + 'static,
) -> MeshNodeRemoval {
    let client = codewire_client::ClientConfig::new(&attachment.mesh_url)
        .and_then(|config| config.with_mesh_url(&attachment.mesh_url))
        .and_then(|config| codewire_client::CodewireClient::new(config, token));
    let client = match client {
        Ok(client) => client,
        Err(error) => return MeshNodeRemoval::Kept(error.to_string()),
    };
    match client
        .revoke_mesh_node(codewire_client::RevokeMeshNodeRequest {
            org_id: attachment.organization_id.clone(),
            network_id: attachment.network_id.clone(),
            node_name: attachment.node_name.clone(),
            ..Default::default()
        })
        .await
    {
        Ok(_) => MeshNodeRemoval::Revoked,
        Err(error) if error.code() == codewire_client::ErrorCode::NotFound => {
            MeshNodeRemoval::Revoked
        }
        Err(error) => MeshNodeRemoval::Kept(error.to_string()),
    }
}

/// The command that revokes the attachment's node by hand.
fn mesh_revoke_command(mesh: &v1::MeshAttachment) -> String {
    let placement = match v1::MeshEnrollmentAuthSource::try_from(mesh.auth_source) {
        Ok(v1::MeshEnrollmentAuthSource::HostedCurrent) => "--cloud",
        _ => "--local",
    };
    format!(
        "cw {placement} network revoke {} --org {} --network {}",
        mesh.node_name, mesh.organization_id, mesh.network_id
    )
}

/// Removed, removed with cleanup pending, or not confirmed, and what became
/// of its Mesh node.
pub(super) fn remove_result(
    removed: &v1::DeleteEnvironmentResponse,
    node: Option<(&v1::MeshAttachment, &MeshNodeRemoval)>,
) -> ResultBlock {
    let name = &removed.name;
    let local = location_label(VmLocation::Local);
    let block = if removed.removed {
        let left = match node {
            Some((mesh, MeshNodeRemoval::Revoked)) => {
                format!(" · Mesh node {} left {}", mesh.node_name, mesh.network_id)
            }
            _ => String::new(),
        };
        ResultBlock::new(Status::Done, format!("Environment {name} removed"))
            .detail(format!("{local} · environment disk removed{left}"))
    } else {
        ResultBlock::new(
            Status::Attention,
            format!("Removal of {name} was not confirmed"),
        )
        .detail(local)
    };
    let block = if removed.cleanup_pending {
        block.attention(
            "Cleanup needs inspection",
            "An unsafe or unknown object remains quarantined; inspect it with `cw doctor local`.",
        )
    } else {
        block
    };
    match node {
        Some((mesh, MeshNodeRemoval::Kept(reason))) => block
            .attention(
                format!(
                    "Mesh node {} is still registered in {}",
                    mesh.node_name, mesh.network_id
                ),
                format!("It was not revoked: {reason}. It shows offline until it is."),
            )
            .next(mesh_revoke_command(mesh)),
        _ => block.next("cw ls"),
    }
}

/// The working context of a create, from what it will request.
pub(super) struct CreateContext {
    pub(super) credentials: SourceRef,
    pub(super) secrets: SourceRef,
    pub(super) network: NetworkRef,
    pub(super) policy: CreatePolicy,
}

impl CreateContext {
    pub(super) fn summary(
        &self,
        name: &str,
        vcpus: u32,
        memory_mib: u32,
        disk_bytes: u64,
    ) -> LifecycleSummary {
        LifecycleSummary {
            outcome: Outcome::Created,
            name: name.to_owned(),
            location: VmLocation::Local,
            allocation: Allocation::local(vcpus, memory_mib, disk_bytes),
            credentials: self.credentials.clone(),
            credentials_note: None,
            secrets: self.secrets.clone(),
            network: self.network.clone(),
            policy: Some(self.policy.text()),
            next: Some(next_shell_command(VmLocation::Local, name)),
        }
    }
}

/// Prints the summary of a created environment, then on stderr any profile
/// credential its agents can't use (#5545); JSON keeps its shape.
pub(crate) async fn print_native_created(
    created: &NativeCreated,
    output: OutputFormat,
    caps: &Capabilities,
) -> anyhow::Result<()> {
    let withheld = super::profile::withheld_credentials(&created.environment).await;
    match output {
        OutputFormat::Json => {
            let view = NativeEnvironmentView::try_from(&created.environment)?;
            let result = created.configuration.add_to(serde_json::to_value(&view)?);
            println!("{}", serde_json::to_string_pretty(&result)?);
            super::profile::print_withheld(&withheld);
        }
        OutputFormat::Text => {
            let mut summary = local_summary(
                &created.environment,
                Outcome::Created,
                created.secrets.clone(),
            );
            // The credentials its agents can't use come before the next step.
            let next = summary.next.take();
            print_summary(&summary, caps);
            super::profile::print_withheld(&withheld);
            if let Some(next) = next {
                print!("{}", render_next(&next, caps.stdout_style()));
            }
        }
    }
    Ok(())
}

/// A created local environment and its secrets reference, named while the
/// selection was made.
pub(crate) struct NativeCreated {
    pub(crate) environment: v1::Environment,
    pub(crate) secrets: SourceRef,
    /// Where its configuration came from, for the JSON result.
    pub(crate) configuration: crate::commands::project_file::Provenance,
}

/// Where a local create's network policy came from (#2537).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PolicySource {
    Flag,
    ProjectFile,
    Default,
}

/// The network policy a local create selects: an explicit `--policy`, else
/// the project file's `network.policy`, else none, which is `open`. The review
/// and the create both use it, so what is shown is what is selected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CreatePolicy {
    reference: String,
    source: PolicySource,
}

impl CreatePolicy {
    pub(super) fn resolve(flag: Option<&str>, spec: &ProjectSpec) -> Self {
        match (flag, spec.network.as_ref()) {
            (Some(flag), _) => Self {
                reference: flag.to_owned(),
                source: PolicySource::Flag,
            },
            (None, Some(binding)) => Self {
                reference: binding.policy.clone(),
                source: PolicySource::ProjectFile,
            },
            (None, None) => Self {
                reference: String::new(),
                source: PolicySource::Default,
            },
        }
    }

    /// Resolves the policy and takes the file's value out of the spec, so
    /// the VM's selection stays its one record.
    pub(super) fn take(flag: Option<&str>, mut spec: ProjectSpec) -> (Self, ProjectSpec) {
        let policy = Self::resolve(flag, &spec);
        spec.network = None;
        (policy, spec)
    }

    /// The selection the create requests: empty for the default.
    pub(super) fn reference(&self) -> String {
        self.reference.clone()
    }

    /// `work (--policy)`, `work (codewire.yaml)`, or `open`.
    pub(super) fn text(&self) -> String {
        match self.source {
            PolicySource::Flag => format!("{} (--policy)", self.reference),
            PolicySource::ProjectFile => format!("{} (codewire.yaml)", self.reference),
            PolicySource::Default => "open".to_owned(),
        }
    }
}

/// Refuses a policy selection before contacting a supervisor too old to
/// enforce one.
pub(super) fn require_policy_selection(
    client: &NativeSupervisorClient,
    policy: &str,
) -> anyhow::Result<()> {
    if policy.is_empty() {
        return Ok(());
    }
    client
        .require_network_policy_selection()
        .map_err(|status| anyhow::anyhow!("{}", status.message()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_start_that_moved_the_runtime_says_so_on_one_line() {
        let plain = Style::new(false, crate::output::Charset::Unicode);
        let moved = |checkpoints| v1::RuntimeMove {
            from_guest_abi: "seed=9;cw_catalog=1".into(),
            to_guest_abi: "seed=9;cw_catalog=1;net=2".into(),
            unrestorable_checkpoints: checkpoints,
        };
        assert_eq!(
            runtime_move_line("up-walk", &moved(0), plain),
            "✓ Moved up-walk to this cw's VM runtime (guest net none to 2)"
        );
        assert_eq!(
            runtime_move_line("up-walk", &moved(1), plain),
            "! Moved up-walk to this cw's VM runtime (guest net none to 2); its 1 VM checkpoint from before can't be restored (`cw --local checkpoint ls` lists it)"
        );
        assert!(runtime_move_line("up-walk", &moved(2), plain).contains("its 2 VM checkpoints"));
        assert!(!runtime_move_line("up-walk", &moved(1), plain).contains('\n'));
    }

    /// The move comes from the completed start's result, which the
    /// progress observer never sees.
    #[test]
    fn a_completed_start_reports_the_move_its_result_records() {
        let moved = v1::RuntimeMove {
            from_guest_abi: "seed=9;cw_catalog=1".into(),
            to_guest_abi: "seed=10;cw_catalog=1;net=2".into(),
            unrestorable_checkpoints: 1,
        };
        let completed = |runtime_move| v1::Operation {
            phase: v1::OperationPhase::Completed as i32,
            result: Some(v1::OperationResult {
                value: Some(v1::operation_result::Value::Environment(
                    v1::EnvironmentOperationResult {
                        runtime_move,
                        ..Default::default()
                    },
                )),
            }),
            ..Default::default()
        };
        assert_eq!(
            runtime_move_of(&completed(Some(moved.clone()))),
            Some(moved)
        );
        assert_eq!(runtime_move_of(&completed(None)), None);
        assert_eq!(runtime_move_of(&v1::Operation::default()), None);
    }

    /// The line always shows what changed, whichever keys did.
    #[test]
    fn a_runtime_move_names_each_key_that_changed() {
        assert_eq!(
            abi_change("seed=9;cw_catalog=1", "seed=9;cw_catalog=1;net=2"),
            "guest net none to 2"
        );
        assert_eq!(
            abi_change("seed=9;cw_catalog=1", "seed=10;cw_catalog=1;net=2"),
            "guest seed 9 to 10, net none to 2"
        );
        assert_eq!(
            abi_change("seed=9;cw_catalog=1;net=1", "seed=9;cw_catalog=2"),
            "guest cw_catalog 1 to 2, net 1 to none"
        );
        // Not key=value pairs, or nothing differs: the two as given.
        assert_eq!(abi_change("v9", "v10"), "guest v9 to v10");
        assert_eq!(abi_change("seed=9", "seed=9"), "guest seed=9 to seed=9");
    }

    use super::*;

    #[test]
    fn the_state_line_keeps_the_next_step_on_its_own() {
        let error = crate::error_report::with_next_step(
            anyhow::anyhow!("start_intercept_unavailable (the switch is on)"),
            "rm /state/egress-intercept",
        );
        let error = with_state(
            "Start p3 failed at \"Starting the VM\"",
            &error,
            "p3 reports state error",
        );
        assert_eq!(
            crate::error_report::next_step(&error).as_deref(),
            Some("rm /state/egress-intercept")
        );
        assert_eq!(
            crate::error_report::sentence(&error),
            "Start p3 failed at \"Starting the VM\": start_intercept_unavailable (the switch is on)\np3 reports state error"
        );
    }
    use crate::output::{Charset, Style};

    #[tokio::test]
    async fn a_lost_wait_says_the_operation_may_still_finish() {
        let lost = lost_contact("creation", "dev", Some("Pulling the image"));
        assert_eq!(
            lost.downcast_ref::<LostContact>().unwrap().to_string(),
            "lost contact with the local runtime during \"Pulling the image\" before the \
             creation of dev finished; it may still finish"
        );
        assert_eq!(
            lost.downcast_ref::<crate::error_report::NextStep>()
                .unwrap()
                .to_string(),
            "cw --local info dev"
        );
        // It is reported as it is, never as "create dev failed at ..." (#4418).
        let reported = lifecycle_failure("create", "dev", None, lost, false).await;
        assert!(reported.is::<LostContact>());
        assert!(!format!("{reported:#}").contains("failed"));
        let start = lost_contact("start", "dev", None);
        assert_eq!(
            start.downcast_ref::<LostContact>().unwrap().to_string(),
            "lost contact with the local runtime before the start of dev finished; it may still \
             finish"
        );
    }

    const PLAIN: Style = Style::new(false, Charset::Unicode);

    #[test]
    fn an_explicit_policy_overrides_the_project_file_and_the_file_never_persists() {
        let file = |policy: &str| ProjectSpec {
            network: Some(codewire_project::NetworkBinding {
                policy: policy.to_owned(),
            }),
            ..Default::default()
        };
        let (policy, spec) = CreatePolicy::take(None, file("work"));
        assert_eq!(
            (policy.reference(), policy.text()),
            ("work".to_owned(), "work (codewire.yaml)".to_owned())
        );
        assert!(spec.network.is_none());

        let (policy, spec) = CreatePolicy::take(Some("locked"), file("work"));
        assert_eq!(
            (policy.reference(), policy.text()),
            ("locked".to_owned(), "locked (--policy)".to_owned())
        );
        assert!(spec.network.is_none());

        let (policy, _) = CreatePolicy::take(None, ProjectSpec::default());
        assert_eq!(
            (policy.reference(), policy.text()),
            (String::new(), "open".to_owned())
        );
    }
    const PROFILE_ID: &str = "856b6b9e-a520-48c7-aab1-8ac915465f28";

    fn environment() -> v1::Environment {
        let spec = ProjectSpec {
            image: "workspace".to_owned(),
            credentials: Some(codewire_project::CredentialBinding {
                profile: format!("local:id:{PROFILE_ID}"),
            }),
            ..Default::default()
        };
        let json = spec.canonical_json().unwrap();
        v1::Environment {
            id: "a6249c2e-2fa4-473b-b41a-8d0f08f39e51".to_owned(),
            name: "app".to_owned(),
            state: v1::EnvironmentState::Running as i32,
            vcpus: 2,
            memory_mib: 4096,
            disk_bytes: 40 * 1024 * 1024 * 1024,
            project_spec_sha256: format!("{:x}", Sha256::digest(&json)),
            project_spec_json: json,
            access_profile: "user/work".to_owned(),
            access_profile_id: PROFILE_ID.to_owned(),
            access_profile_revision: 3,
            mesh: Some(v1::MeshAttachment {
                network_id: "work".to_owned(),
                auth_source: v1::MeshEnrollmentAuthSource::HostedCurrent as i32,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn started_summary_names_size_profile_secrets_and_network() {
        let summary = local_summary(
            &environment(),
            Outcome::Started,
            SourceRef::Unresolved("local:id:x".to_owned()),
        );
        assert_eq!(
            summary.render(PLAIN),
            "✓ Environment app started · local VM\n  2 vCPU · 4 GiB RAM · 40 GiB disk\n\n  Credentials: local:work\n  Secrets:     local:id:x\n  Network:     cloud:work\n\n→ cw --local shell app\n"
        );
    }

    #[test]
    fn missing_selections_read_none_and_not_attached() {
        let mut environment = environment();
        environment.mesh = None;
        environment.access_profile.clear();
        environment.access_profile_id.clear();
        environment.access_profile_revision = 0;
        let spec = ProjectSpec {
            image: "workspace".to_owned(),
            ..Default::default()
        };
        environment.project_spec_json = spec.canonical_json().unwrap();
        environment.project_spec_sha256 =
            format!("{:x}", Sha256::digest(&environment.project_spec_json));
        let text = local_summary(&environment, Outcome::Created, SourceRef::None).render(PLAIN);
        assert!(
            text.contains(
                "  Credentials: none\n  Secrets:     none\n  Network:     not attached\n"
            )
        );
        assert!(text.starts_with("✓ Environment app created · local VM\n"));
    }

    #[test]
    fn local_mesh_networks_and_unreadable_specs_stay_honest() {
        let mut environment = environment();
        environment.mesh = Some(v1::MeshAttachment {
            network_id: "lab".to_owned(),
            auth_source: v1::MeshEnrollmentAuthSource::StandaloneLocal as i32,
            ..Default::default()
        });
        assert_eq!(network_ref(environment.mesh.as_ref()).text(), "local:lab");
        assert_eq!(
            network_ref(Some(&v1::MeshAttachment::default())),
            NetworkRef::NotAttached
        );
        environment.project_spec_json = b"{}".to_vec();
        assert_eq!(
            environment_credentials(&environment, stored_spec(&environment).as_ref()),
            SourceRef::Unresolved("user/work".to_owned())
        );
    }

    #[test]
    fn stop_reports_the_observed_state() {
        let mut stopped = environment();
        stopped.state = v1::EnvironmentState::Stopped as i32;
        assert_eq!(
            stop_result(&stopped).render(PLAIN),
            "✓ Environment app stopped\n  local VM · environment disk retained\n\n→ cw --local start app\n"
        );
        stopped.state = v1::EnvironmentState::Error as i32;
        assert_eq!(
            stop_result(&stopped).render(PLAIN),
            "! Environment app did not report stopped\n  local VM · state: error\n\n→ cw --local info app\n"
        );
    }

    #[test]
    fn remove_distinguishes_removed_and_cleanup_pending() {
        let mut removed = v1::DeleteEnvironmentResponse {
            name: "app".to_owned(),
            removed: true,
            cleanup_pending: false,
        };
        assert_eq!(
            remove_result(&removed, None).render(PLAIN),
            "✓ Environment app removed\n  local VM · environment disk removed\n\n→ cw ls\n"
        );
        removed.cleanup_pending = true;
        let text = remove_result(&removed, None).render(PLAIN);
        assert!(text.starts_with("✓ Environment app removed\n"));
        assert!(text.contains("\n! Cleanup needs inspection\n  An unsafe or unknown object remains quarantined; inspect it with `cw doctor local`.\n"));
        removed.removed = false;
        assert!(
            remove_result(&removed, None)
                .render(PLAIN)
                .starts_with("! Removal of app was not confirmed\n")
        );
    }

    fn mesh(auth_source: v1::MeshEnrollmentAuthSource) -> v1::MeshAttachment {
        v1::MeshAttachment {
            mesh_url: "https://mesh.codewire.sh".to_owned(),
            organization_id: "org-demo".to_owned(),
            network_id: "team".to_owned(),
            node_name: "app".to_owned(),
            auth_source: auth_source as i32,
            ..Default::default()
        }
    }

    fn removed() -> v1::DeleteEnvironmentResponse {
        v1::DeleteEnvironmentResponse {
            name: "app".to_owned(),
            removed: true,
            cleanup_pending: false,
        }
    }

    /// #2697: a removed VM's node leaves its network, and the result says so.
    #[test]
    fn a_removed_attached_vm_reports_its_node_left() {
        let mesh = mesh(v1::MeshEnrollmentAuthSource::HostedCurrent);
        assert_eq!(
            remove_result(&removed(), Some((&mesh, &MeshNodeRemoval::Revoked))).render(PLAIN),
            "✓ Environment app removed\n  local VM · environment disk removed · Mesh node app left team\n\n→ cw ls\n"
        );
    }

    /// #2697: a failed revoke leaves the removal done and names the exact
    /// command that removes the node, on the attachment's own Mesh; the exit
    /// status is unchanged.
    #[test]
    fn a_failed_revoke_names_the_exact_command_and_keeps_the_exit_status() {
        let kept = MeshNodeRemoval::Kept("Mesh unavailable".to_owned());
        for (source, command) in [
            (
                v1::MeshEnrollmentAuthSource::HostedCurrent,
                "cw --cloud network revoke app --org org-demo --network team",
            ),
            (
                v1::MeshEnrollmentAuthSource::StandaloneLocal,
                "cw --local network revoke app --org org-demo --network team",
            ),
        ] {
            let mesh = mesh(source);
            assert_eq!(
                remove_result(&removed(), Some((&mesh, &kept))).render(PLAIN),
                format!(
                    "✓ Environment app removed\n  local VM · environment disk removed\n\n\
                     ! Mesh node app is still registered in team\n  \
                     It was not revoked: Mesh unavailable. It shows offline until it is.\n\n\
                     → {command}\n"
                )
            );
            let caps = crate::commands::lifecycle_output::capabilities(OutputFormat::Json);
            assert!(
                report_removal(OutputFormat::Json, &caps, &removed(), Some((&mesh, &kept))).is_ok(),
                "a failed revoke never fails the removal"
            );
        }
        // With cleanup also pending, both are reported.
        let mut pending = removed();
        pending.cleanup_pending = true;
        let mesh = mesh(v1::MeshEnrollmentAuthSource::HostedCurrent);
        let text = remove_result(&pending, Some((&mesh, &kept))).render(PLAIN);
        assert!(text.contains("! Cleanup needs inspection\n"));
        assert!(text.contains("! Mesh node app is still registered in team\n"));
    }

    /// #2697: the revoke goes to the attachment's exact Mesh with the
    /// owner's credential; a node already gone counts as revoked, and any
    /// other refusal keeps the node with the reason.
    #[tokio::test]
    async fn the_revoke_reaches_the_attachments_mesh_and_reads_its_answer() {
        use buffa::Message as _;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        for (status, expected) in [
            (200, MeshNodeRemoval::Revoked),
            (404, MeshNodeRemoval::Revoked),
            (403, MeshNodeRemoval::Kept(String::new())),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/codewire.v1.MeshNodeService/RevokeMeshNode"))
                .and(header("authorization", "Bearer cw_owner"))
                .respond_with(move |request: &wiremock::Request| {
                    let mut body = request.body.as_slice();
                    let request = codewire_client::RevokeMeshNodeRequest::decode(&mut body)
                        .expect("decode revoke request");
                    assert_eq!(
                        (
                            request.org_id.as_str(),
                            request.network_id.as_str(),
                            request.node_name.as_str()
                        ),
                        ("org-demo", "team", "app")
                    );
                    match status {
                        200 => ResponseTemplate::new(200)
                            .insert_header("content-type", "application/proto")
                            .set_body_bytes(
                                codewire_client::RevokeMeshNodeResponse::default().encode_to_vec(),
                            ),
                        404 => ResponseTemplate::new(404).set_body_json(serde_json::json!({
                            "code": "not_found",
                            "message": "Mesh node not found",
                        })),
                        _ => ResponseTemplate::new(403).set_body_json(serde_json::json!({
                            "code": "permission_denied",
                            "message": "forbidden",
                        })),
                    }
                })
                .expect(1)
                .mount(&server)
                .await;
            let attachment =
                codewire_local_vmm::mesh_ingress::MeshAttachment::new_with_auth_source(
                    codewire_local_vmm::mesh_enrollment::MeshEnrollmentAuthSource::StandaloneLocal,
                    &server.uri(),
                    "org-demo",
                    "team",
                    "app",
                    [],
                )
                .unwrap();
            let outcome = revoke_mesh_node_with(
                &attachment,
                codewire_client::StaticTokenProvider::from_token(
                    codewire_client::BearerToken::new("cw_owner").unwrap(),
                ),
            )
            .await;
            match (&expected, &outcome) {
                (MeshNodeRemoval::Kept(_), MeshNodeRemoval::Kept(reason)) => {
                    assert!(!reason.is_empty(), "a kept node says why")
                }
                _ => assert_eq!(outcome, expected, "status {status}"),
            }
        }
    }
}
