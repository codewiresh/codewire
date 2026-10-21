//! Local environment lifecycle results: the start/create summary and its
//! working context, stop and remove outcomes, and failures that name the
//! stage that stopped.

use codewire_project::{ProjectSpec, StoragePlacement};

use super::*;
use crate::commands::lifecycle_output::{
    InterruptNotice, ResultBlock, bounded, credential_ref, environment_command, exact_reference_id,
    location_label, next_run_command, print_context, print_summary, secret_refs,
};
use crate::output::{
    Allocation, Capabilities, LifecycleSummary, MeshPlacement, NetworkRef, Outcome, SourceRef,
    Status, VmLocation,
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
        secrets,
        network: network_ref(environment.mesh.as_ref()),
        next: Some(next_run_command(VmLocation::Local, &environment.name)),
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

/// A lifecycle call that failed after its progress began: the stage it
/// stopped at, the supervisor's reason, and, for an environment that
/// existed before the call, its state afterwards and where to look.
pub(super) async fn lifecycle_failure(
    verb: &str,
    name: &str,
    stage: Option<&str>,
    error: anyhow::Error,
    inspect: bool,
) -> anyhow::Error {
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
    anyhow::anyhow!("{head}: {error:#}\n{after}")
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
    let started = match started {
        Ok(started) => started,
        Err((stage, error)) => {
            return Err(lifecycle_failure("start", &environment.name, stage, error, true).await);
        }
    };
    match output {
        OutputFormat::Json => print_native_environment(&started, output),
        OutputFormat::Text => {
            print_summary(&local_summary(&started, Outcome::Started, secrets), &caps);
            Ok(())
        }
    }
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
    let environment = get_native_environment_with_required_authority(&mut client, name).await?;
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
    output: OutputFormat,
) -> anyhow::Result<()> {
    let caps = crate::commands::lifecycle_output::capabilities(output);
    let mut client = native_client().await?;
    let environment = get_native_environment_with_authority_recovery(&mut client, name).await?;
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
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "name": removed.name,
                "removed": removed.removed,
                "cleanup_pending": removed.cleanup_pending,
            }))?
        ),
        OutputFormat::Text => remove_result(&removed).print(&caps),
    }
    Ok(())
}

/// Removed, removed with cleanup pending, or not confirmed.
pub(super) fn remove_result(removed: &v1::DeleteEnvironmentResponse) -> ResultBlock {
    let name = &removed.name;
    let local = location_label(VmLocation::Local);
    let block = if removed.removed {
        ResultBlock::new(Status::Done, format!("Environment {name} removed"))
            .detail(format!("{local} · environment disk removed"))
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
    block.next("cw ls")
}

/// The working context of a create, from what it will request.
pub(super) struct CreateContext {
    pub(super) credentials: SourceRef,
    pub(super) secrets: SourceRef,
    pub(super) network: NetworkRef,
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
            secrets: self.secrets.clone(),
            network: self.network.clone(),
            next: Some(next_run_command(VmLocation::Local, name)),
        }
    }
}

/// Prints the summary of a created environment; JSON keeps its shape.
pub(crate) fn print_native_created(
    created: &NativeCreated,
    output: OutputFormat,
    caps: &Capabilities,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => print_native_environment(&created.environment, output),
        OutputFormat::Text => {
            print_summary(
                &local_summary(
                    &created.environment,
                    Outcome::Created,
                    created.secrets.clone(),
                ),
                caps,
            );
            Ok(())
        }
    }
}

/// A created local environment and its secrets reference, named while the
/// selection was made.
pub(crate) struct NativeCreated {
    pub(crate) environment: v1::Environment,
    pub(crate) secrets: SourceRef,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Charset, Style};

    const PLAIN: Style = Style::new(false, Charset::Unicode);
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
            "✓ Environment app started · local VM\n  2 vCPU · 4 GiB RAM · 40 GiB disk\n\n  Credentials: local:work\n  Secrets:     local:id:x\n  Network:     cloud:work\n\n→ cw --local run claude --in app\n"
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
            remove_result(&removed).render(PLAIN),
            "✓ Environment app removed\n  local VM · environment disk removed\n\n→ cw ls\n"
        );
        removed.cleanup_pending = true;
        let text = remove_result(&removed).render(PLAIN);
        assert!(text.starts_with("✓ Environment app removed\n"));
        assert!(text.contains("\n! Cleanup needs inspection\n  An unsafe or unknown object remains quarantined; inspect it with `cw doctor local`.\n"));
        removed.removed = false;
        assert!(
            remove_result(&removed)
                .render(PLAIN)
                .starts_with("! Removal of app was not confirmed\n")
        );
    }
}
