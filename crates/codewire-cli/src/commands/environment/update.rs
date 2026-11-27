//! `cw update ENV`: an existing environment's secret and credential sources,
//! network policy, idle stop, idle suspend and, from a file, its startup
//! script.

use super::*;

mod file;

pub(super) async fn handle_unified(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    mut args: EnvUpdateArgs,
) -> anyhow::Result<()> {
    sources::validate_update_args(&args)?;
    let target =
        resolve_unified_environment_target(globals, placement, &args.environment, "update").await?;
    match target {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        UnifiedEnvironmentTarget::NativeLocal(name) => {
            if !args.file.is_empty() {
                return Err(local_file_refusal());
            }
            args.environment = name;
            handle_native_environment_update(globals, args).await
        }
        UnifiedEnvironmentTarget::Platform(id) => {
            args.environment = id;
            handle_platform_env_command(globals, EnvCommand::Update(args)).await
        }
    }
}

/// A local VM's setup is sealed when it is created (SPEC.md, #5949), so its
/// startup script doesn't change from a file.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn local_file_refusal() -> anyhow::Error {
    crate::error_report::with_next_step(
        anyhow::anyhow!(
            "a local VM's setup is sealed when it is created, so `cw update --file` can't change its startup script; nothing was changed"
        ),
        "cw --local create --file codewire.yaml",
    )
}

/// A cloud environment's update, once its organization is resolved.
pub(super) async fn platform(
    globals: &Globals,
    platform: &config::ResolvedPlatformConfig,
    environment_client: &EnvironmentClient,
    org_id: &str,
    mut args: EnvUpdateArgs,
) -> anyhow::Result<()> {
    if !args.file.is_empty() {
        return file::platform(platform, environment_client, org_id, args).await;
    }
    let policy = args.policy.take();
    let idle_stop = args
        .idle_stop
        .take()
        .as_deref()
        .map(codewire_project::parse_idle_stop)
        .transpose()?;
    let idle_suspend = args
        .idle_suspend
        .take()
        .as_deref()
        .map(codewire_project::parse_idle_suspend)
        .transpose()?;
    let idle_hibernate = args
        .idle_hibernate
        .take()
        .as_deref()
        .map(codewire_project::parse_idle_hibernate)
        .transpose()?;
    let output = args.output;
    let environment = args.environment.clone();
    let sources_changed = args.clear_secrets
        || args.clear_profile
        || args.secrets.is_some()
        || args.user_secrets.is_some()
        || args.org_secrets
        || args.profile.is_some();
    if sources_changed
        || (policy.is_none()
            && idle_stop.is_none()
            && idle_suspend.is_none()
            && idle_hibernate.is_none())
    {
        sources::update_platform_sources(platform, environment_client, org_id, args).await?;
    }
    if let Some(reference) = policy {
        update_platform_network_policy(
            globals,
            environment_client,
            org_id,
            &environment,
            &reference,
            output,
        )
        .await?;
    }
    if let Some(idle_stop_seconds) = idle_stop {
        let environment_id =
            resolve_environment_id(environment_client, org_id, &environment).await?;
        let response = environment_client
            .set_environment_idle_stop(org_id, &environment_id, idle_stop_seconds)
            .await
            .context("set idle stop")?;
        print_env_idle_stop_status(&environment, &response, idle_stop_seconds, output)?;
        idle_stop::note_after_update(environment_client, org_id, &environment_id, output).await;
    }
    // A runtime that can't suspend is refused by the server, by name.
    if let Some(idle_suspend_seconds) = idle_suspend {
        let environment_id =
            resolve_environment_id(environment_client, org_id, &environment).await?;
        let response = environment_client
            .set_environment_idle_suspend(org_id, &environment_id, idle_suspend_seconds)
            .await
            .context("set idle suspend")?;
        idle_suspend::print_status(&environment, &response, idle_suspend_seconds, output)?;
    }
    // A runtime that can't hibernate is refused by the server, by name.
    if let Some(idle_hibernate_seconds) = idle_hibernate {
        let environment_id =
            resolve_environment_id(environment_client, org_id, &environment).await?;
        let response = environment_client
            .set_environment_idle_hibernate(org_id, &environment_id, idle_hibernate_seconds)
            .await
            .context("set idle hibernate")?;
        idle_hibernate::print_status(&environment, &response, idle_hibernate_seconds, output)?;
    }
    Ok(())
}
