use super::*;

/// What one environment's runtime is, as intent for the driver (#3628 PR
/// 8b): its image, isolation, shape and identity under the captured operation
/// authority. The checks here need no deployment configuration; the driver
/// makes the rest when it renders.
pub fn environment_rendering_intent(
    image_ref: &str,
    template_base: &str,
    env: &EnvironmentRow,
    operation_generation: i64,
) -> anyhow::Result<RenderingIntent> {
    anyhow::ensure!(
        operation_generation > 0 && env.operation_generation == operation_generation,
        "template metadata no longer matches operation authority"
    );
    let selection = env
        .projection_selection
        .as_ref()
        .map_err(|_| anyhow::anyhow!("invalid platform environment projection selection"))?;
    let projection_selection_sha256 = selection
        .as_ref()
        .map(|selection| selection.sha256())
        .transpose()?;
    let managed_credential_clients = *env
        .managed_credential_clients
        .as_ref()
        .map_err(|_| anyhow::anyhow!("invalid managed credential client selection"))?;
    managed_credential_clients
        .check_collisions(env.project_spec.environment.keys().map(String::as_str))?;
    // Without a profile, the only managed client is the creator's own GitHub
    // connection for a selected GitHub repository.
    let account_github = codewire_access::ManagedCredentialClients::from_profile_slots(["github"])?;
    anyhow::ensure!(
        managed_credential_clients == Default::default()
            || selection.as_ref().is_some_and(|selection| {
                selection.profile.is_some() || managed_credential_clients == account_github
            }),
        "managed credential clients require an exact selected profile"
    );
    Ok(RenderingIntent {
        image: image_ref.to_owned(),
        template_base: template_base.to_owned(),
        isolation: Isolation::of_tier(&env.isolation_tier)
            .expect("environment isolation tier is validated at creation"),
        dedicated_cpu: env.dedicated_cpu,
        systemd_workspace: env.systemd_workspace,
        systemd_runtime_profile: env.systemd_runtime_profile.clone(),
        // The driver checks it with the profile it renders on.
        systemd_opted_in: env.systemd_environments_enabled,
        shape: WorkspaceShape {
            cpu_millicores: i64::from(env.cpu_millicores),
            memory_mib: i64::from(env.memory_mb),
            disk_gib: i64::from(env.disk_gb),
        },
        identity: RenderingIdentity {
            environment_id: env.id.clone(),
            organization_id: env.org_id.clone(),
            operation_generation,
            projection_selection_sha256,
            managed_credential_clients,
            source_snapshot_id: env.source_snapshot_id.clone(),
            confidential_storage_manifest_uri: String::new(),
        },
    })
}
