//! `cw create` in the cloud.

use super::*;

/// `cw create` in the cloud.
/// It lists organizations only if it needs one before it asks (#3747).
pub(super) async fn handle_platform_env_create(
    globals: &Globals,
    paths: &ResolvePaths,
    mut args: EnvCreateArgs,
) -> anyhow::Result<Option<Environment>> {
    // A create reads and checks its configuration, and names where it came
    // from, before it reads the platform settings or sends any request.
    let source = project_file::select_from(
        &project_file::invoking_directory()?,
        &args.file,
        args.no_file,
    )?;
    let mut prepared = prepare_platform_env_create(&args, &source)?;
    if matches!(args.output, OutputFormat::Text) {
        eprintln!("Configuration: {}", prepared.1.text());
    }
    let guided_flow = args.guided && super::super::guided::available(args.output) && !args.yes;
    let platform =
        &super::super::launch_setup::resolve_guided_platform(globals, paths, guided_flow).await?;
    // A network a cloud create can never use is refused before any request.
    refuse_requested_cloud_mesh(args.network.as_deref(), args.no_network)?;
    let environment_client = &EnvironmentClient::new(platform)?;
    let organization_client = &organization_client(platform)?;
    let org = CreateOrganization::new(platform, organization_client, globals.org.as_deref());
    if guided_flow {
        let located = globals.with_org(Some(org.for_setup(globals).await?.to_owned()));
        super::super::launch_setup::edit_cloud_create(&located, &mut args, &prepared.0).await?;
        // Apply edits through the same resolver and file precedence as
        // the original validated request, before any create request.
        let source = project_file::select_from(
            &project_file::invoking_directory()?,
            &args.file,
            args.no_file,
        )?;
        prepared = prepare_platform_env_create(&args, &source)?;
    }
    let began = Instant::now();
    let (mut request, provenance) = prepared;
    request.source_snapshot_id = args.snapshot.clone();
    host_placement::apply(&args, &mut request)?;
    let env = OsEnv;
    let mesh = if create_mesh_needs_organization(
        paths,
        &env,
        platform,
        args.network.as_deref(),
        args.no_network,
    )? {
        resolve_env_create_mesh_bootstrap(
            paths,
            &env,
            platform,
            org.id().await?,
            args.yes,
            args.network.as_deref(),
            args.no_network,
        )?
    } else {
        if !args.no_network {
            print_legacy_selection_notice(&paths.mesh_data_dir);
        }
        None
    };
    if let Some(mesh) = mesh {
        require_cloud_network_membership(globals, paths, &env, &mesh).await?;
        request.network = Some(mesh.network_id);
    }
    request.network_policy = args.policy.clone().map(String::from);
    let names =
        sources::prepare_create_sources(platform, environment_client, &org, &args, &mut request)
            .await?;
    // Only the guided create reviews, and it already knows its organization.
    if guided_flow
        && !super::super::launch_setup::review_cloud_create(&args, &request, org.id().await?)?
    {
        return Ok(None);
    }
    let environment = create_in_organization(environment_client, &org, &request).await?;
    if args.output == OutputFormat::Text
        && let Some(asked) = args.policy.as_deref()
    {
        report_policy_selection(
            asked,
            environment.name.as_deref().unwrap_or(&environment.id),
            environment.network_policy.as_ref(),
        );
    }
    if args.write_preset {
        write_resolved_codewire_yaml(Path::new("codewire.yaml"), &request)
            .context("write codewire.yaml")?;
        eprintln!("Preset written: codewire.yaml");
    }
    if let Some(preset_name) = trimmed_optional(args.save_preset.clone()) {
        let preset_request = create_preset_request_from_environment(&preset_name, &request)?;
        let preset = organization_client
            .create_preset(&environment.org_id, &preset_request)
            .await
            .context("save preset")?;
        eprintln!("Preset saved: {} ({}).", preset.name, preset.id);
    }
    // The credentials its agents can't use are part of the result (#5594).
    let withheld =
        lifecycle::withheld::withheld_credentials(platform, environment.source_selection.as_ref())
            .await;
    match args.output {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &provenance.add_to(serde_json::to_value(&environment)?)
                )?
            );
            lifecycle::withheld::print_withheld(&withheld);
        }
        OutputFormat::Text if args.follow && !args.no_wait => {
            let caps = super::super::lifecycle_output::capabilities(args.output);
            let summary = lifecycle::cloud_summary(&environment, Outcome::Created, &names);
            super::super::lifecycle_output::print_context(&summary, &caps);
            // The platform holds the environment from here on: an
            // interrupt ends only the wait for its setup.
            // Boxed: this command's future stays small enough for a
            // thread's default stack.
            Box::pin(super::super::lifecycle_output::unless_interrupted(
                true,
                wait_for_platform_environment_setup(
                    environment_client,
                    &environment.org_id,
                    &environment,
                    began,
                    &caps,
                ),
            ))
            .await
            .ok_or_else(|| {
                InterruptNotice::new(VmLocation::Cloud, "creation", &summary.name).error(true)
            })??;
            print_with_withheld(summary, &withheld, &caps);
        }
        OutputFormat::Text => {
            // Readiness was not observed: the result is pending.
            let caps = super::super::lifecycle_output::capabilities(args.output);
            print_with_withheld(
                lifecycle::cloud_summary(&environment, Outcome::Creating, &names),
                &withheld,
                &caps,
            );
        }
    }
    Ok(Some(environment))
}

/// The summary, then the credentials its agents can't use, then its next
/// step, as a local create prints them.
fn print_with_withheld(
    mut summary: crate::output::LifecycleSummary,
    withheld: &[String],
    caps: &crate::output::Capabilities,
) {
    let next = summary.next.take();
    super::super::lifecycle_output::print_summary(&summary, caps);
    lifecycle::withheld::print_withheld(withheld);
    if let Some(next) = next {
        print!("{}", crate::output::render_next(&next, caps.stdout_style()));
    }
}
