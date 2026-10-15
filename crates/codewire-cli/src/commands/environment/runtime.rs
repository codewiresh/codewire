//! Explicit runtime changes; never environment lifecycle effects.
use super::*;

mod platform;

pub(super) async fn handle(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    command: EnvRuntimeCommand,
) -> anyhow::Result<()> {
    validate_placement(placement, &command)?;
    if placement == Some(EnvironmentPlacement::Platform) {
        return platform::handle(globals, command).await;
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        handle_linux(command).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = command;
        anyhow::bail!(
            "live cw runtime updates require native Linux protocol9; this host is unsupported"
        )
    }
}

fn validate_placement(
    placement: Option<EnvironmentPlacement>,
    command: &EnvRuntimeCommand,
) -> anyhow::Result<()> {
    let platform = placement == Some(EnvironmentPlacement::Platform);
    match command {
        EnvRuntimeCommand::Update(args) => anyhow::ensure!(
            if platform {
                args.from.is_some()
                    && args.expected_generation.is_some()
                    && args.source.is_none()
                    && args.image_sha256.is_none()
                    && args.expected_revision.is_none()
            } else {
                args.from.is_none()
                    && args.expected_generation.is_none()
                    && args.source.is_some()
                    && args.image_sha256.is_some()
                    && args.expected_revision.is_some()
            },
            "platform updates require --cloud --from DIR --expected-generation; native updates require --source --image-sha256 --expected-revision"
        ),
        EnvRuntimeCommand::Rollback(args) => anyhow::ensure!(
            if platform {
                args.expected_generation.is_some() && args.expected_revision.is_none()
            } else {
                args.expected_revision.is_some() && args.expected_generation.is_none()
            },
            "platform rollback requires --cloud --expected-generation; native rollback requires --expected-revision"
        ),
        EnvRuntimeCommand::Cancel(_) if platform => anyhow::bail!(
            "platform runtime requests are observe-only after dispatch; use observe with the original request UUID"
        ),
        _ => {}
    }
    Ok(())
}

fn selection(
    status: &codewire_local_vmm::control::v1::LinuxCwRuntimeStatus,
) -> anyhow::Result<codewire_local_vmm::cw_runtime::RuntimeSelection> {
    let selection: codewire_local_vmm::cw_runtime::RuntimeSelection =
        serde_json::from_slice(&status.selection_json)
            .context("decode admitted runtime selection")?;
    selection.validate().map_err(anyhow::Error::msg)?;
    if selection.environment_id.to_string() != status.environment_id || status.generation == 0 {
        anyhow::bail!("runtime selection environment identity changed");
    }
    Ok(selection)
}

fn print(
    status: &codewire_local_vmm::control::v1::LinuxCwRuntimeStatus,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let selected = selection(status)?;
    match output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "environment_id":status.environment_id, "generation":status.generation,
                "selection":selected, "operation_id":status.operation_id, "request_id":status.request_id,
                "phase":status.phase, "error_code":status.error_code, "interrupted_request_ids":status.interrupted_request_ids,
            }))?
        ),
        OutputFormat::Text => {
            println!(
                "Environment: {}\nVM generation: {}\nBootstrap: {}\nSelection revision: {}\nDefault cw: {}\nPrevious cw: {}\nRetained versions: {}",
                status.environment_id,
                status.generation,
                selected.bootstrap_catalog_sha256,
                selected.revision,
                selected.catalog.active_sha256,
                selected.previous_sha256.as_deref().unwrap_or("none"),
                selected.catalog.runtimes.len()
            );
            if !status.interrupted_request_ids.is_empty() {
                println!(
                    "Retained interrupted requests with unknown effects: {}",
                    status.interrupted_request_ids.join(", ")
                );
            }
            if !status.operation_id.is_empty() {
                println!(
                    "Operation: {}\nRequest: {}\nPhase: {}",
                    status.operation_id, status.request_id, status.phase
                );
                if let Some(receipt) = selected
                    .operations
                    .iter()
                    .find(|receipt| receipt.operation_id.to_string() == status.operation_id)
                {
                    println!("Observed effect: {:?}", receipt.outcome);
                }
            }
        }
    }
    Ok(())
}

async fn handle_linux(command: EnvRuntimeCommand) -> anyhow::Result<()> {
    use codewire_local_vmm::control::v1;
    use uuid::Uuid;
    let environment = match &command {
        EnvRuntimeCommand::Info(args) => &args.environment,
        EnvRuntimeCommand::Update(args) => &args.environment,
        EnvRuntimeCommand::Rollback(args) => &args.environment,
        EnvRuntimeCommand::Observe(args) | EnvRuntimeCommand::Cancel(args) => &args.environment,
    };
    let environment = trimmed_required(environment, "explicit native environment")?;
    let client = native_runtime_control_client().await?;
    // Generic List/Get may replay pending lifecycle work. The runtime service
    // resolves only saved identity, and UUID input never falls through to a name.
    let id = client
        .runtime_resolve(environment)
        .await
        .context("resolve explicit native environment without lifecycle effects")?;
    match command {
        EnvRuntimeCommand::Info(args) => print(&client.runtime_info(&id).await?, args.output),
        EnvRuntimeCommand::Observe(args) => print(
            &client
                .runtime_observe(&id, &args.request_id.to_string())
                .await?,
            args.output,
        ),
        EnvRuntimeCommand::Cancel(args) => print(
            &client
                .runtime_cancel(&id, &args.request_id.to_string())
                .await?,
            args.output,
        ),
        EnvRuntimeCommand::Update(args) => {
            let current = client.runtime_info(&id).await?;
            let selected = selection(&current)?;
            let request_id = args.request_id.unwrap_or_else(Uuid::new_v4);
            let source =
                fs::canonicalize(args.source.as_ref().context("native source is required")?)
                    .context("resolve admitted local image source lock")?;
            let request = v1::LinuxCwRuntimeMutation {
                environment_id: id.clone(),
                generation: current.generation,
                bootstrap_catalog_sha256: selected.bootstrap_catalog_sha256,
                request_id: request_id.to_string(),
                expected_revision: args
                    .expected_revision
                    .context("native revision is required")?,
                target_sha256: args.target_sha256,
                image_index_sha256: args.image_sha256.context("native image pin is required")?,
                source_lock: source
                    .into_os_string()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("runtime source path is not UTF8"))?,
            };
            eprintln!(
                "Runtime request: {request_id}; observe with cw env --local runtime observe {id} --request-id {request_id}"
            );
            let status = client
                .runtime_update(request)
                .await
                .context("admit runtime update; retain request UUID on an uncertain reply")?;
            follow(&client, &id, status, args.output).await
        }
        EnvRuntimeCommand::Rollback(args) => {
            let current = client.runtime_info(&id).await?;
            let selected = selection(&current)?;
            let request_id = args.request_id.unwrap_or_else(Uuid::new_v4);
            let request = v1::LinuxCwRuntimeMutation {
                environment_id: id.clone(),
                generation: current.generation,
                bootstrap_catalog_sha256: selected.bootstrap_catalog_sha256,
                request_id: request_id.to_string(),
                expected_revision: args
                    .expected_revision
                    .context("native revision is required")?,
                target_sha256: selected
                    .previous_sha256
                    .context("no retained previous cw runtime")?,
                image_index_sha256: String::new(),
                source_lock: String::new(),
            };
            eprintln!(
                "Runtime request: {request_id}; observe with cw env --local runtime observe {id} --request-id {request_id}"
            );
            let status = client
                .runtime_rollback(request)
                .await
                .context("admit runtime rollback; retain request UUID on an uncertain reply")?;
            follow(&client, &id, status, args.output).await
        }
    }
}

async fn follow(
    client: &codewire_local_vmm::supervisor::NativeSupervisorClient,
    id: &str,
    mut status: codewire_local_vmm::control::v1::LinuxCwRuntimeStatus,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(300);
    while !matches!(
        status.phase.as_str(),
        "completed" | "failed" | "interrupted"
    ) {
        if Instant::now() >= deadline {
            print(&status, output)?;
            anyhow::bail!(
                "runtime request {} remains uncertain; observe or cancel this SAME request, do not replay",
                status.request_id
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        status = client
            .runtime_observe(id, &status.request_id)
            .await
            .context("runtime reply unavailable; observe the SAME request UUID")?;
    }
    print(&status, output)?;
    if status.phase != "completed" {
        anyhow::bail!(
            "runtime request ended {}; effect is not assumed unchanged",
            status.phase
        );
    }
    let selected = selection(&status)?;
    if selected.operations.iter().any(|receipt| {
        receipt.operation_id.to_string() == status.operation_id
            && receipt.outcome == codewire_local_vmm::cw_runtime::SelectionOutcome::Cancelled
    }) {
        anyhow::bail!("runtime request was cancelled before selector commit");
    }
    Ok(())
}
