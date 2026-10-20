//! Explicit platform calls. Native lifecycle resolution and private role
//! configuration are never consulted here.
use super::*;
use codewire_client::CodewireClient;
use codewire_client::cw_runtime as rpc;
use codewire_cw_release::identity::CwPayloadIdentity;

mod source;
#[cfg(test)]
mod tests;

fn identity(value: &CwPayloadIdentity) -> rpc::EnvironmentCwRuntimeIdentity {
    rpc::EnvironmentCwRuntimeIdentity {
        schema_version: value.schema_version,
        package_version: value.package_version.clone(),
        protocol_version: value.protocol_version,
        record_version: value.record_version,
        target: value.target.clone(),
        source_revision: value.source_revision.clone(),
        source_tree_sha256: value.source_tree_sha256.clone(),
        rustc: value.rustc.clone(),
        sha256: value.sha256.clone(),
        size: value.size,
        ..Default::default()
    }
}

fn expected(
    info: &rpc::GetEnvironmentCwRuntimeResponse,
    generation: u64,
) -> anyhow::Result<rpc::EnvironmentCwRuntimeExpectation> {
    let selection = info
        .selection
        .as_option()
        .context("runtime status omitted selection")?;
    anyhow::ensure!(
        info.supported_image,
        "this Pod has no admitted runtime role; verified helper bootstrap is required"
    );
    anyhow::ensure!(
        selection.generation == generation,
        "observed runtime Store generation changed; review status before a new request"
    );
    anyhow::ensure!(
        !selection.pending && selection.consistent,
        "runtime Store is pending or inconsistent; no recovery is performed by this command"
    );
    let current = selection
        .current
        .as_option()
        .map(|value| value.sha256.clone());
    let previous = selection
        .previous
        .as_option()
        .map(|value| value.sha256.clone());
    anyhow::ensure!(
        (generation == 0) == current.is_none(),
        "runtime status omitted the selected identity"
    );
    Ok(rpc::EnvironmentCwRuntimeExpectation {
        generation,
        current_sha256: current,
        previous_sha256: previous,
        ..Default::default()
    })
}

async fn resolve_runtime_environment_id(
    client: &EnvironmentClient,
    org_id: &str,
    reference: &str,
) -> anyhow::Result<String> {
    let reference = trimmed_required(reference, "environment reference")?;
    if let Ok(id) = uuid::Uuid::parse_str(reference) {
        anyhow::ensure!(!id.is_nil(), "runtime environment UUID must not be nil");
        // A UUID fixes the requested scope even when it is absent or denied.
        // Only names may enter the legacy lookup and name-fallback path.
        return Ok(id.to_string());
    }
    let explicit_uuid = reference.starts_with('{')
        || reference.ends_with('}')
        || reference
            .get(..9)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("urn:uuid:"))
        || (reference.len() == 36
            && [8, 13, 18, 23]
                .into_iter()
                .all(|index| reference.as_bytes()[index] == b'-'));
    anyhow::ensure!(!explicit_uuid, "invalid runtime environment UUID");
    resolve_environment_id(client, org_id, reference).await
}

pub(super) async fn handle(globals: &Globals, command: EnvRuntimeCommand) -> anyhow::Result<()> {
    // Resolve only the explicit platform. The server owns current operator
    // authorization and captures the original Pod before any journal effect.
    let env = OsEnv;
    let paths = ResolvePaths::from_env(&env)?;
    let platform = resolve_platform(globals, &paths, &env)?;
    let orgs = organization_client(&platform)?
        .list_orgs()
        .await
        .context("list orgs")?;
    let org_id = current_org_id(&platform, &orgs)?;
    let client = codewire_client(&platform)?;
    let environment_client = EnvironmentClient::new(&platform)?;
    let reference = match &command {
        EnvRuntimeCommand::Info(a) => &a.environment,
        EnvRuntimeCommand::Update(a) => &a.environment,
        EnvRuntimeCommand::Rollback(a) => &a.environment,
        EnvRuntimeCommand::Observe(a) | EnvRuntimeCommand::Cancel(a) => &a.environment,
    };
    let id = resolve_runtime_environment_id(&environment_client, &org_id, reference).await?;
    match command {
        EnvRuntimeCommand::Info(args) => {
            let info = status(&client, &org_id, &id).await?;
            print_status(&info, args.output)
        }
        EnvRuntimeCommand::Observe(args) => {
            let response = client
                .observe_environment_cw_runtime(rpc::ObserveEnvironmentCwRuntimeRequest {
                    org_id,
                    environment_id: id,
                    request_id: args.request_id.to_string(),
                    ..Default::default()
                })
                .await?;
            let operation = response
                .operation
                .into_option()
                .context("runtime observation omitted the saved operation")?;
            anyhow::ensure!(
                operation.request_id == args.request_id.to_string(),
                "runtime observation changed the request UUID"
            );
            print_operation(&operation, args.output)
        }
        EnvRuntimeCommand::Update(args) => {
            let source = source::Candidate::open(
                args.from
                    .as_deref()
                    .context("platform release directory is required")?,
                &args.target_sha256,
            )?;
            let info = status(&client, &org_id, &id).await?;
            let expected = expected(
                &info,
                args.expected_generation
                    .context("platform generation is required")?,
            )?;
            let request_id = args
                .request_id
                .unwrap_or_else(uuid::Uuid::new_v4)
                .to_string();
            let bootstrap = if expected.generation == 0 {
                Some(
                    info.bootstrap_identity
                        .into_option()
                        .context("image identity is unavailable for bootstrap")?,
                )
            } else {
                None
            };
            let header = rpc::UpdateEnvironmentCwRuntimeHeader {
                org_id: org_id.clone(),
                environment_id: id.clone(),
                request_id: request_id.clone(),
                expected_incarnation: Some(
                    info.incarnation
                        .into_option()
                        .context("runtime status omitted original Pod incarnation")?,
                )
                .into(),
                expected_selection: Some(expected).into(),
                identity: Some(identity(&source.identity)).into(),
                bootstrap_identity: bootstrap.into(),
                ..Default::default()
            };
            source.recheck()?;
            print_observe_command(&id, &request_id);
            let response = client
                .update_environment_cw_runtime(header, tokio_stream::iter(source))
                .await?;
            follow(
                &client,
                &org_id,
                &id,
                &request_id,
                response
                    .operation
                    .into_option()
                    .context("runtime update omitted operation")?,
                args.output,
            )
            .await
        }
        EnvRuntimeCommand::Rollback(args) => {
            let info = status(&client, &org_id, &id).await?;
            let expected = expected(
                &info,
                args.expected_generation
                    .context("platform generation is required")?,
            )?;
            let previous = info
                .selection
                .previous
                .as_option()
                .context("no retained previous cw")?
                .clone();
            let request_id = args
                .request_id
                .unwrap_or_else(uuid::Uuid::new_v4)
                .to_string();
            let request = rpc::RollbackEnvironmentCwRuntimeRequest {
                org_id: org_id.clone(),
                environment_id: id.clone(),
                request_id: request_id.clone(),
                expected_incarnation: Some(
                    info.incarnation
                        .into_option()
                        .context("runtime status omitted original Pod incarnation")?,
                )
                .into(),
                expected_selection: Some(expected).into(),
                identity: Some(previous).into(),
                ..Default::default()
            };
            print_observe_command(&id, &request_id);
            let response = client.rollback_environment_cw_runtime(request).await?;
            follow(
                &client,
                &org_id,
                &id,
                &request_id,
                response
                    .operation
                    .into_option()
                    .context("runtime rollback omitted operation")?,
                args.output,
            )
            .await
        }
        EnvRuntimeCommand::Cancel(_) => {
            anyhow::bail!("platform runtime requests are observe-only after dispatch")
        }
    }
}

async fn status(
    client: &CodewireClient,
    org: &str,
    id: &str,
) -> anyhow::Result<rpc::GetEnvironmentCwRuntimeResponse> {
    let response = client
        .get_environment_cw_runtime(rpc::GetEnvironmentCwRuntimeRequest {
            org_id: org.into(),
            environment_id: id.into(),
            ..Default::default()
        })
        .await?;
    anyhow::ensure!(
        response
            .incarnation
            .as_option()
            .is_some_and(|inc| inc.org_id == org && inc.environment_id == id),
        "runtime status scope changed"
    );
    Ok(response)
}

fn print_observe_command(id: &str, request_id: &str) {
    eprintln!(
        "Runtime request: {request_id}; observe with cw --cloud runtime observe {id} --request-id {request_id}"
    );
}

fn print_status(
    info: &rpc::GetEnvironmentCwRuntimeResponse,
    output: OutputFormat,
) -> anyhow::Result<()> {
    if output == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(info)?);
        return Ok(());
    }
    let incarnation = info
        .incarnation
        .as_option()
        .context("runtime status omitted incarnation")?;
    let selection = info
        .selection
        .as_option()
        .context("runtime status omitted selection")?;
    println!(
        "Environment: {}\nPod incarnation: {}\nSupported image: {}\nStore generation: {}\nDefault cw: {}\nPrevious cw: {}\nPending: {}\nConsistent: {}\nRetained versions: {}",
        incarnation.environment_id,
        incarnation.pod_uid,
        info.supported_image,
        selection.generation,
        selection
            .current
            .as_option()
            .map(|v| v.sha256.as_str())
            .unwrap_or("none"),
        selection
            .previous
            .as_option()
            .map(|v| v.sha256.as_str())
            .unwrap_or("none"),
        selection.pending,
        selection.consistent,
        selection.retained_count
    );
    Ok(())
}

fn print_operation(
    operation: &rpc::EnvironmentCwRuntimeOperation,
    output: OutputFormat,
) -> anyhow::Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(operation)?),
        OutputFormat::Text => {
            println!(
                "Request: {}\nAction: {}\nPhase: {}\nCheckpoint: {}",
                operation.request_id, operation.action, operation.phase, operation.checkpoint
            );
            if let Some(code) = &operation.error_code {
                println!("Error: {code}");
            }
        }
    }
    Ok(())
}

async fn follow(
    client: &CodewireClient,
    org: &str,
    id: &str,
    request: &str,
    mut operation: rpc::EnvironmentCwRuntimeOperation,
    output: OutputFormat,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        anyhow::ensure!(
            operation.request_id == request,
            "runtime receipt changed the original request UUID"
        );
        match operation.phase.as_str() {
            "succeeded" => {
                print_operation(&operation, output)?;
                return Ok(());
            }
            "failed" | "unknown" | "issued" => {
                print_operation(&operation, output)?;
                anyhow::bail!(
                    "runtime request {request} ended or remains {}; observe this SAME request UUID; no replay is performed",
                    operation.phase
                );
            }
            "admitted" | "acknowledged" if Instant::now() < deadline => {}
            _ => {
                print_operation(&operation, output)?;
                anyhow::bail!(
                    "runtime request {request} remains uncertain; observe the SAME request UUID"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let response = client
            .observe_environment_cw_runtime(rpc::ObserveEnvironmentCwRuntimeRequest {
                org_id: org.into(),
                environment_id: id.into(),
                request_id: request.into(),
                ..Default::default()
            })
            .await
            .context("observe the original runtime request; no replay is performed")?;
        operation = response
            .operation
            .into_option()
            .context("runtime observation omitted saved operation")?;
    }
}
