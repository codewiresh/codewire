//! `cw stop` and `cw start` on a cloud environment.

use super::*;
use crate::commands::lifecycle_output::{Already, already_line};

/// `cw stop ENV` in the cloud: the stop, the wait until it is stopped, and
/// the result.
pub(super) async fn stop(
    environment_client: &EnvironmentClient,
    org_id: &str,
    args: EnvTargetArgs,
) -> anyhow::Result<()> {
    let environment_id =
        resolve_environment_id(environment_client, org_id, &args.environment).await?;
    let caps = crate::commands::lifecycle_output::capabilities(args.output);
    let shown = display_name_for(
        environment_client,
        org_id,
        &environment_id,
        &args.environment,
        &caps,
    )
    .await;
    let name = shown.name.clone();
    let mut line = StatusLine::new(std::io::stderr(), &caps);
    line.begin(STOPPING_LABEL)?;
    let stopped = Box::pin(super::lifecycle::stop_cloud_environment(
        environment_client,
        org_id,
        &environment_id,
        &name,
        &mut line,
        !caps.is_machine(),
        super::lifecycle::StopWait::default(),
    ))
    .await;
    match stopped {
        Ok(()) => line.clear()?,
        Err(error)
            if already(
                environment_client,
                org_id,
                &environment_id,
                &error,
                "stopped",
            )
            .await =>
        {
            line.clear()?;
            return print_already(&args, &name, Already::Stopped, &caps);
        }
        Err(error)
            if crate::commands::lifecycle_output::interrupted_exit_code(&error).is_some() =>
        {
            line.clear()?;
            return Err(error);
        }
        Err(error) => {
            line.fail(STOPPING_LABEL)?;
            return Err(error);
        }
    }
    match args.output {
        OutputFormat::Json => {
            let response = StatusResponse {
                status: "stopped".to_owned(),
            };
            print_env_status(&args.environment, &response, args.output)?;
        }
        OutputFormat::Text => {
            super::lifecycle::stop_result(&name, shown.host.as_deref()).print(&caps)
        }
    }
    Ok(())
}

/// `cw start ENV` in the cloud: the plan, the start's progress, and the
/// result.
pub(super) async fn start(
    platform: &config::ResolvedPlatformConfig,
    environment_client: &EnvironmentClient,
    org_id: &str,
    args: EnvTargetArgs,
) -> anyhow::Result<()> {
    let began = Instant::now();
    let environment_id =
        resolve_environment_id(environment_client, org_id, &args.environment).await?;
    if matches!(args.output, OutputFormat::Text) {
        let caps = crate::commands::lifecycle_output::capabilities(args.output);
        let environment = environment_client
            .get_environment(org_id, &environment_id)
            .await
            .context("get environment")?;
        let names = super::lifecycle::resolve_source_names(
            platform,
            environment_client,
            org_id,
            &environment,
        )
        .await;
        if environment.state == "running" {
            let name = super::lifecycle::display_name(&environment);
            return print_already(&args, &name, Already::Running, &caps);
        }
        let summary = super::lifecycle::cloud_summary(&environment, Outcome::Started, &names);
        crate::commands::lifecycle_output::print_context(&summary, &caps);
        Box::pin(start_platform_environment_with_progress(
            environment_client,
            org_id,
            &environment_id,
            began,
            &caps,
            &InterruptNotice::new(VmLocation::Cloud, "start", &summary.name),
        ))
        .await?;
        crate::commands::lifecycle_output::print_summary(&summary, &caps);
        return Ok(());
    }
    let caps = crate::commands::lifecycle_output::capabilities(args.output);
    let started = Box::pin(start_platform_environment_with_progress(
        environment_client,
        org_id,
        &environment_id,
        began,
        &caps,
        &InterruptNotice::new(VmLocation::Cloud, "start", &args.environment),
    ))
    .await;
    if let Err(error) = started
        && !already(
            environment_client,
            org_id,
            &environment_id,
            &error,
            "running",
        )
        .await
    {
        return Err(error);
    }
    // The start has finished, so report its state, as stop does.
    let response = StatusResponse {
        status: "running".to_owned(),
    };
    print_env_status(&args.environment, &response, args.output)?;
    Ok(())
}

/// Whether the platform refused a stop or a start because the environment
/// is already `state`: it refuses either as `invalid_state` for every state
/// it can't act from, so the state is read once to tell them apart.
async fn already(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
    error: &anyhow::Error,
    state: &str,
) -> bool {
    super::lifecycle::error_has_reason(error, "invalid_state")
        && client
            .get_environment(org_id, environment_id)
            .await
            .is_ok_and(|environment| environment.state == state)
}

/// The result of a stop or start that found the environment as asked: the
/// one line in text, and in JSON the status a finished one reports.
fn print_already(
    args: &EnvTargetArgs,
    name: &str,
    already: Already,
    caps: &crate::output::Capabilities,
) -> anyhow::Result<()> {
    match args.output {
        OutputFormat::Json => {
            let status = match already {
                Already::Stopped => "stopped",
                Already::Running => "running",
            };
            let response = StatusResponse {
                status: status.to_owned(),
            };
            print_env_status(&args.environment, &response, args.output)
        }
        OutputFormat::Text => {
            if !caps.is_machine() {
                print!("{}", already_line(&terminal_text(name), already));
            }
            Ok(())
        }
    }
}

/// `cw start`: the start's stages, shown as `caps` allows, through its
/// startup script and daemon readiness. Exits non-zero when a stage fails.
pub(super) async fn start_platform_environment_with_progress(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
    began: Instant,
    caps: &crate::output::Capabilities,
    interrupt: &InterruptNotice,
) -> anyhow::Result<()> {
    let cursor = log_cursor(client, org_id, environment_id).await;
    let started = client
        .start_environment(org_id, environment_id)
        .await
        .context("start environment")?;
    let feed = progress::PlatformLogFeed {
        client,
        org_id,
        environment_id,
    };
    let view = StartProgress::new(std::io::stderr(), caps, began, "Starting");
    follow_platform_start(
        &feed,
        cursor,
        started.completes_with_log,
        view,
        caps,
        interrupt,
    )
    .await
}

/// Where a start's own log rows begin: rows up to now belong to earlier
/// operations, including the terminal row that would otherwise end the
/// stream at once. Read before the request that starts it.
pub(super) async fn log_cursor(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
) -> anyhow::Result<Option<String>> {
    client
        .get_environment_logs(org_id, environment_id)
        .await
        .map(|logs| progress::last_log_id(&logs))
}

/// The wait for a start the platform has accepted, `cw start`'s or the one
/// a source update's restart ends with: its stages from the log rows after
/// `cursor`, then daemon readiness, within the daemon wait's bounds. With
/// `completes_with_log` the start ends with a `complete` row, and the
/// environment leaving the start path ends the wait at once. An interrupt
/// ends only the wait.
pub(super) async fn follow_platform_start(
    feed: &progress::PlatformLogFeed<'_>,
    cursor: anyhow::Result<Option<String>>,
    completes_with_log: bool,
    mut view: StartProgress<std::io::Stderr>,
    caps: &crate::output::Capabilities,
    interrupt: &InterruptNotice,
) -> anyhow::Result<()> {
    let (client, org_id, environment_id) = (feed.client, feed.org_id, feed.environment_id);
    let daemon_ready = async {
        wait_for_platform_environment_daemon_ready(client, org_id, environment_id)
            .await
            .context("wait for environment daemon readiness")
    };
    let waited = crate::commands::lifecycle_output::unless_interrupted(!caps.is_machine(), async {
        match cursor {
            Ok(cursor) => {
                progress::await_environment_start(
                    feed,
                    &mut view,
                    &FollowPolicy::default(),
                    environment_id,
                    cursor,
                    completes_with_log
                        .then(|| progress::watch_start_failure(client, org_id, environment_id)),
                    daemon_ready,
                )
                .await
            }
            Err(error) => {
                view.note(&format!("Start progress is unavailable: {error:#}"))?;
                progress::await_daemon_ready(&mut view, &FollowPolicy::default(), daemon_ready)
                    .await
            }
        }
    })
    .await;
    match waited {
        Some(result) => result,
        None => {
            view.finish()?;
            Err(interrupt.error(true))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const GET: &str = "/codewire.v1.EnvironmentService/GetEnvironment";
    const STOP: &str = "/codewire.v1.EnvironmentService/StopEnvironment";

    /// The platform's refusal of a stop of an environment that isn't
    /// running, as orchestration sends it: `invalid_state`, whatever the
    /// state.
    fn refused() -> ResponseTemplate {
        ResponseTemplate::new(400)
            .insert_header("content-type", "application/json")
            .set_body_json(serde_json::json!({
                "code": "failed_precondition",
                "message": "environment must be running to stop",
                "details": [connectrpc::ErrorDetail::from_message(
                    "google.rpc.ErrorInfo",
                    &codewire_proto::google::rpc::ErrorInfo {
                        reason: "invalid_state".into(),
                        domain: "codewire.sh".into(),
                        ..Default::default()
                    },
                )],
            }))
    }

    fn environment(state: codewire_client::EnvironmentState) -> ResponseTemplate {
        let response = codewire_client::GetEnvironmentResponse {
            environment: Some(codewire_client::Environment {
                id: "env_demo".into(),
                org_id: "org_demo".into(),
                name: "app".into(),
                state: state.into(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        ResponseTemplate::new(200)
            .insert_header("content-type", "application/proto")
            .set_body_bytes(buffa::Message::encode_to_vec(&response))
    }

    /// Whether a refused stop is read as "already stopped" when the
    /// environment is `state`.
    async fn already_stopped_when(state: codewire_client::EnvironmentState) -> bool {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(STOP))
            .respond_with(refused())
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(GET))
            .respond_with(environment(state))
            .mount(&server)
            .await;
        let client = EnvironmentClient::new(&config::ResolvedPlatformConfig::static_token(
            server.uri(),
            "synthetic-lifecycle-token",
            true,
            None,
        ))
        .unwrap();
        let error = client
            .stop_environment("org_demo", "env_demo")
            .await
            .expect_err("the platform refuses the stop");
        already(&client, "org_demo", "env_demo", &error, "stopped").await
    }

    /// docs/dev/CLI-PARITY.md, L1: a stop of a stopped environment did what
    /// was asked; a refusal in any other state stays an error.
    #[tokio::test]
    async fn a_refused_stop_of_a_stopped_environment_is_already_done() {
        assert!(already_stopped_when(codewire_client::EnvironmentState::Stopped).await);
        assert!(!already_stopped_when(codewire_client::EnvironmentState::Starting).await);
        assert!(!already_stopped_when(codewire_client::EnvironmentState::Error).await);
    }
}
