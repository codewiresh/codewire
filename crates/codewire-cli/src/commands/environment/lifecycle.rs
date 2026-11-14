//! Cloud environment lifecycle results: the create/start summary and its
//! working context, a stop and the wait for it, and the observed outcome of a
//! removal.

use super::*;
use crate::commands::lifecycle_output::{
    InterruptNotice, ResultBlock, bounded, credential_profile_name, credential_ref,
    environment_command, exact_reference_id, location_label, next_shell_command, secret_refs,
    unless_interrupted,
};
use crate::commands::progress::terminal_text;
use crate::output::{
    Allocation, LifecycleSummary, NetworkRef, Outcome, SourceRef, Status, StatusLine, VmLocation,
};

/// Display-only names of the selected credential profile and secret
/// project. The selection itself keeps its canonical references.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SourceNames {
    pub(crate) profile: Option<String>,
    pub(crate) project: Option<String>,
}

/// The environment's name, or its ID when it has none.
pub(crate) fn display_name(environment: &Environment) -> String {
    environment
        .name
        .as_deref()
        .and_then(trimmed_str)
        .unwrap_or(&environment.id)
        .to_owned()
}

/// A summary of a cloud environment. Its network, when it joins one, shows
/// how far joining has come, as the platform reports it.
pub(crate) fn cloud_summary(
    environment: &Environment,
    outcome: Outcome,
    names: &SourceNames,
) -> LifecycleSummary {
    let name = display_name(environment);
    let selection = environment.source_selection.as_ref();
    let credentials = credential_ref(
        selection
            .and_then(|selection| selection.credentials.as_ref())
            .map(|binding| binding.profile.as_str()),
        names.profile.as_deref(),
    );
    let secrets = selection.map_or(SourceRef::None, |selection| {
        secret_refs(&selection.secrets, names.project.as_deref())
    });
    let network = NetworkRef::cloud(
        environment.network.as_deref(),
        environment.network_state.as_deref(),
        environment.network_failure.as_deref(),
    );
    let next = match outcome {
        Outcome::Creating => environment_command(VmLocation::Cloud, "info", &name),
        _ => next_shell_command(VmLocation::Cloud, &name),
    };
    LifecycleSummary {
        outcome,
        name,
        location: VmLocation::Cloud,
        allocation: Allocation::cloud(
            environment.cpu_millicores,
            environment.memory_mb,
            environment.disk_gb,
        ),
        credentials,
        secrets,
        network,
        next: Some(next),
    }
}

/// Names the environment's selected profile and secret project through the
/// platform. Best effort and bounded; an unnamed source shows its canonical
/// reference.
pub(crate) async fn resolve_source_names(
    platform: &config::ResolvedPlatformConfig,
    client: &EnvironmentClient,
    org_id: &str,
    environment: &Environment,
) -> SourceNames {
    let Some(selection) = environment.source_selection.as_ref() else {
        return SourceNames::default();
    };
    let profile = async {
        let profile = selection.credentials.as_ref()?;
        credential_profile_name(client, &profile.profile).await
    };
    let project = async {
        exact_reference_id(&selection.secrets.project)?;
        bounded(async {
            let secrets = SecretClient::new(platform)?;
            load_secret_project_by_name(&secrets, org_id, &selection.secrets.project).await
        })
        .await
        .filter(|project| project.org_id == org_id)
        .map(|project| project.name)
    };
    let (profile, project) = tokio::join!(profile, project);
    SourceNames { profile, project }
}

/// How long `cw stop` waits to see `stopped`: past the 120 s the worker gives
/// the Pod to go, and short enough to say something true when it runs out.
const STOP_TIMEOUT: Duration = Duration::from_secs(180);
const STOP_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// The bounds of one wait for `stopped`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StopWait {
    timeout: Duration,
    interval: Duration,
}

impl Default for StopWait {
    fn default() -> Self {
        Self {
            timeout: STOP_TIMEOUT,
            interval: STOP_POLL_INTERVAL,
        }
    }
}

/// `cw stop` on a cloud environment: the request, then the wait until the
/// platform reports `stopped`, so that a `cw start` straight after is accepted.
/// An interrupt ends only the wait.
pub(crate) async fn stop_cloud_environment<W: std::io::Write>(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
    name: &str,
    line: &mut StatusLine<W>,
    interruptible: bool,
    wait: StopWait,
) -> anyhow::Result<()> {
    let name = terminal_text(name);
    let name = name.as_str();
    let interrupted = InterruptNotice::new(VmLocation::Cloud, "stop", name);
    let Some(accepted) = Box::pin(tick_while(
        line,
        interruptible,
        client.stop_environment(org_id, environment_id),
    ))
    .await
    else {
        return Err(interrupted.error(false));
    };
    accepted.with_context(|| format!("stop {name}"))?;
    let Some(stopped) = Box::pin(tick_while(
        line,
        interruptible,
        await_stopped(client, org_id, environment_id, name, wait),
    ))
    .await
    else {
        return Err(interrupted.error(true));
    };
    stopped
}

/// Reads the environment until it is `stopped`. A read that fails is tried
/// again: the stop is already accepted, and the timeout says what was last seen.
/// The deadline is checked after each read rather than cancelling one, so the
/// timeout always reports a state or a read error (#4299); each read is bounded
/// by the client's own unary timeout.
async fn await_stopped(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
    name: &str,
    wait: StopWait,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + wait.timeout;
    loop {
        let (last_seen, interval) = match client
            .get_environment_with_poll_interval(org_id, environment_id)
            .await
        {
            Ok((environment, interval)) => {
                if stop_finished(&environment, name)? {
                    return Ok(());
                }
                (format!("state: {}", environment.state), interval)
            }
            Err(error) if is_not_found(&error) => {
                anyhow::bail!("{name} was removed before it stopped")
            }
            Err(error) => (
                format!("last read failed: {}", terminal_text(&format!("{error:#}"))),
                None,
            ),
        };
        let now = tokio::time::Instant::now();
        if now >= deadline {
            anyhow::bail!(
                "timed out after {} s waiting for {name} to stop ({last_seen}). The stop was requested and the platform carries on with it; check it with `{}`.",
                wait.timeout.as_secs(),
                environment_command(VmLocation::Cloud, "info", name)
            );
        }
        tokio::time::sleep(interval.unwrap_or(wait.interval).min(deadline - now)).await;
    }
}

/// Whether an accepted stop has finished, or the error when it never will.
/// `running` is still on the way: the worker takes the request up after the
/// reply.
fn stop_finished(environment: &Environment, name: &str) -> anyhow::Result<bool> {
    let state = environment.state.as_str();
    match state {
        "stopped" => return Ok(true),
        "error" | "failed" | "destroying" | "destroyed" => {
            let reason = environment
                .error_reason
                .as_deref()
                .map(terminal_text)
                .filter(|reason| !reason.is_empty())
                .map(|reason| format!(": {reason}"))
                .unwrap_or_default();
            anyhow::bail!("{name} became {state} before it stopped{reason}");
        }
        _ => {}
    }
    if environment.desired_state != "stopped" {
        anyhow::bail!(
            "{name} did not stop: a newer request wants it {} (state: {state})",
            environment.desired_state
        );
    }
    Ok(false)
}

/// What a finished stop says.
pub(crate) fn stop_result(name: &str) -> ResultBlock {
    ResultBlock::new(Status::Done, format!("Environment {name} stopped"))
        .detail(location_label(VmLocation::Cloud))
        .next(environment_command(VmLocation::Cloud, "start", name))
}

/// What a removal did, from one read after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CloudRemoval {
    /// Destroyed, or no longer found.
    Removed,
    /// A create the platform ended and removed itself; its row is still
    /// listed for the rest of its day (#4482).
    AlreadyRemoved,
    /// A deletion grace period runs until the given time, when known.
    Scheduled { until: Option<String> },
    /// The platform is removing it in the background.
    Removing { state: String },
    /// The removal was accepted but the state could not be read.
    Unconfirmed,
}

impl CloudRemoval {
    pub(crate) fn observe(after: anyhow::Result<Environment>) -> Self {
        match after {
            Ok(environment) if environment.state == "destroyed" => CloudRemoval::Removed,
            Ok(environment) => match environment
                .deletion_grace_until
                .as_deref()
                .and_then(trimmed_str)
            {
                Some(until) => CloudRemoval::Scheduled {
                    until: Some(until.to_owned()),
                },
                None => CloudRemoval::Removing {
                    state: trimmed_str(&environment.state)
                        .unwrap_or("unknown")
                        .to_owned(),
                },
            },
            Err(error) if is_not_found(&error) => CloudRemoval::Removed,
            Err(_) => CloudRemoval::Unconfirmed,
        }
    }

    pub(crate) fn result(&self, name: &str) -> ResultBlock {
        let cloud = location_label(VmLocation::Cloud);
        match self {
            CloudRemoval::Removed => {
                ResultBlock::new(Status::Done, format!("Environment {name} removed"))
                    .detail(format!("{cloud} · environment disk removed"))
                    .next("cw ls")
            }
            CloudRemoval::AlreadyRemoved => ResultBlock::new(
                Status::Done,
                format!("Environment {name} was already removed"),
            )
            .detail(format!(
                "{cloud} · its create failed; it leaves cw ls within a day"
            ))
            .next("cw ls"),
            CloudRemoval::Scheduled { until } => {
                let detail = match until {
                    Some(until) => format!("{cloud} · grace period until {until}"),
                    None => format!("{cloud} · grace period active"),
                };
                ResultBlock::new(Status::Done, format!("Deletion scheduled: {name}"))
                    .detail(detail)
                    .next(format!(
                        "Undo: {}",
                        environment_command(VmLocation::Cloud, "cancel-delete", name)
                    ))
            }
            CloudRemoval::Removing { state } => {
                ResultBlock::new(Status::Done, format!("Removal started: {name}"))
                    .detail(format!("{cloud} · state: {state}"))
                    .next("cw --cloud ls")
            }
            CloudRemoval::Unconfirmed => {
                ResultBlock::new(Status::Done, format!("Removal requested: {name}"))
                    .detail(format!("{cloud} · state not confirmed"))
                    .next("cw --cloud ls")
            }
        }
    }
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<codewire_client::ClientError>()
        .is_some_and(|error| error.code() == codewire_client::ErrorCode::NotFound)
}

/// Whether a platform error carries the reason `code` (`environment_protected`
/// arrives as the `ENVIRONMENT_PROTECTED` error-info reason), or, from an
/// older platform, names it in its message.
pub(crate) fn error_has_reason(error: &anyhow::Error, code: &str) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<codewire_client::ClientError>()
            .and_then(codewire_client::ClientError::reason)
            .is_some_and(|reason| reason.eq_ignore_ascii_case(code))
    }) || format!("{error:#}").contains(code)
}

/// A platform reply that scheduled the deletion behind a grace period
/// instead of removing at once. An accepted outcome, not a failure.
pub(crate) fn delete_was_scheduled(error: &anyhow::Error) -> bool {
    error_has_reason(error, "deletion_pending")
}

/// `cw rm` on a cloud environment: the delete, then one read of what it
/// did. A refusal (protection, access) or a failed request is an error.
pub(crate) async fn remove_cloud_environment(
    client: &EnvironmentClient,
    org_id: &str,
    environment_id: &str,
    environment_ref: &str,
) -> anyhow::Result<CloudRemoval> {
    // A create the platform ended is already destroyed, and the platform
    // refuses to destroy it twice. Its row leaves the listing by itself.
    if client
        .get_environment(org_id, environment_id)
        .await
        .is_ok_and(|environment| environment.failed_create())
    {
        return Ok(CloudRemoval::AlreadyRemoved);
    }
    match client.delete_environment(org_id, environment_id).await {
        Ok(()) => Ok(CloudRemoval::observe(
            client.get_environment(org_id, environment_id).await,
        )),
        Err(error) if delete_was_scheduled(&error) => {
            let until = client
                .get_environment(org_id, environment_id)
                .await
                .ok()
                .and_then(|environment| environment.deletion_grace_until)
                .and_then(|until| trimmed_str(&until).map(str::to_owned));
            Ok(CloudRemoval::Scheduled { until })
        }
        Err(error) => Err(map_env_delete_error(environment_ref, error)),
    }
}

/// Runs `work` while the status line animates. When `interruptible`, the
/// first Ctrl-C ends the wait (not the operation) and returns `None`.
pub(crate) async fn tick_while<W: std::io::Write, T>(
    line: &mut StatusLine<W>,
    interruptible: bool,
    work: impl std::future::Future<Output = T>,
) -> Option<T> {
    unless_interrupted(interruptible, async {
        tokio::pin!(work);
        loop {
            let Some(interval) = line.tick_interval() else {
                return work.await;
            };
            tokio::select! {
                result = &mut work => return result,
                () = tokio::time::sleep(interval) => {
                    let _ = line.tick();
                }
            }
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{Charset, Style};

    const PLAIN: Style = Style::new(false, Charset::Unicode);

    fn environment() -> Environment {
        serde_json::from_value(serde_json::json!({
            "id": "env_demo",
            "org_id": "org_demo",
            "created_by": "user_demo",
            "preset_id": "",
            "type": "sandbox",
            "name": "app",
            "state": "running",
            "desired_state": "running",
            "error_reason": null,
            "recoverable": false,
            "state_changed_at": "",
            "retry_count": 0,
            "setup_phase": 0,
            "setup_complete": true,
            "ttl_seconds": null,
            "shutdown_at": null,
            "cpu_millicores": 2000,
            "memory_mb": 4096,
            "disk_gb": 40,
            "total_running_seconds": 0,
            "created_at": "",
            "started_at": null,
            "stopped_at": null,
            "destroyed_at": null,
            "protected": false,
            "deletion_requested_at": null,
            "deletion_grace_until": null,
            "network": null,
            "operation_generation": 1,
            "source_selection": {
                "secrets": {
                    "project": "platform:id:a6249c2e-2fa4-473b-b41a-8d0f08f39e51",
                    "organization": true
                },
                "credentials": {"profile": "platform:id:856b6b9e-a520-48c7-aab1-8ac915465f28"},
                "profile_revision": 3
            }
        }))
        .unwrap()
    }

    #[test]
    fn started_summary_names_resolved_sources_and_no_network() {
        let names = SourceNames {
            profile: Some("work".to_owned()),
            project: Some("app-dev".to_owned()),
        };
        assert_eq!(
            cloud_summary(&environment(), Outcome::Started, &names).render(PLAIN),
            "✓ Environment app started · cloud VM\n  2 vCPU · 4 GiB RAM · 40 GiB disk\n\n  Credentials: platform:work\n  Secrets:     platform:app-dev, organization secrets (platform)\n  Network:     not attached\n\n→ cw --cloud shell app\n"
        );
    }

    #[test]
    fn unresolved_names_show_canonical_references() {
        let text =
            cloud_summary(&environment(), Outcome::Created, &SourceNames::default()).render(PLAIN);
        assert!(text.contains("  Credentials: platform:id:856b6b9e-a520-48c7-aab1-8ac915465f28\n"));
        assert!(text.contains(
            "  Secrets:     platform:id:a6249c2e-2fa4-473b-b41a-8d0f08f39e51, organization secrets (platform)\n"
        ));
        let mut bare = environment();
        bare.source_selection = None;
        bare.name = None;
        let text = cloud_summary(&bare, Outcome::Creating, &SourceNames::default()).render(PLAIN);
        assert!(text.starts_with("! Environment env_demo is being created · cloud VM\n"));
        assert!(text.contains("  Credentials: none\n  Secrets:     none\n"));
        assert!(text.ends_with("→ cw --cloud info env_demo\n"));
    }

    #[test]
    fn a_finished_stop_names_the_next_start() {
        assert_eq!(
            stop_result("app").render(PLAIN),
            "✓ Environment app stopped\n  cloud VM\n\n→ cw --cloud start app\n"
        );
    }

    #[test]
    fn removal_reports_what_one_read_observed() {
        let mut destroyed = environment();
        destroyed.state = "destroyed".to_owned();
        assert_eq!(CloudRemoval::observe(Ok(destroyed)), CloudRemoval::Removed);

        let mut destroying = environment();
        destroying.state = "destroying".to_owned();
        assert_eq!(
            CloudRemoval::observe(Ok(destroying)),
            CloudRemoval::Removing {
                state: "destroying".to_owned()
            }
        );

        let mut grace = environment();
        grace.deletion_grace_until = Some("2026-10-21T12:00:00Z".to_owned());
        assert_eq!(
            CloudRemoval::observe(Ok(grace)),
            CloudRemoval::Scheduled {
                until: Some("2026-10-21T12:00:00Z".to_owned())
            }
        );

        assert_eq!(
            CloudRemoval::observe(Err(anyhow::anyhow!("connection closed"))),
            CloudRemoval::Unconfirmed
        );
        let missing = codewire_client::ClientError::new(
            codewire_client::ErrorCode::NotFound,
            "environment not found",
        );
        assert_eq!(
            CloudRemoval::observe(Err(missing.into())),
            CloudRemoval::Removed
        );
    }

    #[test]
    fn removal_results_name_the_observed_outcome() {
        assert_eq!(
            CloudRemoval::Removed.result("app").render(PLAIN),
            "✓ Environment app removed\n  cloud VM · environment disk removed\n\n→ cw ls\n"
        );
        assert_eq!(
            CloudRemoval::Scheduled { until: None }
                .result("app")
                .render(PLAIN),
            "✓ Deletion scheduled: app\n  cloud VM · grace period active\n\n→ Undo: cw --cloud cancel-delete app\n"
        );
        assert!(
            CloudRemoval::Scheduled {
                until: Some("2026-10-21T12:00:00Z".to_owned())
            }
            .result("app")
            .render(PLAIN)
            .contains("grace period until 2026-10-21T12:00:00Z")
        );
        assert_eq!(
            CloudRemoval::Removing {
                state: "destroying".to_owned()
            }
            .result("app")
            .render(PLAIN),
            "✓ Removal started: app\n  cloud VM · state: destroying\n\n→ cw --cloud ls\n"
        );
        assert_eq!(
            CloudRemoval::Unconfirmed.result("app").render(PLAIN),
            "✓ Removal requested: app\n  cloud VM · state not confirmed\n\n→ cw --cloud ls\n"
        );
    }

    fn reasoned(error: connectrpc::ConnectError, reason: &str) -> anyhow::Error {
        use codewire_proto::google::rpc::ErrorInfo;
        codewire_client::ClientError::from(error.with_detail(
            connectrpc::ErrorDetail::from_message(
                "google.rpc.ErrorInfo",
                &ErrorInfo {
                    reason: reason.into(),
                    domain: "codewire.sh".into(),
                    ..Default::default()
                },
            ),
        ))
        .into()
    }

    #[test]
    fn only_the_deletion_pending_reason_schedules_a_deletion() {
        assert!(delete_was_scheduled(&reasoned(
            connectrpc::ConnectError::failed_precondition("environment deletion is pending"),
            "DELETION_PENDING",
        )));
        assert!(delete_was_scheduled(&anyhow::anyhow!(
            "failed_precondition: deletion_pending"
        )));
        // A timestamp or an HTTP status in the text is not a reason.
        assert!(!delete_was_scheduled(&anyhow::anyhow!(
            "internal: failed at 2026-10-20T10:00:00Z (HTTP 202 seen upstream)"
        )));
        assert!(!delete_was_scheduled(&reasoned(
            connectrpc::ConnectError::failed_precondition("environment is protected from deletion"),
            "ENVIRONMENT_PROTECTED",
        )));
    }

    #[test]
    fn delete_refusals_keep_their_repair() {
        let protected = map_env_delete_error(
            "app",
            reasoned(
                connectrpc::ConnectError::invalid_argument(
                    "environment is protected from deletion",
                ),
                "ENVIRONMENT_PROTECTED",
            ),
        );
        assert_eq!(
            protected.to_string(),
            "environment app is protected, so nothing was removed; remove the protection first with `cw --cloud unprotect app`"
        );
        let denied = map_env_delete_error(
            "app",
            reasoned(
                connectrpc::ConnectError::permission_denied(
                    "only environment owners can delete environments",
                ),
                "ACCESS_DENIED",
            ),
        );
        assert_eq!(
            denied.to_string(),
            "access denied: only the environment owner can delete it"
        );
        // An unrelated failure whose text holds a date stays a failure.
        let failed = map_env_delete_error(
            "app",
            anyhow::anyhow!("internal: storage error at 2026-10-20T10:00:00Z"),
        );
        assert_eq!(
            failed.to_string(),
            "delete environment: internal: storage error at 2026-10-20T10:00:00Z"
        );
    }

    mod platform {
        use super::*;
        use std::sync::{Arc, Mutex};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

        const DELETE: &str = "/codewire.v1.EnvironmentService/DeleteEnvironment";
        const GET: &str = "/codewire.v1.EnvironmentService/GetEnvironment";
        const STOP: &str = "/codewire.v1.EnvironmentService/StopEnvironment";

        fn client(server: &MockServer) -> EnvironmentClient {
            EnvironmentClient::new(&config::ResolvedPlatformConfig::static_token(
                server.uri(),
                "synthetic-lifecycle-token",
                true,
                None,
            ))
            .unwrap()
        }

        fn proto(body: impl buffa::Message) -> ResponseTemplate {
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/proto")
                .set_body_bytes(body.encode_to_vec())
        }

        fn error(status: u16, code: &str, message: &str, reason: Option<&str>) -> ResponseTemplate {
            let details = reason
                .map(|reason| {
                    vec![connectrpc::ErrorDetail::from_message(
                        "google.rpc.ErrorInfo",
                        &codewire_proto::google::rpc::ErrorInfo {
                            reason: reason.into(),
                            domain: "codewire.sh".into(),
                            ..Default::default()
                        },
                    )]
                })
                .unwrap_or_default();
            ResponseTemplate::new(status)
                .insert_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "code": code,
                    "message": message,
                    "details": details,
                }))
        }

        async fn platform(delete: ResponseTemplate, get: ResponseTemplate) -> MockServer {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(DELETE))
                .respond_with(delete)
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(GET))
                .respond_with(get)
                .mount(&server)
                .await;
            server
        }

        fn get_response(
            state: codewire_client::EnvironmentState,
            grace: bool,
        ) -> codewire_client::GetEnvironmentResponse {
            let at = |seconds| {
                Some(codewire_client::Timestamp {
                    seconds,
                    ..Default::default()
                })
                .into()
            };
            codewire_client::GetEnvironmentResponse {
                environment: Some(codewire_client::Environment {
                    id: "env_demo".into(),
                    org_id: "org_demo".into(),
                    created_by: "user_demo".into(),
                    r#type: "sandbox".into(),
                    name: "app".into(),
                    state: state.into(),
                    desired_state: codewire_client::DesiredState::Stopped.into(),
                    state_changed_at: at(1_767_225_600),
                    created_at: at(1_767_225_600),
                    deletion_grace_until: if grace {
                        at(1_792_584_000)
                    } else {
                        None.into()
                    },
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }
        }

        fn environment(state: codewire_client::EnvironmentState, grace: bool) -> ResponseTemplate {
            proto(get_response(state, grace))
        }

        async fn remove(server: &MockServer) -> anyhow::Result<CloudRemoval> {
            remove_cloud_environment(&client(server), "org_demo", "env_demo", "app").await
        }

        /// A create the platform ended is already destroyed, and the platform
        /// refuses a second destroy, so removing it asks for nothing (#4482).
        #[tokio::test]
        async fn a_failed_create_is_removed_without_asking_the_platform() {
            let mut failed = get_response(codewire_client::EnvironmentState::Destroyed, false);
            let mut environment = (*failed.environment).clone();
            environment.error_code = "container_start_failed".into();
            environment.destroyed_at = Some(codewire_client::Timestamp {
                seconds: chrono::Utc::now().timestamp() - 600,
                ..Default::default()
            })
            .into();
            failed.environment = Some(environment).into();
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(DELETE))
                .respond_with(error(409, "failed_precondition", "already destroyed", None))
                .expect(0)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(GET))
                .respond_with(proto(failed))
                .mount(&server)
                .await;
            let removal = remove(&server).await.unwrap();
            assert_eq!(removal, CloudRemoval::AlreadyRemoved);
            assert_eq!(
                removal.result("app").render(PLAIN),
                "✓ Environment app was already removed\n  cloud VM · its create failed; it leaves cw ls within a day\n\n→ cw ls\n"
            );
        }

        #[tokio::test]
        async fn an_accepted_delete_reports_what_the_platform_shows_next() {
            let ok = proto(codewire_client::DeleteEnvironmentResponse::default());
            let server = platform(
                ok.clone(),
                environment(codewire_client::EnvironmentState::Destroying, false),
            )
            .await;
            assert_eq!(
                remove(&server).await.unwrap(),
                CloudRemoval::Removing {
                    state: "destroying".to_owned()
                }
            );
            let server = platform(
                ok.clone(),
                environment(codewire_client::EnvironmentState::Destroyed, false),
            )
            .await;
            assert_eq!(remove(&server).await.unwrap(), CloudRemoval::Removed);
            let server = platform(
                ok.clone(),
                error(404, "not_found", "environment not found", None),
            )
            .await;
            assert_eq!(remove(&server).await.unwrap(), CloudRemoval::Removed);
            let server = platform(ok, error(503, "unavailable", "connection closed", None)).await;
            assert_eq!(remove(&server).await.unwrap(), CloudRemoval::Unconfirmed);
        }

        #[tokio::test]
        async fn a_scheduled_deletion_is_an_accepted_outcome() {
            let server = platform(
                error(
                    400,
                    "failed_precondition",
                    "environment deletion is pending its grace period",
                    Some("DELETION_PENDING"),
                ),
                environment(codewire_client::EnvironmentState::Stopped, true),
            )
            .await;
            let CloudRemoval::Scheduled { until } = remove(&server).await.unwrap() else {
                panic!("a pending deletion is scheduled");
            };
            assert!(until.is_some_and(|until| until.starts_with("2026-10-21")));
        }

        #[tokio::test]
        async fn refusals_and_failures_stay_errors() {
            let server = platform(
                error(
                    400,
                    "invalid_argument",
                    "environment is protected from deletion",
                    Some("ENVIRONMENT_PROTECTED"),
                ),
                environment(codewire_client::EnvironmentState::Running, false),
            )
            .await;
            let refused = remove(&server).await.unwrap_err().to_string();
            assert!(
                refused.contains("is protected, so nothing was removed"),
                "{refused}"
            );
            assert!(refused.contains("cw --cloud unprotect app"));
            let server = platform(
                error(
                    500,
                    "internal",
                    "storage failed at 2026-10-20T10:00:00Z",
                    None,
                ),
                environment(codewire_client::EnvironmentState::Running, false),
            )
            .await;
            let failed = remove(&server).await.unwrap_err().to_string();
            assert!(failed.starts_with("delete environment:"), "{failed}");
            assert!(!failed.contains("scheduled"));
        }

        const START: &str = "/codewire.v1.EnvironmentService/StartEnvironment";
        const QUICK: StopWait = StopWait {
            timeout: Duration::from_secs(10),
            interval: Duration::from_millis(10),
        };

        /// The platform as a stop runs on it: the reply comes first, the worker
        /// takes the request up after it, and a start is refused until `stopped`.
        #[derive(Clone)]
        struct StoppingPlatform {
            accepted: Arc<Mutex<Option<Instant>>>,
        }

        impl StoppingPlatform {
            fn state(&self) -> codewire_client::EnvironmentState {
                use codewire_client::EnvironmentState as State;
                match self.accepted.lock().unwrap().map(|at| at.elapsed()) {
                    Some(since) if since >= Duration::from_millis(200) => State::Stopped,
                    Some(since) if since >= Duration::from_millis(50) => State::Stopping,
                    _ => State::Running,
                }
            }
        }

        impl Respond for StoppingPlatform {
            fn respond(&self, request: &Request) -> ResponseTemplate {
                match request.url.path() {
                    STOP => {
                        *self.accepted.lock().unwrap() = Some(Instant::now());
                        proto(codewire_client::StopEnvironmentResponse {
                            status: "stop requested".into(),
                            ..Default::default()
                        })
                    }
                    GET => observed(self.state(), codewire_client::DesiredState::Stopped, None),
                    START if self.state() == codewire_client::EnvironmentState::Stopped => {
                        proto(codewire_client::StartEnvironmentResponse {
                            status: "start requested".into(),
                            ..Default::default()
                        })
                    }
                    START => error(
                        400,
                        "invalid_argument",
                        "environment must be stopped, pending, or errored to start",
                        None,
                    ),
                    other => panic!("unexpected request to {other}"),
                }
            }
        }

        fn observed(
            state: codewire_client::EnvironmentState,
            desired: codewire_client::DesiredState,
            reason: Option<&str>,
        ) -> ResponseTemplate {
            let mut response = get_response(state, false);
            let environment = response.environment.as_option_mut().unwrap();
            environment.desired_state = desired.into();
            environment.error_reason = reason.unwrap_or_default().into();
            proto(response)
        }

        fn accepting_stop() -> Mock {
            Mock::given(method("POST"))
                .and(path(STOP))
                .respond_with(proto(codewire_client::StopEnvironmentResponse {
                    status: "stop requested".into(),
                    ..Default::default()
                }))
                .expect(1)
        }

        async fn stop(server: &MockServer, wait: StopWait) -> anyhow::Result<()> {
            let caps = crate::commands::lifecycle_output::capabilities(OutputFormat::Json);
            let mut line = StatusLine::new(Vec::new(), &caps);
            stop_cloud_environment(
                &client(server),
                "org_demo",
                "env_demo",
                "app",
                &mut line,
                false,
                wait,
            )
            .await
        }

        #[tokio::test]
        async fn a_start_right_after_a_stop_is_accepted() {
            let server = MockServer::start().await;
            let platform = StoppingPlatform {
                accepted: Arc::default(),
            };
            Mock::given(method("POST"))
                .respond_with(platform)
                .mount(&server)
                .await;
            stop(&server, QUICK).await.unwrap();
            client(&server)
                .start_environment("org_demo", "env_demo")
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn a_stop_that_never_finishes_says_so_and_what_to_check() {
            let server = MockServer::start().await;
            accepting_stop().mount(&server).await;
            // Each read outlasts the whole wait, as on a loaded host: the
            // timeout still reports what that read saw (#4299).
            Mock::given(method("POST"))
                .and(path(GET))
                .respond_with(
                    observed(
                        codewire_client::EnvironmentState::Stopping,
                        codewire_client::DesiredState::Stopped,
                        None,
                    )
                    .set_delay(Duration::from_millis(200)),
                )
                .mount(&server)
                .await;
            let wait = StopWait {
                timeout: Duration::from_millis(50),
                ..QUICK
            };
            let timed_out = stop(&server, wait).await.unwrap_err().to_string();
            assert!(timed_out.starts_with("timed out after"), "{timed_out}");
            assert!(timed_out.contains("waiting for app to stop (state: stopping)"));
            assert!(timed_out.contains("`cw --cloud info app`"), "{timed_out}");
        }

        #[tokio::test]
        async fn a_failed_read_is_tried_again() {
            let server = MockServer::start().await;
            accepting_stop().mount(&server).await;
            Mock::given(method("POST"))
                .and(path(GET))
                .respond_with(error(503, "unavailable", "connection closed", None))
                .up_to_n_times(1)
                .with_priority(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(GET))
                .respond_with(observed(
                    codewire_client::EnvironmentState::Stopped,
                    codewire_client::DesiredState::Stopped,
                    None,
                ))
                .mount(&server)
                .await;
            stop(&server, QUICK).await.unwrap();
        }

        #[tokio::test]
        async fn a_stop_that_cannot_finish_ends_the_wait_with_why() {
            use codewire_client::{DesiredState, EnvironmentState};
            for (state, desired, reason, expected) in [
                (
                    EnvironmentState::Error,
                    DesiredState::Stopped,
                    Some("set replicas 0: refused"),
                    "app became error before it stopped: set replicas 0: refused",
                ),
                (
                    EnvironmentState::Destroying,
                    DesiredState::Destroyed,
                    None,
                    "app became destroying before it stopped",
                ),
                (
                    EnvironmentState::Starting,
                    DesiredState::Started,
                    None,
                    "app did not stop: a newer request wants it started (state: starting)",
                ),
                (
                    EnvironmentState::Stopping,
                    DesiredState::Started,
                    None,
                    "app did not stop: a newer request wants it started (state: stopping)",
                ),
            ] {
                let server = MockServer::start().await;
                accepting_stop().mount(&server).await;
                Mock::given(method("POST"))
                    .and(path(GET))
                    .respond_with(observed(state, desired, reason))
                    .mount(&server)
                    .await;
                assert_eq!(
                    stop(&server, QUICK).await.unwrap_err().to_string(),
                    expected
                );
            }
            let server = MockServer::start().await;
            accepting_stop().mount(&server).await;
            Mock::given(method("POST"))
                .and(path(GET))
                .respond_with(error(404, "not_found", "environment not found", None))
                .mount(&server)
                .await;
            assert_eq!(
                stop(&server, QUICK).await.unwrap_err().to_string(),
                "app was removed before it stopped"
            );
        }

        #[tokio::test]
        async fn a_refused_stop_says_why_and_waits_for_nothing() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(STOP))
                .respond_with(error(
                    400,
                    "invalid_argument",
                    "environment must be running to stop",
                    None,
                ))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(GET))
                .respond_with(ResponseTemplate::new(500))
                .expect(0)
                .mount(&server)
                .await;
            let refused = format!("{:#}", stop(&server, QUICK).await.unwrap_err());
            assert!(refused.starts_with("stop app: "), "{refused}");
            assert!(refused.contains("must be running to stop"), "{refused}");
        }
    }
}
