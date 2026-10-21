//! Cloud environment lifecycle results: the create/start summary and its
//! working context, the stop acknowledgement, and the observed outcome of a
//! removal.

use super::*;
use crate::commands::lifecycle_output::{
    ResultBlock, bounded, credential_profile_name, credential_ref, environment_command,
    exact_reference_id, location_label, next_run_command, secret_refs, unless_interrupted,
};
use crate::output::{
    Allocation, LifecycleSummary, MeshPlacement, NetworkRef, Outcome, SourceRef, Status,
    StatusLine, VmLocation,
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

/// A summary of a cloud environment. Cloud VMs have no Mesh attachment
/// today (creation refuses one), so the network reads `not attached` unless
/// the platform reports a network.
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
    let network = match environment.network.as_deref().and_then(trimmed_str) {
        Some(network) => NetworkRef::Attached {
            mesh: MeshPlacement::Cloud,
            network: network.to_owned(),
        },
        None => NetworkRef::NotAttached,
    };
    let next = match outcome {
        Outcome::Creating => environment_command(VmLocation::Cloud, "info", &name),
        _ => next_run_command(VmLocation::Cloud, &name),
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

/// What the stop reply says: stopped when the platform reports it, else
/// an accepted request with the state it reported.
pub(crate) fn stop_result(name: &str, response: &StatusResponse) -> ResultBlock {
    let state = trimmed_str(&response.status).unwrap_or("unknown");
    let cloud = location_label(VmLocation::Cloud);
    if state == "stopped" {
        ResultBlock::new(Status::Done, format!("Environment {name} stopped"))
            .detail(cloud)
            .next(environment_command(VmLocation::Cloud, "start", name))
    } else {
        ResultBlock::new(Status::Done, format!("Stop requested: {name}"))
            .detail(format!("{cloud} · state: {state}"))
            .next(environment_command(VmLocation::Cloud, "info", name))
    }
}

/// What a removal did, from one read after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CloudRemoval {
    /// Destroyed, or no longer found.
    Removed,
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
            "✓ Environment app started · cloud VM\n  2 vCPU · 4 GiB RAM · 40 GiB disk\n\n  Credentials: platform:work\n  Secrets:     platform:app-dev, organization secrets (platform)\n  Network:     not attached\n\n→ cw --cloud run claude --in app\n"
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
    fn stop_acceptance_is_not_reported_as_stopped() {
        let stopping = StatusResponse {
            status: "stopping".to_owned(),
        };
        assert_eq!(
            stop_result("app", &stopping).render(PLAIN),
            "✓ Stop requested: app\n  cloud VM · state: stopping\n\n→ cw --cloud info app\n"
        );
        let stopped = StatusResponse {
            status: "stopped".to_owned(),
        };
        assert_eq!(
            stop_result("app", &stopped).render(PLAIN),
            "✓ Environment app stopped\n  cloud VM\n\n→ cw --cloud start app\n"
        );
        let empty = StatusResponse {
            status: " ".to_owned(),
        };
        assert!(
            stop_result("app", &empty)
                .render(PLAIN)
                .contains("state: unknown")
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
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

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

        fn environment(state: codewire_client::EnvironmentState, grace: bool) -> ResponseTemplate {
            let at = |seconds| {
                Some(codewire_client::Timestamp {
                    seconds,
                    ..Default::default()
                })
                .into()
            };
            proto(codewire_client::GetEnvironmentResponse {
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
            })
        }

        async fn remove(server: &MockServer) -> anyhow::Result<CloudRemoval> {
            remove_cloud_environment(&client(server), "org_demo", "env_demo", "app").await
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

        #[tokio::test]
        async fn a_stop_reply_of_stopping_is_reported_as_requested() {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(STOP))
                .respond_with(proto(codewire_client::StopEnvironmentResponse {
                    status: "stopping".into(),
                    ..Default::default()
                }))
                .expect(1)
                .mount(&server)
                .await;
            let response = client(&server)
                .stop_environment("org_demo", "env_demo")
                .await
                .unwrap();
            let text = stop_result("app", &response).render(PLAIN);
            assert!(text.starts_with("✓ Stop requested: app\n"), "{text}");
            assert!(!text.contains("stopped"));
        }
    }
}
