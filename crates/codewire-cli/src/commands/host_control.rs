//! Local owner administration for trusted-host delegation. Network discovery
//! and caller authentication belong to the host-peer adapter, not these verbs.
use super::*;
use codewire_daemon_proto::daemon::v1;

#[derive(Debug, Args)]
pub(crate) struct HostControlArgs {
    #[command(subcommand)]
    command: HostControlCommand,
}

#[derive(Debug, Subcommand)]
enum HostControlCommand {
    /// Inspect the retained host control capability without starting a daemon.
    Info(HostControlTarget),
    /// List explicit grants, including revoked tombstones.
    #[command(visible_alias = "ls")]
    List(HostControlTarget),
    /// Grant bounded session verbs to one full caller/target key pair.
    Grant(HostControlGrantArgs),
    /// Revoke a grant using its observed book and grant revisions.
    Revoke(HostControlRevokeArgs),
}

#[derive(Debug, Args)]
struct HostControlTarget {
    #[arg(long, value_name = "HOST_ID_OR_NAME")]
    environment: String,
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum GrantedVerb {
    Read,
    Launch,
    Input,
    Stop,
    ManagedLaunch,
    ManagedMessage,
    ManagedSteer,
    ManagedInterrupt,
    ManagedStop,
    ManagedRestart,
    ManagedRead,
}

#[derive(Clone, Debug)]
struct ControlKey(Vec<u8>);

impl GrantedVerb {
    fn wire(self) -> i32 {
        match self {
            Self::Read => v1::HostControlVerb::Read as i32,
            Self::Launch => v1::HostControlVerb::Launch as i32,
            Self::Input => v1::HostControlVerb::Input as i32,
            Self::Stop => v1::HostControlVerb::Stop as i32,
            Self::ManagedLaunch => v1::HostControlVerb::ManagedLaunch as i32,
            Self::ManagedMessage => v1::HostControlVerb::ManagedMessage as i32,
            Self::ManagedSteer => v1::HostControlVerb::ManagedSteer as i32,
            Self::ManagedInterrupt => v1::HostControlVerb::ManagedInterrupt as i32,
            Self::ManagedStop => v1::HostControlVerb::ManagedStop as i32,
            Self::ManagedRestart => v1::HostControlVerb::ManagedRestart as i32,
            Self::ManagedRead => v1::HostControlVerb::ManagedRead as i32,
        }
    }
}

#[derive(Debug, Args)]
struct HostControlGrantArgs {
    #[command(flatten)]
    target: HostControlTarget,
    #[arg(long, value_parser = canonical_control_uuid)]
    grant_id: String,
    #[arg(long)]
    org: String,
    #[arg(long)]
    network: String,
    #[arg(long, value_parser = control_key)]
    caller_key: ControlKey,
    #[arg(long, value_parser = control_key)]
    target_key: ControlKey,
    #[arg(long, value_enum, value_delimiter = ',', required = true)]
    allow: Vec<GrantedVerb>,
    #[arg(long)]
    expected_book_revision: u64,
    #[arg(
        long,
        help = "Zero creates a new grant; an existing grant requires its observed revision"
    )]
    expected_grant_revision: u64,
}

#[derive(Debug, Args)]
struct HostControlRevokeArgs {
    #[command(flatten)]
    target: HostControlTarget,
    #[arg(long, value_parser = canonical_control_uuid)]
    grant_id: String,
    #[arg(long)]
    expected_book_revision: u64,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    expected_grant_revision: u64,
}

fn canonical_control_uuid(value: &str) -> Result<String, String> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| "expected a canonical nonnil UUID")?;
    if id.is_nil() || id.to_string() != value {
        return Err("expected a canonical nonnil UUID".into());
    }
    Ok(value.into())
}

fn control_key(value: &str) -> Result<ControlKey, String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected 64 lowercase hexadecimal public-key digits".into());
    }
    fn nibble(byte: u8) -> u8 {
        if byte.is_ascii_digit() {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    }
    let key = value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| nibble(pair[0]) * 16 + nibble(pair[1]))
        .collect::<Vec<_>>();
    if key.iter().all(|byte| *byte == 0) {
        return Err("public key must be nonzero".into());
    }
    Ok(ControlKey(key))
}

fn key_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(rendered, "{byte:02x}").expect("writing to String cannot fail");
    }
    rendered
}

fn select_control_host(
    environments: Vec<HostEnvironment>,
    requested: &str,
) -> anyhow::Result<HostEnvironment> {
    // A UUID-shaped selector is always an identity, including foreign or
    // noncanonical UUIDs. It must never rebind to a mutable same-name entry.
    let selected = if uuid::Uuid::parse_str(requested).is_ok() {
        canonical_control_uuid(requested).map_err(anyhow::Error::msg)?;
        environments.into_iter().find(|env| env.id == requested)
    } else {
        environments.into_iter().find(|env| env.name == requested)
    };
    selected.context("registered host environment was not found")
}

fn grants_json(response: &v1::HostControlGrantsResponse) -> serde_json::Value {
    serde_json::json!({
        "environment_id": response.environment_id,
        "book_revision": response.book_revision,
        "grants": response.grants.iter().map(|grant| serde_json::json!({
            "grant_id":grant.grant_id,"environment_id":grant.environment_id,
            "org_id":grant.org_id,"network_id":grant.network_id,
            "caller_key":key_hex(&grant.caller_key),"target_key":key_hex(&grant.target_key),
            "verbs":grant.verbs.iter().map(|verb| v1::HostControlVerb::try_from(*verb)
                .map(|verb| verb.as_str_name()).unwrap_or("UNSPECIFIED")).collect::<Vec<_>>(),
            "revision":grant.revision,"revoked":grant.revoked,
        })).collect::<Vec<_>>(),
    })
}

pub(crate) async fn handle_host_control_command(
    _globals: &Globals,
    args: HostControlArgs,
) -> anyhow::Result<()> {
    let target = match &args.command {
        HostControlCommand::Info(a) | HostControlCommand::List(a) => a,
        HostControlCommand::Grant(a) => &a.target,
        HostControlCommand::Revoke(a) => &a.target,
    };
    let environment = select_control_host(host_environments()?, &target.environment)?;
    let client = host_control_client(&environment).await?;
    let output = target.output;
    let response = match args.command {
        HostControlCommand::Info(_) => {
            let info = client.require_ready().await?;
            let value = serde_json::json!({"environment_id":info.environment_id,
                "protocol_version":info.protocol_version,
                "verbs": info.verbs.iter().map(|v| v1::HostControlVerb::try_from(*v)
                    .map(|v|v.as_str_name()).unwrap_or("UNSPECIFIED")).collect::<Vec<_>>()});
            match output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&value)?),
                OutputFormat::Text => println!(
                    "{}\thost control v{}",
                    environment.id, info.protocol_version
                ),
            }
            return Ok(());
        }
        HostControlCommand::List(_) => client.grants().await?,
        HostControlCommand::Grant(a) => {
            client
                .put_grant(v1::HostControlPutGrantRequest {
                    expected_book_revision: a.expected_book_revision,
                    grant: Some(v1::HostControlGrant {
                        grant_id: a.grant_id,
                        environment_id: environment.id,
                        org_id: a.org,
                        network_id: a.network,
                        caller_key: a.caller_key.0,
                        target_key: a.target_key.0,
                        verbs: a.allow.into_iter().map(GrantedVerb::wire).collect(),
                        revision: a.expected_grant_revision,
                        revoked: false,
                    }),
                })
                .await?
        }
        HostControlCommand::Revoke(a) => {
            client
                .revoke_grant(v1::HostControlRevokeGrantRequest {
                    expected_book_revision: a.expected_book_revision,
                    grant_id: a.grant_id,
                    expected_grant_revision: a.expected_grant_revision,
                })
                .await?
        }
    };
    match output {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&grants_json(&response))?)
        }
        OutputFormat::Text => {
            println!(
                "{}\tbook revision {}",
                response.environment_id, response.book_revision
            );
            for grant in response.grants {
                println!(
                    "{}\trevision {}\t{}",
                    grant.grant_id,
                    grant.revision,
                    if grant.revoked { "revoked" } else { "active" }
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_control_selectors_never_rebind_uuid_to_a_name() {
        let requested = uuid::Uuid::new_v4().to_string();
        let id = uuid::Uuid::new_v4().to_string();
        let env = HostEnvironment {
            id: id.clone(),
            name: requested.clone(),
            path: "/tmp".into(),
            created_at: String::new(),
            state: "running".into(),
            runtime_root: None,
        };
        assert!(select_control_host(vec![env.clone()], &requested).is_err());
        assert_eq!(select_control_host(vec![env], &id).unwrap().id, id);
    }

    #[test]
    fn host_control_owner_inputs_require_canonical_public_identity() {
        assert!(canonical_control_uuid(&uuid::Uuid::nil().to_string()).is_err());
        assert!(control_key(&"0".repeat(64)).is_err());
        assert!(control_key(&"AB".repeat(32)).is_err());
        assert_eq!(control_key(&"01".repeat(32)).unwrap().0, vec![1; 32]);
    }

    #[test]
    fn host_control_parser_keeps_fixed_public_key_bytes_and_explicit_cas() {
        let grant = uuid::Uuid::new_v4().to_string();
        let caller = "01".repeat(32);
        let target = "02".repeat(32);
        let args = [
            "cw",
            "control",
            "grant",
            "--environment",
            "registered-host",
            "--grant-id",
            &grant,
            "--org",
            "synthetic-org",
            "--network",
            "synthetic-network",
            "--caller-key",
            &caller,
            "--target-key",
            &target,
            "--allow",
            "read,launch,input,stop",
            "--expected-book-revision",
            "0",
            "--expected-grant-revision",
            "0",
        ];
        let parsed = crate::Cli::try_parse_from(args).unwrap();
        let crate::Command::Control(HostControlArgs {
            command: HostControlCommand::Grant(value),
        }) = parsed.command
        else {
            panic!("control grant parsed incorrectly")
        };
        assert_eq!(value.caller_key.0, vec![1; 32]);
        assert_eq!(value.target_key.0, vec![2; 32]);
        assert_eq!(
            value
                .allow
                .into_iter()
                .map(GrantedVerb::wire)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        let mut missing = args.to_vec();
        missing.truncate(missing.len() - 2);
        assert!(crate::Cli::try_parse_from(missing).is_err());
    }

    /// Bounds a wait on an event, so a hang fails instead of stalling the run.
    /// It is never the expected duration: a loaded CI slot can stall for
    /// seconds.
    const HANG: Duration = Duration::from_secs(120);

    /// Mutates and returns the request's outcome. The daemon answers with
    /// the receipt it has after its RPC join bound, which on a stalled slot
    /// can still be unsettled; the outcome is then the settled receipt.
    async fn outcome(
        client: &codewire_daemon::client::HostControlClient,
        request: v1::HostControlMutationRequest,
    ) -> v1::HostControlReceipt {
        let receipt = client.mutate(request.clone()).await.unwrap();
        let unsettled = |receipt: &v1::HostControlReceipt| {
            [
                v1::HostControlRequestPhase::Pending as i32,
                v1::HostControlRequestPhase::Issued as i32,
            ]
            .contains(&receipt.phase)
        };
        if !unsettled(&receipt) {
            return receipt;
        }
        tokio::time::timeout(HANG, async {
            loop {
                let receipt = client
                    .observe(v1::HostControlObserveRequest {
                        request_id: request.request_id.clone(),
                        scope: request.scope.clone(),
                    })
                    .await
                    .unwrap();
                if !unsettled(&receipt) {
                    return receipt;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap()
    }

    /// #3774: the failure from CI, made certain. The real daemon replies before
    /// its request can settle, the client follows the same request, and a launch
    /// that succeeded reads as one. It would read as "not confirmed" without
    /// that. Every other host bound is a hang guard.
    #[tokio::test]
    async fn a_reply_before_the_request_settles_still_reports_the_success() {
        use tokio_stream::wrappers::UnixListenerStream;
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        private_directory(&registry).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let root = registry.join(&id);
        private_directory(&root).unwrap();
        let home = temp.path().join("home");
        private_directory(&home).unwrap();
        let workspace = temp.path().join("workspace");
        private_directory(&workspace).unwrap();
        let environment = HostEnvironment {
            id: id.clone(),
            name: "synthetic-host".into(),
            path: workspace.clone(),
            created_at: String::new(),
            state: "running".into(),
            runtime_root: Some(root.clone()),
        };
        let token = "synthetic-owner-uds-host-control";
        write_private_json(&root.join("host.json"), &environment).unwrap();
        write_private_json(&root.join("daemon-token.json"), &token).unwrap();
        let config = codewire_daemon::Config {
            listen_addr: String::new(),
            workspace_root: workspace,
            home_root: home,
            mount_roots: Vec::new(),
            auth_token: codewire_daemon::DaemonAuthToken::new(token).unwrap(),
            process_execution: codewire_daemon::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            launch_projection: None,
            host: Some(codewire_daemon::HostConfig {
                state_root: root.clone(),
            }),
            session_working_dir: None,
        };
        let socket = root.join("daemon.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let (closing, closed) = tokio::sync::oneshot::channel();
        let binding = codewire_daemon::host_control::HostControlBinding::new(id.clone()).unwrap();
        let server = tokio::spawn(async move {
            codewire_daemon::serve_host_control_grpc_replying_within(
                config,
                binding,
                UnixListenerStream::new(listener),
                async {
                    let _ = closed.await;
                },
                HANG,
                Duration::ZERO,
            )
            .await
        });
        let client = host_control_client_within(&environment, HANG)
            .await
            .unwrap();
        let grant = uuid::Uuid::new_v4().to_string();
        client
            .put_grant(v1::HostControlPutGrantRequest {
                expected_book_revision: 0,
                grant: Some(v1::HostControlGrant {
                    environment_id: id.clone(),
                    grant_id: grant.clone(),
                    org_id: "synthetic-org".into(),
                    network_id: "synthetic-network".into(),
                    caller_key: vec![1; 32],
                    target_key: vec![2; 32],
                    verbs: vec![1, 2, 3, 4],
                    revision: 0,
                    revoked: false,
                }),
            })
            .await
            .unwrap();
        let scope = v1::HostControlScope {
            environment_id: id,
            org_id: "synthetic-org".into(),
            network_id: "synthetic-network".into(),
            caller_key: vec![1; 32],
            target_key: vec![2; 32],
            grant_id: grant,
            expected_grant_revision: 1,
        };
        let request = v1::HostControlMutationRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            scope: Some(scope.clone()),
            operation: Some(v1::host_control_mutation_request::Operation::Launch(
                v1::HostControlLaunch {
                    command: vec!["/bin/sh".into(), "-c".into(), "read line".into()],
                    ..Default::default()
                },
            )),
        };
        let reply = client.mutate(request.clone()).await.unwrap();
        let unfinished = [
            v1::HostControlRequestPhase::Pending as i32,
            v1::HostControlRequestPhase::Issued as i32,
        ];
        assert!(unfinished.contains(&reply.phase), "{}", reply.phase);
        assert!(super::super::member_control::complete(&reply).is_err());
        let settled = super::super::member_control::settle_receipt(
            reply,
            HANG,
            Duration::from_millis(5),
            async || {
                Ok(client
                    .observe(v1::HostControlObserveRequest {
                        request_id: request.request_id.clone(),
                        scope: request.scope.clone(),
                    })
                    .await?)
            },
        )
        .await
        .unwrap();
        super::super::member_control::complete(&settled).unwrap();
        closing.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn host_control_private_socket_round_trip_never_starts_or_replays_an_owner() {
        use tokio_stream::wrappers::UnixListenerStream;
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        private_directory(&registry).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let root = registry.join(&id);
        private_directory(&root).unwrap();
        let home = temp.path().join("home");
        private_directory(&home).unwrap();
        let workspace = temp.path().join("workspace");
        private_directory(&workspace).unwrap();
        let environment = HostEnvironment {
            id: id.clone(),
            name: "synthetic-host".into(),
            path: workspace.clone(),
            created_at: String::new(),
            state: "running".into(),
            runtime_root: Some(root.clone()),
        };
        let token = "synthetic-owner-uds-host-control";
        write_private_json(&root.join("host.json"), &environment).unwrap();
        write_private_json(&root.join("daemon-token.json"), &token).unwrap();
        assert!(host_control_client(&environment).await.is_err());
        assert!(!root.join("daemon.sock").exists());
        assert!(!root.join("daemon.log").exists());
        assert!(!root.join("lifecycle.lock").exists());
        let config = codewire_daemon::Config {
            listen_addr: String::new(),
            workspace_root: workspace,
            home_root: home,
            mount_roots: Vec::new(),
            auth_token: codewire_daemon::DaemonAuthToken::new(token).unwrap(),
            process_execution: codewire_daemon::execution::ProcessExecution::Native,
            credential_bridge: None,
            managed_credential_clients: Default::default(),
            launch_projection: None,
            host: Some(codewire_daemon::HostConfig {
                state_root: root.clone(),
            }),
            session_working_dir: None,
        };
        let socket = root.join("daemon.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let (closing, closed) = tokio::sync::oneshot::channel();
        let binding = codewire_daemon::host_control::HostControlBinding::new(id.clone()).unwrap();
        // The host sessions' cleanup and dispatch bounds ran out on a loaded
        // CI slot and a confirmed stop read as unknown. This test is about
        // neither, so they are a hang guard here.
        let server = tokio::spawn(async move {
            codewire_daemon::serve_host_control_grpc_within(
                config,
                binding,
                UnixListenerStream::new(listener),
                async {
                    let _ = closed.await;
                },
                Some(HANG),
            )
            .await
        });
        // The production 5 s request timeout ran out on a loaded CI host
        // while the daemon launched the owner (#3231). This proves the
        // protocol, not its latency; the bound only turns a hang into a
        // failure.
        let client = host_control_client_within(&environment, HANG)
            .await
            .unwrap();
        let grant = uuid::Uuid::new_v4().to_string();
        let response = client
            .put_grant(v1::HostControlPutGrantRequest {
                expected_book_revision: 0,
                grant: Some(v1::HostControlGrant {
                    environment_id: id.clone(),
                    grant_id: grant.clone(),
                    org_id: "synthetic-org".into(),
                    network_id: "synthetic-network".into(),
                    caller_key: vec![1; 32],
                    target_key: vec![2; 32],
                    verbs: vec![1, 2, 3, 4],
                    revision: 0,
                    revoked: false,
                }),
            })
            .await
            .unwrap();
        assert_eq!(response.book_revision, 1);
        let scope = v1::HostControlScope {
            environment_id: id.clone(),
            org_id: "synthetic-org".into(),
            network_id: "synthetic-network".into(),
            caller_key: vec![1; 32],
            target_key: vec![2; 32],
            grant_id: grant.clone(),
            expected_grant_revision: 1,
        };
        let request = v1::HostControlMutationRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            scope: Some(scope.clone()),
            operation: Some(v1::host_control_mutation_request::Operation::Launch(
                v1::HostControlLaunch {
                    command: vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "printf through-owner; read line".into(),
                    ],
                    ..Default::default()
                },
            )),
        };
        let launched = outcome(&client, request.clone()).await;
        assert_eq!(
            launched.phase,
            v1::HostControlRequestPhase::Completed as i32
        );
        assert_eq!(
            client.mutate(request).await.unwrap().session_id,
            launched.session_id
        );
        let read = v1::HostControlReadRequest {
            scope: Some(scope.clone()),
            session_id: launched.session_id.clone(),
            ..Default::default()
        };
        tokio::time::timeout(HANG, async {
            loop {
                if client.get(read.clone()).await.unwrap().output_end_offset == 13 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let output = client
            .read_output(v1::HostControlReadRequest {
                limit: 4,
                ..read.clone()
            })
            .await
            .unwrap();
        assert_eq!(
            output
                .chunks
                .into_iter()
                .flat_map(|chunk| chunk.data)
                .collect::<Vec<_>>(),
            b"thro"
        );
        assert_eq!(output.next_offset, 4);
        let page = client
            .list(v1::HostControlReadRequest {
                scope: Some(scope.clone()),
                page_limit: 1,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(page.sessions.len(), 1);
        assert!(page.next_session_id.is_empty());
        let stopped = outcome(
            &client,
            v1::HostControlMutationRequest {
                request_id: uuid::Uuid::new_v4().to_string(),
                scope: Some(scope.clone()),
                operation: Some(v1::host_control_mutation_request::Operation::Stop(
                    v1::HostControlStop {
                        session_id: launched.session_id.clone(),
                        expected_launch_generation: 1,
                    },
                )),
            },
        )
        .await;
        assert_eq!(stopped.phase, v1::HostControlRequestPhase::Completed as i32);
        assert!(!stopped.cleanup_unknown);
        client
            .revoke_grant(v1::HostControlRevokeGrantRequest {
                expected_book_revision: 1,
                grant_id: grant,
                expected_grant_revision: 1,
            })
            .await
            .unwrap();
        assert!(client.get(read).await.is_err());
        assert_eq!(
            client
                .observe(v1::HostControlObserveRequest {
                    request_id: launched.request_id,
                    scope: Some(scope)
                })
                .await
                .unwrap()
                .phase,
            v1::HostControlRequestPhase::Completed as i32
        );
        closing.send(()).unwrap();
        server.await.unwrap().unwrap();
        assert!(host_control_client(&environment).await.is_err());
        assert!(!root.join("daemon.log").exists());
        assert!(!root.join("lifecycle.lock").exists());
    }
}
