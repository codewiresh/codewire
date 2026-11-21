use super::git_identity::{GitIdentityOutcome, configure_environment_outcome};
use super::*;
use std::sync::{Arc, Mutex};

#[derive(Default, Clone)]
struct MockState {
    calls: Vec<String>,
    phases: Vec<i32>,
    complete: bool,
    error: Option<(i32, String)>,
    shutdown_ttl: Option<i32>,
    startup_launches: Vec<(String, String)>,
    fail_step: Option<&'static str>,
    authority_loss_step: Option<&'static str>,
    recovery_failure_step: Option<&'static str>,
    cancellation_step: Option<&'static str>,
    cancel_before_commit: bool,
    daemon: Option<DaemonReadiness>,
}

#[derive(Clone)]
struct Mock(Arc<Mutex<MockState>>);

impl Mock {
    fn new() -> Self {
        Mock(Arc::new(Mutex::new(MockState::default())))
    }
    fn failing(step: &'static str) -> Self {
        let m = Self::new();
        m.0.lock().unwrap().fail_step = Some(step);
        m
    }
    fn losing_authority(step: &'static str) -> Self {
        let m = Self::new();
        m.0.lock().unwrap().authority_loss_step = Some(step);
        m
    }
    fn failing_recovery(step: &'static str) -> Self {
        let m = Self::new();
        m.0.lock().unwrap().recovery_failure_step = Some(step);
        m
    }
    fn cancelling_before_commit() -> Self {
        let m = Self::new();
        m.0.lock().unwrap().cancel_before_commit = true;
        m
    }
    fn call(&self, name: &str) -> anyhow::Result<()> {
        let mut s = self.0.lock().unwrap();
        s.calls.push(name.to_string());
        if s.authority_loss_step == Some(name) {
            return Err(super::super::activity_authority::AuthorityLost.into());
        }
        if s.cancellation_step == Some(name) {
            return Err(SetupActivityCancelled.into());
        }
        if s.recovery_failure_step == Some(name) {
            return Err(SetupRecoveryFailed {
                message: format!("{name} recovery boom"),
            }
            .into());
        }
        if s.fail_step == Some(name) {
            anyhow::bail!("{name} boom");
        }
        Ok(())
    }
    fn state(&self) -> MockState {
        self.0.lock().unwrap().clone()
    }
}

impl SetupStore for Mock {
    async fn complete_phase(
        &self,
        _env_id: &str,
        completion: PhaseCompletion<'_>,
    ) -> anyhow::Result<()> {
        let mut state = self.0.lock().unwrap();
        state
            .calls
            .push(format!("log:{}:{}", completion.step, completion.status));
        state.phases.push(completion.next_phase);
        Ok(())
    }
    async fn complete_setup(
        &self,
        _env_id: &str,
        _phase: i32,
        ttl_seconds: Option<i32>,
    ) -> anyhow::Result<()> {
        let mut state = self.0.lock().unwrap();
        state.complete = true;
        state.shutdown_ttl = ttl_seconds.filter(|ttl| *ttl > 0);
        state.calls.push("log:complete:completed".to_string());
        Ok(())
    }
    async fn set_error(&self, _env_id: &str, phase: i32, msg: &str) -> anyhow::Result<()> {
        self.0.lock().unwrap().error = Some((phase, msg.to_string()));
        Ok(())
    }
}

impl SetupOps for Mock {
    async fn prepare_phase(
        &mut self,
        _input: &Inputs,
        _phase: i32,
    ) -> anyhow::Result<PhaseAcquire> {
        Ok(PhaseAcquire::Acquired)
    }

    async fn emit_log(
        &self,
        _env_id: &str,
        _phase_number: i32,
        step: &str,
        status: &str,
        _message: &str,
        _data: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        self.0
            .lock()
            .unwrap()
            .calls
            .push(format!("log:{step}:{status}"));
        Ok(())
    }
    async fn ensure_can_commit(&self) -> anyhow::Result<()> {
        if self.0.lock().unwrap().cancel_before_commit {
            return Err(SetupActivityCancelled.into());
        }
        Ok(())
    }
    async fn health_check(&mut self, _input: &Inputs) -> anyhow::Result<Option<DaemonReadiness>> {
        self.call("health_check")?;
        Ok(self.0.lock().unwrap().daemon.clone())
    }
    async fn configure_environment(&mut self, _input: &Inputs) -> anyhow::Result<()> {
        self.call("configure_environment")
    }
    async fn clone_repos(&mut self, _input: &Inputs) -> anyhow::Result<()> {
        self.call("clone_repos")
    }
    async fn run_install(&mut self, _input: &Inputs, _wd: &str) -> anyhow::Result<()> {
        self.call("run_install")
    }
    async fn run_startup_script(&mut self, input: &Inputs, wd: &str) -> anyhow::Result<()> {
        assert_eq!(wd, input.working_directory);
        self.0
            .lock()
            .unwrap()
            .startup_launches
            .push((input.startup_script.clone(), wd.to_string()));
        self.call("run_startup_script")
    }
    async fn validate_agents(&mut self, _input: &Inputs) -> anyhow::Result<()> {
        self.call("validate_agents")
    }
    async fn register_ports(&mut self, _input: &Inputs) -> anyhow::Result<()> {
        self.call("register_ports")
    }
}

fn full_inputs() -> Inputs {
    Inputs {
        environment_id: "env-1".into(),
        namespace: "ns".into(),
        desired_state: "started".into(),
        has_setup: true,
        repos: vec![Repo {
            url: "https://x/y/app.git".into(),
            revision: String::new(),
            branch: "".into(),
            mount_path: "/workspace/app".into(),
            known_hosts: Vec::new(),
        }],
        working_directory: "/workspace/app".into(),
        install_command: "npm ci".into(),
        startup_script: "npm start".into(),
        agents: vec!["claude-code".into()],
        app_ports: vec![(3000, "web".into(), "public".into())],
        ttl_seconds: Some(7200),
        ..Default::default()
    }
}

#[tokio::test]
async fn post_start_runs_script_after_completed_setup_without_replaying_install() {
    let mut mock = Mock::new();
    let mut input = full_inputs();
    input.setup_complete = true;
    input.setup_phase = 7;
    input.startup_script = "./current-startup.sh".into();
    input.working_directory = "/workspace/current".into();
    run_post_start_script(&mut mock, &input).await.unwrap();
    let state = mock.state();
    assert_eq!(
        state.calls,
        [
            "log:startup_script:started",
            "run_startup_script",
            "log:startup_script:completed",
        ]
    );
    assert!(state.phases.is_empty());
    assert_eq!(
        state.startup_launches,
        [("./current-startup.sh".into(), "/workspace/current".into())]
    );
    assert!(!state.complete);
    assert_eq!(input.setup_phase, 7);
    assert!(input.setup_complete);
}

#[tokio::test]
async fn post_start_skips_empty_script() {
    let mut mock = Mock::new();
    let mut input = full_inputs();
    input.startup_script.clear();
    run_post_start_script(&mut mock, &input).await.unwrap();
    assert!(mock.state().calls.is_empty());
}

#[tokio::test]
async fn post_start_script_failure_is_warning_only() {
    let mut mock = Mock::failing("run_startup_script");
    run_post_start_script(&mut mock, &full_inputs())
        .await
        .unwrap();
    assert_eq!(
        mock.state().calls,
        [
            "log:startup_script:started",
            "run_startup_script",
            "log:startup_script:warning",
        ]
    );
    assert!(mock.state().phases.is_empty());
}

#[tokio::test]
async fn post_start_propagates_control_flow_without_success_or_warning() {
    let cancelled = Mock::new();
    cancelled.0.lock().unwrap().cancellation_step = Some("run_startup_script");
    for mut mock in [
        Mock::losing_authority("run_startup_script"),
        Mock::failing_recovery("run_startup_script"),
        cancelled,
        Mock::cancelling_before_commit(),
    ] {
        let error = run_post_start_script(&mut mock, &full_inputs())
            .await
            .unwrap_err();
        assert!(is_setup_control_flow(&error), "{error:#}");
        let state = mock.state();
        assert_eq!(
            state.calls,
            ["log:startup_script:started", "run_startup_script"]
        );
        assert!(state.phases.is_empty());
        assert!(!state.complete);
    }
}

#[tokio::test]
async fn run_executes_all_phases_in_order() {
    let mock = Mock::new();
    let mut runner = Runner {
        store: mock.clone(),
        ops: mock.clone(),
    };
    let mut input = full_inputs();
    runner.run(&mut input).await.unwrap();
    let s = mock.state();
    let ops: Vec<&str> = s
        .calls
        .iter()
        .filter(|c| !c.starts_with("log:"))
        .map(String::as_str)
        .collect();
    assert_eq!(
        ops,
        [
            "health_check",
            "configure_environment",
            "clone_repos",
            "run_install",
            "run_startup_script",
            "validate_agents",
            "register_ports"
        ]
    );
    assert_eq!(s.phases, vec![1, 2, 3, 4, 5, 6, 7]);
    assert!(s.complete);
    assert_eq!(s.shutdown_ttl, Some(7200));
    assert!(input.setup_complete);
}

#[tokio::test]
async fn run_without_setup_completes_after_configuration() {
    let mock = Mock::new();
    let mut runner = Runner {
        store: mock.clone(),
        ops: mock.clone(),
    };
    let mut input = Inputs {
        environment_id: "env-1".into(),
        ..Default::default()
    };
    runner.run(&mut input).await.unwrap();
    let s = mock.state();
    assert_eq!(s.phases, vec![1, 2]);
    assert!(s.complete);
    assert_eq!(s.shutdown_ttl, None);
    assert!(s.calls.contains(&"log:complete:completed".to_string()));
    assert!(!s.calls.iter().any(|c| c == "clone_repos"));
}

#[tokio::test]
async fn run_resumes_from_recorded_phase() {
    let mock = Mock::new();
    let mut runner = Runner {
        store: mock.clone(),
        ops: mock.clone(),
    };
    let mut input = full_inputs();
    input.setup_phase = 3; // health/configuration/clone already done
    runner.run(&mut input).await.unwrap();
    let s = mock.state();
    let ops: Vec<&str> = s
        .calls
        .iter()
        .filter(|c| !c.starts_with("log:"))
        .map(String::as_str)
        .collect();
    assert_eq!(
        ops,
        [
            "run_install",
            "run_startup_script",
            "validate_agents",
            "register_ports"
        ]
    );
    assert_eq!(s.phases, vec![4, 5, 6, 7]);
}

/// Retry setup (#4767): a setup that failed at install, run again from the
/// checkpoint it recorded, runs install and what follows, and never a step
/// before it.
#[tokio::test]
async fn a_retry_after_a_failed_install_runs_no_earlier_step() {
    let failed = Mock::failing("run_install");
    let mut runner = Runner {
        store: failed.clone(),
        ops: failed.clone(),
    };
    let mut input = full_inputs();
    runner.run(&mut input).await.unwrap_err();
    let checkpoint = *failed.state().phases.last().unwrap();
    assert_eq!(
        checkpoint, 3,
        "the failure is recorded at the install checkpoint"
    );

    let retry = Mock::new();
    let mut runner = Runner {
        store: retry.clone(),
        ops: retry.clone(),
    };
    let mut input = full_inputs();
    input.setup_phase = checkpoint;
    runner.run(&mut input).await.unwrap();
    let s = retry.state();
    for earlier in ["health_check", "configure_environment", "clone_repos"] {
        assert!(
            !s.calls.iter().any(|call| call == earlier),
            "{earlier} ran again"
        );
    }
    let ops: Vec<&str> = s
        .calls
        .iter()
        .filter(|call| !call.starts_with("log:"))
        .map(String::as_str)
        .collect();
    assert_eq!(ops.first(), Some(&"run_install"));
    assert!(s.complete);
}

#[tokio::test]
async fn already_complete_is_a_noop() {
    let mock = Mock::new();
    let mut runner = Runner {
        store: mock.clone(),
        ops: mock.clone(),
    };
    let mut input = full_inputs();
    input.setup_complete = true;
    runner.run(&mut input).await.unwrap();
    assert!(mock.state().calls.is_empty());
    assert!(!mock.state().complete);
}

#[tokio::test]
async fn install_failure_aborts_with_wrapped_error() {
    let mock = Mock::failing("run_install");
    let mut runner = Runner {
        store: mock.clone(),
        ops: mock.clone(),
    };
    let mut input = full_inputs();
    let err = runner.run(&mut input).await.unwrap_err();
    assert!(format!("{err:#}").starts_with("install: "), "{err:#}");
    let s = mock.state();
    assert!(!s.complete);
    assert_eq!(s.phases, vec![1, 2, 3]); // stopped at install
    assert!(s.calls.contains(&"log:install:failed".to_string()));
}

#[tokio::test]
async fn startup_script_failure_is_warning_only() {
    let mock = Mock::failing("run_startup_script");
    let mut runner = Runner {
        store: mock.clone(),
        ops: mock.clone(),
    };
    let mut input = full_inputs();
    runner.run(&mut input).await.unwrap();
    let s = mock.state();
    assert!(s.complete);
    assert!(s.calls.contains(&"log:startup_script:warning".to_string()));
    assert_eq!(s.phases, vec![1, 2, 3, 4, 5, 6, 7]);
}

#[tokio::test]
async fn unavailable_selected_agent_fails_setup_without_a_download() {
    let mock = Mock::failing("validate_agents");
    let mut runner = Runner {
        store: mock.clone(),
        ops: mock.clone(),
    };
    let mut input = full_inputs();
    let error = runner.run(&mut input).await.unwrap_err();
    assert!(
        format!("{error:#}").starts_with("agent validation: validate_agents boom"),
        "{error:#}"
    );
    let state = mock.state();
    assert!(!state.complete);
    assert_eq!(state.phases, vec![1, 2, 3, 4, 5]);
    assert!(
        state
            .calls
            .contains(&"log:agent_validation:failed".to_string())
    );
    assert!(!state.calls.iter().any(|call| call == "install_agents"));
}

#[tokio::test]
async fn authority_loss_escapes_every_runner_path_without_advancing() {
    for step in [
        "health_check",
        "configure_environment",
        "clone_repos",
        "run_install",
        "run_startup_script",
        "validate_agents",
        "register_ports",
    ] {
        let mock = Mock::losing_authority(step);
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = full_inputs();
        let error = runner.run(&mut input).await.unwrap_err();
        assert!(
            is_authority_lost(&error),
            "{step} hid authority loss: {error:#}"
        );
        let state = mock.state();
        assert!(
            !state.complete,
            "{step} completed setup after authority loss"
        );
        let log_step = match step {
            "run_startup_script" => "startup_script",
            other => other,
        };
        assert!(
            !state
                .calls
                .iter()
                .any(|call| call == &format!("log:{log_step}:warning")),
            "{step} converted authority loss into a warning"
        );
    }
}

#[tokio::test]
async fn recovery_failure_escapes_every_runner_path_without_advancing() {
    for step in [
        "health_check",
        "configure_environment",
        "clone_repos",
        "run_install",
        "run_startup_script",
        "validate_agents",
        "register_ports",
    ] {
        let mock = Mock::failing_recovery(step);
        let mut runner = Runner {
            store: mock.clone(),
            ops: mock.clone(),
        };
        let mut input = full_inputs();
        let error = runner.run(&mut input).await.unwrap_err();
        assert!(
            is_setup_recovery_failed(&error),
            "{step} hid retryable recovery failure: {error:#}"
        );
        let state = mock.state();
        assert!(
            !state.complete,
            "{step} completed setup after recovery failure"
        );
        let log_step = match step {
            "run_startup_script" => "startup_script",
            other => other,
        };
        assert!(
            !state
                .calls
                .iter()
                .any(|call| call == &format!("log:{log_step}:warning")),
            "{step} converted retryable recovery failure into a warning"
        );
    }
}

#[tokio::test]
async fn cancellation_barrier_prevents_phase_advance_after_work_returns() {
    let mock = Mock::cancelling_before_commit();
    let mut runner = Runner {
        store: mock.clone(),
        ops: mock.clone(),
    };
    let mut input = full_inputs();
    let error = runner.run(&mut input).await.unwrap_err();
    assert!(is_setup_activity_cancelled(&error));
    let state = mock.state();
    assert!(state.phases.is_empty());
    assert!(!state.complete);
    assert!(state.calls.contains(&"health_check".to_string()));
    assert!(
        !state
            .calls
            .contains(&"log:health_check:completed".to_string())
    );
}

/// #3684: the daemon status read beside the health check becomes a
/// `daemon_ready` row inside phase 0, before setup completes; with no
/// status read, no row is written and `cw create` asks the API as before.
#[tokio::test]
async fn the_daemon_status_read_beside_the_health_check_is_logged_before_complete() {
    let mock = Mock::new();
    mock.0.lock().unwrap().daemon = Some(DaemonReadiness {
        state: "ready",
        message: String::new(),
        defaults_generation: None,
    });
    let mut runner = Runner {
        store: mock.clone(),
        ops: mock.clone(),
    };
    let mut input = full_inputs();
    runner.run(&mut input).await.unwrap();
    let calls = mock.state().calls;
    let at = |entry: &str| calls.iter().position(|call| call == entry);
    let daemon = at("log:daemon_ready:completed").expect("a daemon_ready row");
    assert!(at("health_check").is_some_and(|check| check < daemon));
    assert!(
        calls[daemon..]
            .iter()
            .any(|call| call == "log:git_clone:started"),
        "the row is written in phase 0, before the later phases"
    );
    assert!(mock.state().complete);

    let mock = Mock::new();
    let mut runner = Runner {
        store: mock.clone(),
        ops: mock.clone(),
    };
    let mut input = full_inputs();
    runner.run(&mut input).await.unwrap();
    assert!(
        !mock
            .state()
            .calls
            .iter()
            .any(|call| call.starts_with("log:daemon_ready")),
        "no status read, no row"
    );
}

fn member(name: &str, uid: &str) -> Incarnation {
    Incarnation {
        name: name.into(),
        uid: uid.into(),
    }
}

#[tokio::test(start_paused = true)]
async fn recovery_waits_until_no_member_is_left_under_any_name() {
    let runtime = crate::runtime::fake::FakeRuntimeDriver::default();
    *runtime.member_reads.lock().unwrap() = [
        vec![member("workspace-old", "uid-old")],
        // A replacement under the old name, then one under another name,
        // are still members: neither proves the environment is empty.
        vec![member("workspace-old", "uid-new")],
        vec![member("workspace-other", "uid-other")],
        vec![],
    ]
    .into();
    let began = tokio::time::Instant::now();

    wait_for_no_workspace_pod(
        &runtime,
        &Placement::new("dev-sandboxes"),
        "env-1",
        "workspace-old",
        "uid-old",
    )
    .await
    .unwrap();

    assert_eq!(runtime.member_reads.lock().unwrap().len(), 1);
    assert_eq!(
        began.elapsed(),
        SETUP_POD_RECOVERY_POLL * 3 + SETUP_EXEC_QUIESCENCE
    );
}

#[tokio::test(start_paused = true)]
async fn recovery_gives_up_at_its_bound_while_a_member_remains() {
    let runtime = crate::runtime::fake::FakeRuntimeDriver::default();
    *runtime.member_reads.lock().unwrap() = [vec![member("workspace-other", "uid-other")]].into();
    let began = tokio::time::Instant::now();

    let error = wait_for_no_workspace_pod(
        &runtime,
        &Placement::new("dev-sandboxes"),
        "env-1",
        "workspace-old",
        "uid-old",
    )
    .await
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "setup recovery timed out waiting for Pod workspace-old (uid-old) to be absent"
    );
    assert_eq!(began.elapsed(), SETUP_POD_RECOVERY_TIMEOUT);
}

/// Setup recovery binds the replacement Pod before its access wait: an
/// identity-free daemon serves SSH only once bound (design §10).
#[tokio::test]
async fn recovery_binds_the_replacement_before_its_access_wait() {
    let steps = Arc::new(Mutex::new(Vec::new()));
    let step = |name: &'static str, result: anyhow::Result<()>| {
        let steps = Arc::clone(&steps);
        async move {
            steps.lock().unwrap().push(name);
            result
        }
    };

    let reached = bind_replacement_then_await_access(step("bind", Ok(())), step("access", Ok(())))
        .await
        .unwrap();
    assert_eq!(reached, ReplacementAccess::Ready);
    assert_eq!(*steps.lock().unwrap(), ["bind", "access"]);

    for refusal in [
        BindRefused::NotConverged,
        BindRefused::PodChanged,
        BindRefused::ChainUnverified,
    ] {
        steps.lock().unwrap().clear();
        let reached = bind_replacement_then_await_access(
            step("bind", Err(refusal.into())),
            step("access", Ok(())),
        )
        .await
        .unwrap();
        assert_eq!(reached, ReplacementAccess::NotYetBindable);
        assert_eq!(*steps.lock().unwrap(), ["bind"], "{refusal:?}");
    }

    for failure in [
        anyhow::Error::from(BindRefused::BoundElsewhere),
        anyhow::Error::from(BindRefused::Denied("released binding")),
        anyhow::Error::from(super::super::activity_authority::AuthorityLost),
    ] {
        steps.lock().unwrap().clear();
        assert!(
            bind_replacement_then_await_access(step("bind", Err(failure)), step("access", Ok(())),)
                .await
                .is_err()
        );
        assert_eq!(*steps.lock().unwrap(), ["bind"]);
    }

    steps.lock().unwrap().clear();
    assert!(
        bind_replacement_then_await_access(
            step("bind", Ok(())),
            step("access", Err(anyhow::anyhow!("access timed out"))),
        )
        .await
        .is_err()
    );
    assert_eq!(*steps.lock().unwrap(), ["bind", "access"]);
}

#[test]
fn ordinary_recovery_errors_are_retryable_control_flow() {
    let recovery = classify_setup_recovery_error(anyhow::anyhow!("scale down failed"));
    assert!(is_setup_recovery_failed(&recovery));
    let authority =
        classify_setup_recovery_error(super::super::activity_authority::AuthorityLost.into());
    assert!(is_authority_lost(&authority));
    assert!(!is_setup_recovery_failed(&authority));
}

#[tokio::test]
async fn record_error_writes_phase_and_message() {
    let mock = Mock::new();
    let runner = Runner {
        store: mock.clone(),
        ops: mock.clone(),
    };
    runner
        .record_error("env-1", 4, &anyhow::anyhow!("install: npm ci exploded"))
        .await
        .unwrap();
    assert_eq!(
        mock.state().error,
        Some((4, "install: npm ci exploded".to_string()))
    );
}

#[test]
fn to_setup_inputs_consumes_the_canonical_project_spec() {
    let env = EnvironmentRow {
        id: "env-1".into(),
        org_id: "org-1".into(),
        preset_id: None,
        env_type: "sandbox".into(),
        state: "running".into(),
        desired_state: "started".into(),
        isolation_tier: "standard".into(),
        dedicated_cpu: false,
        never_ran: false,
        external_cleanup_completed_at: None,
        cpu_millicores: 2000,
        memory_mb: 4096,
        disk_gb: 10,
        source_snapshot_id: None,
        ttl_seconds: Some(3600),
        project_spec: codewire_project::ProjectSpec::default(),
        operation_generation: 7,
        projection_selection: Ok(None),
        managed_credential_clients: Ok(Default::default()),
    };
    let backend = BackendRow {
        namespace: "ns".into(),
        setup_phase: 2,
        ..Default::default()
    };
    let input = to_setup_inputs(&env, &backend);
    assert!(!input.has_setup);
    assert_eq!(input.setup_phase, 2);
    assert_eq!(input.ttl_seconds, Some(3600));

    // #3684: saved variables alone are written by `configure_environment`,
    // which runs either way, so they leave no work for a later phase.
    let mut env = env;
    env.project_spec.environment = BTreeMap::from([("APP_MODE".into(), "test".into())]);
    assert!(!to_setup_inputs(&env, &backend).has_setup);

    env.project_spec = codewire_project::ProjectSpec {
        repositories: vec![codewire_project::RepositorySpec {
            source: "https://g/o/r.git".into(),
            branch: "dev".into(),
            destination: "/workspace/r".into(),
            ..Default::default()
        }],
        working_directory: "/workspace/r".into(),
        environment: BTreeMap::from([("APP_MODE".into(), "test".into())]),
        agents: codewire_project::AgentsSpec {
            install: Some(true),
            tools: vec!["codex".into()],
        },
        application_ports: vec![
            codewire_project::ApplicationPort {
                port: 8080,
                label: "api".into(),
                access: String::new(),
            },
            // Saved before the desktop's ports were reserved: never registered.
            codewire_project::ApplicationPort {
                port: codewire_daemon_proto::DESKTOP_VNC_PORT,
                label: "desktop".into(),
                access: String::new(),
            },
            codewire_project::ApplicationPort {
                port: codewire_daemon_proto::BROWSER_DEBUG_PORT,
                label: "devtools".into(),
                access: String::new(),
            },
        ],
        ..Default::default()
    };
    let input = to_setup_inputs(&env, &backend);
    assert!(input.has_setup);
    assert_eq!(input.repos.len(), 1);
    assert_eq!(input.repos[0].branch, "dev");
    assert_eq!(input.repos[0].mount_path, "/workspace/r");
    assert_eq!(input.working_directory, "/workspace/r");
    assert_eq!(input.agents, vec!["codex".to_string()]);
    assert_eq!(
        input.app_ports,
        vec![(8080, "api".to_string(), String::new())]
    );
    env.project_spec.repositories[0].source = "git@example.com:org/app.git".into();
    env.project_spec.repositories[0].known_hosts =
        vec!["example.com ssh-ed25519 QUJDRA== public-pin".into()];
    let input = to_setup_inputs(&env, &backend);
    assert_eq!(
        input.repos[0].known_hosts,
        env.project_spec.repositories[0].known_hosts
    );
}

#[test]
fn stale_setup_commands_do_not_run_after_delete() {
    assert!(setup_command_cancelled("pending", "destroyed"));
    assert!(setup_command_cancelled("running", "destroyed"));
    assert!(setup_command_cancelled("destroying", "destroyed"));
    assert!(setup_command_cancelled("destroyed", "destroyed"));
    assert!(setup_command_cancelled("destroying", "started"));
    assert!(!setup_command_cancelled("running", "started"));
}

#[test]
fn removed_agent_env_is_rejected() {
    assert!(
        serde_json::from_str::<codewire_project::ProjectSpec>(
            r#"{"agent_env":{"CLAUDE_CODE_OAUTH_TOKEN":"synthetic"}}"#,
        )
        .is_err()
    );
}

#[test]
fn resolve_git_field_mirrors_go() {
    assert_eq!(
        resolve_git_field(Some("Git Name"), Some("Acct"), "a@b.c"),
        "Git Name"
    );
    assert_eq!(resolve_git_field(Some(""), Some("Acct"), "a@b.c"), "Acct");
    assert_eq!(resolve_git_field(None, None, "user@b.c"), "user");
    assert_eq!(resolve_git_field(None, None, "@b.c"), "@b.c");
}

#[test]
fn workspace_exec_failure_never_retains_child_output() {
    let marker = "synthetic-secret-output-must-not-persist";
    let result = WorkspaceExecResult {
        stdout: marker.as_bytes().to_vec(),
        stderr: marker.as_bytes().to_vec(),
        exit_code: 23,
    };
    let error = require_workspace_exec_success(&result).unwrap_err();
    assert_eq!(error.to_string(), "workspace exec exited 23");
    assert!(!format!("{error:?}").contains(marker));
}

#[test]
fn only_a_typed_exit_status_matches_exactly() {
    let refused = WorkspaceExecResult {
        exit_code: ssh_checkout::SSH_REFUSED_EXIT,
        ..Default::default()
    };
    let error = require_workspace_exec_success(&refused)
        .unwrap_err()
        .context("git clone https://github.com/org/app.git over SSH");
    assert!(exited_with(&error, ssh_checkout::SSH_REFUSED_EXIT));
    assert!(!exited_with(&error, 128));
    // Text alone, such as a transport error, is never an exit status.
    assert!(!exited_with(
        &anyhow::anyhow!("workspace exec exited 77"),
        ssh_checkout::SSH_REFUSED_EXIT
    ));
}

fn exited(code: i32) -> anyhow::Error {
    require_workspace_exec_success(&WorkspaceExecResult {
        exit_code: code,
        ..Default::default()
    })
    .unwrap_err()
}

#[test]
fn only_a_healthy_defaults_report_names_a_generation() {
    let diagnostic = |name: &str, healthy, message: &str| {
        crate::api::environment_daemon::EnvironmentDaemonDiagnostic {
            name: name.to_owned(),
            healthy,
            message: message.to_owned(),
        }
    };
    let written = codewire_daemon_proto::workspace_defaults_message(7);
    let name = codewire_daemon_proto::WORKSPACE_DEFAULTS_DIAGNOSTIC;
    assert_eq!(
        reported_defaults_generation(&[
            diagnostic("session-store", true, "fine"),
            diagnostic(name, true, &written),
        ]),
        Some(7)
    );
    for refused in [
        vec![],
        vec![diagnostic(name, false, &written)],
        vec![diagnostic(name, false, "project defaults failed")],
        vec![diagnostic(name, true, "something else")],
        vec![diagnostic("session-store", true, &written)],
    ] {
        assert_eq!(reported_defaults_generation(&refused), None, "{refused:?}");
    }
}

#[test]
fn configure_environment_fails_only_for_the_defaults_and_warns_for_the_author() {
    assert!(matches!(
        configure_environment_outcome(Ok(()), true).unwrap(),
        GitIdentityOutcome::Configured
    ));
    assert!(matches!(
        configure_environment_outcome(Ok(()), false).unwrap(),
        GitIdentityOutcome::Unresolved
    ));
    // Only the author's own status, with an author resolved, is a warning.
    assert!(matches!(
        configure_environment_outcome(Err(exited(GIT_IDENTITY_FAILED_EXIT)), true).unwrap(),
        GitIdentityOutcome::Failed(_)
    ));
    for (error, resolved) in [
        (exited(1), true),
        (exited(GIT_IDENTITY_FAILED_EXIT), false),
        (anyhow::anyhow!("workspace exec exited 78"), true),
        (SetupActivityCancelled.into(), true),
        (
            anyhow::Error::new(super::super::activity_authority::AuthorityLost),
            true,
        ),
    ] {
        let message = format!("{error:#}");
        let failed = configure_environment_outcome(Err(error), resolved).unwrap_err();
        assert_eq!(format!("{failed:#}"), message);
    }
}

const GITHUB_HTTPS: &str = "https://github.com/org/app.git";

fn plan_for(repo: Repo, slots: &[&str]) -> ClonePlan {
    let clients = Some(
        codewire_access::ManagedCredentialClients::from_profile_slots(slots.iter().copied())
            .unwrap(),
    );
    let repos = std::slice::from_ref(&repo);
    let ssh = ssh_checkout::commands(repos, clients).unwrap().remove(0);
    let github = github_checkout::commands(repos, clients).unwrap().remove(0);
    clone_plan(
        ssh.as_ref(),
        github.as_ref(),
        plain_clone_command(&repo.url, &repo.mount_path),
        codewire_project::github_ssh_source(&repo.url).is_some(),
    )
}

fn https_repo(url: &str) -> Repo {
    Repo {
        url: url.into(),
        mount_path: "/workspace/app".into(),
        ..Default::default()
    }
}

fn bridge(plan: &[String]) -> bool {
    plan.iter()
        .any(|argument| argument.contains("/_codewire/github/"))
}

#[test]
fn a_selected_ssh_key_is_preferred_and_https_is_its_fallback() {
    let plain = plain_clone_command(GITHUB_HTTPS, "/workspace/app");
    // SSH only: SSH first, then the anonymous HTTPS URL.
    let plan = plan_for(https_repo(GITHUB_HTTPS), &["ssh"]);
    assert_eq!(plan.transport, CloneTransport::Ssh { refused: false });
    assert_eq!(plan.clone[4], "git@github.com:org/app.git");
    assert_eq!(
        plan.https_fallback,
        Some((
            plain.clone(),
            CloneTransport::HttpsAfterSshRefused { github: false }
        ))
    );
    // Both: SSH first, then the GitHub connection.
    let plan = plan_for(https_repo(GITHUB_HTTPS), &["github", "ssh"]);
    assert_eq!(plan.transport, CloneTransport::Ssh { refused: false });
    assert_eq!(plan.clone[4], "git@github.com:org/app.git");
    let (fallback, transport) = plan.https_fallback.unwrap();
    assert!(bridge(&fallback));
    assert_eq!(fallback.last().unwrap(), "/workspace/app");
    assert_eq!(
        transport,
        CloneTransport::HttpsAfterSshRefused { github: true }
    );
    // GitHub only: the bridge, with nothing to fall back to.
    let plan = plan_for(https_repo(GITHUB_HTTPS), &["github"]);
    assert_eq!(plan.transport, CloneTransport::GitHub);
    assert!(bridge(&plan.clone));
    assert_eq!(plan.https_fallback, None);
    // Neither: anonymous, which still clones a public repository.
    let plan = plan_for(https_repo(GITHUB_HTTPS), &[]);
    assert_eq!(plan.transport, CloneTransport::Anonymous { github: true });
    assert_eq!(plan.clone, plain);
    assert_eq!(plan.https_fallback, None);
}

/// A github.com source in SSH form: the key when selected (never falling
/// back), otherwise the GitHub connection's bridge, the origin as written.
#[test]
fn a_github_ssh_source_uses_the_key_first_then_the_github_connection() {
    for source in [
        "git@github.com:org/app.git",
        "ssh://git@github.com/org/app.git",
    ] {
        let repo = Repo {
            url: source.into(),
            mount_path: "/workspace/app".into(),
            known_hosts: codewire_project::GITHUB_SSH_KNOWN_HOSTS
                .map(str::to_owned)
                .to_vec(),
            ..Default::default()
        };
        for slots in [&["ssh"][..], &["github", "ssh"]] {
            let plan = plan_for(repo.clone(), slots);
            assert_eq!(plan.transport, CloneTransport::Ssh { refused: false });
            assert_eq!(plan.clone[4], source);
            assert_eq!(plan.https_fallback, None);
        }
        let plan = plan_for(repo, &["github"]);
        assert_eq!(plan.transport, CloneTransport::GitHub);
        assert!(bridge(&plan.clone));
        assert!(plan.clone.contains(&format!(
            "url.http://127.0.0.1:38081/_codewire/github/org/app.git.insteadOf={source}"
        )));
        assert_eq!(
            &plan.clone[plan.clone.len() - 2..],
            &[source, "/workspace/app"]
        );
        assert_eq!(plan.https_fallback, None);
    }
    // `git://` is served like HTTPS.
    let plan = plan_for(https_repo("git://github.com/org/app.git"), &["github"]);
    assert_eq!(plan.transport, CloneTransport::GitHub);
    assert!(bridge(&plan.clone));
    let plan = plan_for(
        https_repo("git://github.com/org/app.git"),
        &["github", "ssh"],
    );
    assert_eq!(plan.clone[4], "git@github.com:org/app.git");
    assert!(bridge(&plan.https_fallback.unwrap().0));
}

#[test]
fn ssh_and_other_https_sources_never_fall_back() {
    let source = "git@example.com:org/app.git";
    let repo = Repo {
            url: source.into(),
            mount_path: "/workspace/app".into(),
            known_hosts: vec![
                "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx"
                    .into(),
            ],
            ..Default::default()
        };
    let plan = plan_for(repo, &["github", "ssh"]);
    assert_eq!(plan.transport, CloneTransport::Ssh { refused: false });
    assert_eq!(plan.clone[4], source);
    assert_eq!(plan.https_fallback, None);
    let plan = plan_for(https_repo("https://gitlab.com/org/app.git"), &["ssh"]);
    assert_eq!(plan.transport, CloneTransport::Anonymous { github: false });
    assert_eq!(plan.https_fallback, None);
}

#[test]
fn clone_failures_name_the_credential_that_was_used_or_missing() {
    for (transport, expected) in [
        (CloneTransport::Ssh { refused: false }, " over SSH"),
        (
            CloneTransport::Ssh { refused: true },
            " over SSH: the server did not accept the SSH key in the Sandbox's credential profile",
        ),
        (CloneTransport::GitHub, " through the GitHub connection"),
        (
            CloneTransport::HttpsAfterSshRefused { github: true },
            " through the GitHub connection after GitHub did not accept the SSH key",
        ),
        (
            CloneTransport::HttpsAfterSshRefused { github: false },
            " over HTTPS after GitHub did not accept the SSH key; no GitHub connection is selected",
        ),
        (
            CloneTransport::Anonymous { github: true },
            " (no SSH key or GitHub connection is selected; a private repository needs one)",
        ),
        (CloneTransport::Anonymous { github: false }, ""),
    ] {
        assert_eq!(
            clone_failure_context(GITHUB_HTTPS, transport),
            format!("git clone {GITHUB_HTTPS}{expected}")
        );
    }
}

fn current_replacement_probe() -> RuntimeProbe {
    RuntimeProbe {
        claim_exists: true,
        claim_ready: true,
        replicas: 1,
        pod_exists: true,
        pod_phase: "Running".into(),
        pod_name: "workspace-current".into(),
        pod_uid: "uid-new".into(),
        pod_ip: "10.0.0.9".into(),
        ..Default::default()
    }
}

#[test]
fn replacement_runtime_requires_exact_ready_incarnation() {
    let current = current_replacement_probe();
    assert!(replacement_runtime_is_current(
        "workspace-current",
        "uid-old",
        &current
    ));

    let mut cases = Vec::new();
    let mut probe = current.clone();
    probe.claim_exists = false;
    cases.push(probe);
    let mut probe = current.clone();
    probe.claim_ready = false;
    cases.push(probe);
    let mut probe = current.clone();
    probe.replicas = 0;
    cases.push(probe);
    let mut probe = current.clone();
    probe.pod_exists = false;
    cases.push(probe);
    let mut probe = current.clone();
    probe.pod_phase = "Pending".into();
    cases.push(probe);
    let mut probe = current.clone();
    probe.pod_name = "workspace-other".into();
    cases.push(probe);
    let mut probe = current.clone();
    probe.pod_uid.clear();
    cases.push(probe);
    let mut probe = current.clone();
    probe.pod_uid = "uid-old".into();
    cases.push(probe);
    let mut probe = current;
    probe.pod_ip.clear();
    cases.push(probe);

    for probe in cases {
        assert!(!replacement_runtime_is_current(
            "workspace-current",
            "uid-old",
            &probe
        ));
    }
}

fn running_environment() -> EnvironmentRow {
    EnvironmentRow {
        id: "env-1".into(),
        org_id: "org-1".into(),
        preset_id: None,
        env_type: "sandbox".into(),
        state: "running".into(),
        desired_state: "started".into(),
        isolation_tier: "standard".into(),
        dedicated_cpu: false,
        never_ran: false,
        external_cleanup_completed_at: None,
        cpu_millicores: 2000,
        memory_mb: 4096,
        disk_gb: 80,
        source_snapshot_id: None,
        ttl_seconds: Some(1800),
        project_spec: codewire_project::ProjectSpec::default(),
        operation_generation: 7,
        projection_selection: Ok(None),
        managed_credential_clients: Ok(Default::default()),
    }
}

/// #3684: setup in the create activity skips its final reconcile only
/// when the runtime after setup is exactly the one create reconciled, and
/// the backend still names its Pod as bound. Every change since then, and
/// every setup that has no such runtime or could not read one, reconciles.
#[test]
fn the_final_reconcile_is_skipped_only_for_the_runtime_create_reconciled() {
    let env = running_environment();
    let backend = BackendRow {
        namespace: "ns".into(),
        claim_name: "sandbox-env-1".into(),
        claim_uid: "claim-1".into(),
        pod_uid: Some("pod-1".into()),
        ..Default::default()
    };
    let probe = RuntimeProbe {
        pod_name: "cw-pool-member".into(),
        pod_uid: "pod-1".into(),
        pod_ip: "10.0.0.1".into(),
        ..Default::default()
    };
    let confirmed = ReconciledRuntime::observe(&env, &backend, &probe);
    assert!(!final_reconcile_needed(
        Some(&confirmed),
        &env,
        &backend,
        Some(&probe)
    ));
    assert!(final_reconcile_needed(None, &env, &backend, Some(&probe)));
    assert!(final_reconcile_needed(
        Some(&confirmed),
        &env,
        &backend,
        None
    ));

    let mut republished = env.clone();
    republished.projection_selection = Ok(Some(codewire_project::PlatformProjectionSelection {
        creator: "usr-1".into(),
        organization: "org-1".into(),
        organization_selected: true,
        project_id: None,
        user_selected: false,
        profile: None,
        ordinary_keys: ["API_URL".to_string()].into(),
        reserved_keys: Default::default(),
    }));
    let mut regenerated = env.clone();
    regenerated.operation_generation = 8;
    let mut failed = env.clone();
    failed.state = "error".into();
    for (case, changed) in [
        ("a republished projection selection", republished),
        ("a new generation", regenerated),
        ("another state", failed),
    ] {
        assert!(
            final_reconcile_needed(Some(&confirmed), &changed, &backend, Some(&probe)),
            "{case}"
        );
    }

    let released = BackendRow {
        pod_uid: None,
        ..backend.clone()
    };
    let reclaimed = BackendRow {
        claim_uid: "claim-2".into(),
        ..backend.clone()
    };
    for (case, changed) in [
        ("a released binding", released),
        ("another Claim", reclaimed),
    ] {
        assert!(
            final_reconcile_needed(Some(&confirmed), &env, &changed, Some(&probe)),
            "{case}"
        );
    }

    let replaced = RuntimeProbe {
        pod_uid: "pod-2".into(),
        ..probe.clone()
    };
    let readdressed = RuntimeProbe {
        pod_ip: "10.0.0.2".into(),
        ..probe.clone()
    };
    for (case, changed) in [
        ("a replaced Pod", replaced),
        ("a new Pod address", readdressed),
    ] {
        assert!(
            final_reconcile_needed(Some(&confirmed), &env, &backend, Some(&changed)),
            "{case}"
        );
    }
}

#[test]
fn a_setup_command_carries_only_the_projects_ordinary_environment() {
    let spec = codewire_project::ProjectSpec {
        environment: BTreeMap::from([("APP_MODE".into(), "test".into())]),
        secrets: codewire_project::SecretBindings {
            project: "project-store".into(),
            organization: true,
            user: None,
        },
        ..Default::default()
    };
    assert_eq!(setup_exec_env(&spec), spec.environment);
}
