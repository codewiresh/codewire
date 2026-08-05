//! Docker and Lima backend construction, host context, and mount preparation.

use super::*;

pub(crate) fn create_local_runtime(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
) -> anyhow::Result<()> {
    match trimmed_required(&instance.backend, "local backend")? {
        "docker" => create_local_docker_instance(instance),
        "lima" => create_local_lima_instance(instance, data_dir),
        other => anyhow::bail!("unsupported local backend {other:?}"),
    }
}

pub(crate) fn create_local_docker_instance(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<()> {
    let context = LocalDockerHostContext::detect();
    let create = local_docker_create_command_spec(instance, &context)?;
    run_local_command_combined(&create)
        .with_context(|| format!("docker {}", display_local_runtime_args(&create.args)))?;

    if let Err(err) = install_local_docker_daemon_before_start(instance) {
        let cleanup = LocalRuntimeCommand {
            program: "docker".to_string(),
            args: vec![
                "rm".to_string(),
                "-f".to_string(),
                local_runtime_name(instance)?.to_string(),
            ],
        };
        let _ = run_local_command_combined(&cleanup);
        return Err(err);
    }

    let start = LocalRuntimeCommand {
        program: "docker".to_string(),
        args: vec![
            "start".to_string(),
            local_runtime_name(instance)?.to_string(),
        ],
    };
    if let Err(err) = run_local_command_combined(&start)
        .with_context(|| format!("docker {}", start.args.join(" ")))
    {
        let cleanup = LocalRuntimeCommand {
            program: "docker".to_string(),
            args: vec![
                "rm".to_string(),
                "-f".to_string(),
                local_runtime_name(instance)?.to_string(),
            ],
        };
        let _ = run_local_command_combined(&cleanup);
        return Err(err);
    }
    Ok(())
}

#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct LocalDockerHostContext {
    pub(crate) claude_dir: Option<PathBuf>,
    pub(crate) claude_json: Option<PathBuf>,
    pub(crate) gh_config_dir: Option<PathBuf>,
    pub(crate) git_config_path: Option<PathBuf>,
    pub(crate) ssh_auth_sock: Option<PathBuf>,
    pub(crate) ssh_dir: Option<PathBuf>,
    pub(crate) codex_dir: Option<PathBuf>,
    pub(crate) github_token: Option<String>,
    pub(crate) claude_oauth_token: Option<String>,
    pub(crate) anthropic_api_key: Option<String>,
}

impl std::fmt::Debug for LocalDockerHostContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalDockerHostContext")
            .field("claude_dir", &self.claude_dir)
            .field("claude_json", &self.claude_json)
            .field("gh_config_dir", &self.gh_config_dir)
            .field("git_config_path", &self.git_config_path)
            .field("ssh_auth_sock", &self.ssh_auth_sock)
            .field("ssh_dir", &self.ssh_dir)
            .field("codex_dir", &self.codex_dir)
            .field(
                "github_token",
                &self.github_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "claude_oauth_token",
                &self.claude_oauth_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "anthropic_api_key",
                &self.anthropic_api_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl LocalDockerHostContext {
    pub(crate) fn detect() -> Self {
        let home = env::var_os("HOME").map(PathBuf::from);
        let path_if_exists = |path: PathBuf| path.exists().then_some(path);
        Self {
            claude_dir: home
                .as_ref()
                .and_then(|home| path_if_exists(home.join(".claude"))),
            claude_json: home
                .as_ref()
                .and_then(|home| path_if_exists(home.join(".claude.json"))),
            gh_config_dir: home
                .as_ref()
                .and_then(|home| path_if_exists(home.join(".config").join("gh"))),
            git_config_path: detect_local_git_config_path(),
            ssh_auth_sock: detect_local_ssh_auth_sock(),
            ssh_dir: home
                .as_ref()
                .and_then(|home| path_if_exists(home.join(".ssh"))),
            codex_dir: home
                .as_ref()
                .and_then(|home| path_if_exists(home.join(".codex"))),
            github_token: detect_local_github_token(),
            claude_oauth_token: detect_local_claude_oauth_token(),
            anthropic_api_key: env::var("ANTHROPIC_API_KEY")
                .ok()
                .and_then(non_empty_string),
        }
    }
}

#[derive(Debug, serde::Serialize, PartialEq, Eq)]
pub(crate) struct LimaVmMount {
    pub(crate) location: String,
    #[serde(rename = "mountPoint")]
    pub(crate) mount_point: String,
    pub(crate) writable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LimaContainerMount {
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) read_only: bool,
}

pub(crate) fn create_local_lima_instance(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let context = LocalDockerHostContext::detect();
    ensure_lima_git_config(instance, data_dir, &context)?;

    let name = local_lima_instance_name(instance)?;
    let mut cleanup_vm = false;
    let result = (|| -> anyhow::Result<()> {
        match local_lima_instance_status(name)? {
            status if status == "missing" => {
                cleanup_vm = true;
                let create = local_lima_create_command_spec(instance, data_dir, &context)?;
                eprintln!("  Creating Lima VM {name:?}...");
                run_local_command_combined(&create)
                    .with_context(|| format!("limactl {}", create.args.join(" ")))?;
            }
            status if status != "running" => {
                let start = LocalRuntimeCommand {
                    program: "limactl".to_string(),
                    args: vec![
                        "start".to_string(),
                        "--tty=false".to_string(),
                        name.to_string(),
                    ],
                };
                eprintln!("  Starting Lima VM {name:?}...");
                run_local_command_combined(&start)
                    .with_context(|| format!("limactl {}", start.args.join(" ")))?;
            }
            _ => {
                eprintln!("  Reusing existing Lima VM {name:?}...");
            }
        }

        let _ = run_local_command_combined(&LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                name.to_string(),
                "sudo".to_string(),
                "systemctl".to_string(),
                "start".to_string(),
                "docker".to_string(),
            ],
        });

        eprintln!("  Waiting for Docker inside VM...");
        let docker_info = LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                name.to_string(),
                "sudo".to_string(),
                "docker".to_string(),
                "info".to_string(),
            ],
        };
        run_local_command_combined(&docker_info).context("docker not ready inside Lima VM")?;

        if let Some(token) = context.github_token.as_deref().and_then(trimmed_str) {
            let _ = run_local_command_with_stdin(
                &LocalRuntimeCommand {
                    program: "limactl".to_string(),
                    args: vec![
                        "shell".to_string(),
                        "--workdir".to_string(),
                        "/".to_string(),
                        name.to_string(),
                        "sudo".to_string(),
                        "docker".to_string(),
                        "login".to_string(),
                        "ghcr.io".to_string(),
                        "-u".to_string(),
                        "oauth2".to_string(),
                        "--password-stdin".to_string(),
                    ],
                },
                token,
            );
        }

        let image = trimmed_required(&instance.image, "local image")?;
        eprintln!("  Pulling {image}...");
        let pull = LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "shell".to_string(),
                "--workdir".to_string(),
                "/".to_string(),
                name.to_string(),
                "sudo".to_string(),
                "docker".to_string(),
                "pull".to_string(),
                image.to_string(),
            ],
        };
        run_local_command_combined(&pull).with_context(|| format!("docker pull {image}"))?;

        let status = lima_workspace_container_status(name)?;
        let docker_sock_gid = lima_docker_socket_gid(name)?;
        stage_lima_runtime_cli(name)?;
        eprintln!("  Starting workspace container...");
        match status.as_str() {
            "missing" => {
                let run = local_lima_workspace_run_command_spec(
                    instance,
                    data_dir,
                    &context,
                    &docker_sock_gid,
                )?;
                run_local_command_combined(&run).context("docker run")?;
            }
            "running" => {}
            _ => {
                let start = LocalRuntimeCommand {
                    program: "limactl".to_string(),
                    args: vec![
                        "shell".to_string(),
                        "--workdir".to_string(),
                        "/".to_string(),
                        name.to_string(),
                        "sudo".to_string(),
                        "docker".to_string(),
                        "start".to_string(),
                        LIMA_CONTAINER_NAME.to_string(),
                    ],
                };
                run_local_command_combined(&start)
                    .with_context(|| format!("docker start {LIMA_CONTAINER_NAME}"))?;
            }
        }

        ensure_lima_docker_socket_group(name, &docker_sock_gid)?;
        bootstrap_lima_claude_json(instance)?;
        cleanup_vm = false;
        Ok(())
    })();

    if result.is_err() && cleanup_vm {
        let _ = run_local_command_combined(&LocalRuntimeCommand {
            program: "limactl".to_string(),
            args: vec![
                "delete".to_string(),
                "--force".to_string(),
                name.to_string(),
            ],
        });
    }
    result
}

pub(crate) fn ensure_lima_git_config(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
    context: &LocalDockerHostContext,
) -> anyhow::Result<()> {
    let Some(source) = context.git_config_path.as_ref() else {
        return Ok(());
    };
    let target_dir = local_lima_git_state_dir(instance, data_dir);
    fs::create_dir_all(&target_dir).context("create Lima git state dir")?;
    let target = target_dir.join(".gitconfig");
    if target.exists() {
        return Ok(());
    }
    fs::copy(source, &target).context("seed Lima git config")?;
    Ok(())
}

pub(crate) fn local_lima_state_dir(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
) -> PathBuf {
    let name = trimmed_str(&instance.lima_instance_name)
        .or_else(|| trimmed_str(&instance.runtime_name))
        .or_else(|| trimmed_str(&instance.name))
        .unwrap_or("default");
    data_dir.join("lima").join(name)
}

pub(crate) fn local_lima_git_state_dir(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
) -> PathBuf {
    local_lima_state_dir(instance, data_dir).join("git")
}

pub(crate) fn local_lima_create_command_spec(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
    context: &LocalDockerHostContext,
) -> anyhow::Result<LocalRuntimeCommand> {
    let vm_type = trimmed_str(&instance.lima_vm_type)
        .unwrap_or(default_lima_vm_type())
        .to_string();
    let mount_type = trimmed_str(&instance.lima_mount_type)
        .map(str::to_string)
        .unwrap_or_else(|| default_lima_mount_type(&vm_type).to_string());
    let mounts = serde_json::to_string(&lima_vm_mounts(instance, data_dir, context)?)?;
    let mut args = vec![
        "start".to_string(),
        "--tty=false".to_string(),
        "--name".to_string(),
        local_lima_instance_name(instance)?.to_string(),
        "--vm-type".to_string(),
        vm_type,
        "--mount-type".to_string(),
        mount_type,
        "--mount-none".to_string(),
        "--set".to_string(),
        format!(".mounts={mounts}"),
    ];
    if let Some(set_expr) = lima_ssh_agent_forward_set_expr(context)? {
        args.push("--set".to_string());
        args.push(set_expr);
    }
    args.push("--set".to_string());
    args.push(lima_daemon_forward_set_expr(instance)?);
    if instance.cpu > 0 {
        args.push("--cpus".to_string());
        args.push(lima_cpus_from_millicores(instance.cpu).to_string());
    }
    if instance.memory > 0 {
        args.push("--memory".to_string());
        args.push(lima_memory_gib_from_mb(instance.memory).to_string());
    }
    if instance.disk > 0 {
        args.push("--disk".to_string());
        args.push(instance.disk.to_string());
    }
    for port in &instance.ports {
        let host_port = port.effective_host_port();
        let guest_port = port.effective_guest_port();
        if host_port > 0 && guest_port > 0 {
            args.push("--port-forward".to_string());
            args.push(format!("{host_port}:{guest_port},static=true"));
        }
    }
    args.push("template:docker".to_string());

    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args,
    })
}

pub(crate) fn lima_daemon_forward_set_expr(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<String> {
    #[derive(serde::Serialize)]
    struct DaemonForward {
        #[serde(rename = "guestPort")]
        guest_port: u16,
        #[serde(rename = "hostPort")]
        host_port: u16,
        #[serde(rename = "guestIP")]
        guest_ip: &'static str,
        #[serde(rename = "hostIP")]
        host_ip: &'static str,
        proto: &'static str,
        r#static: bool,
    }

    let payload = serde_json::to_string(&[DaemonForward {
        guest_port: LOCAL_DAEMON_RUNTIME_PORT,
        host_port: local_daemon_host_port(instance)?,
        guest_ip: "127.0.0.1",
        host_ip: "127.0.0.1",
        proto: "tcp",
        r#static: true,
    }])?;
    Ok(format!(
        ".portForwards = ((.portForwards // []) | map(select(.guestPort != {LOCAL_DAEMON_RUNTIME_PORT})) + {payload})"
    ))
}

pub(crate) fn local_lima_workspace_run_command_spec(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
    context: &LocalDockerHostContext,
    docker_sock_gid: &str,
) -> anyhow::Result<LocalRuntimeCommand> {
    let name = local_lima_instance_name(instance)?;
    let repo_mount = lima_repo_mount_path(instance)?;
    let daemon_auth_token = local_daemon_auth_token(instance)?;
    let mut docker_args = vec![
        "sudo".to_string(),
        "docker".to_string(),
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        LIMA_CONTAINER_NAME.to_string(),
        "--restart".to_string(),
        "unless-stopped".to_string(),
        "--network".to_string(),
        "host".to_string(),
    ];
    if let Some(gid) = trimmed_str(docker_sock_gid) {
        docker_args.push("--group-add".to_string());
        docker_args.push(gid.to_string());
    }
    docker_args.extend([
        "--entrypoint".to_string(),
        "/bin/sh".to_string(),
        "-e".to_string(),
        format!("DOCKER_HOST={LIMA_DOCKER_HOST_VALUE}"),
        "-v".to_string(),
        format!("{LIMA_DOCKER_SOCK_PATH}:{LIMA_DOCKER_SOCK_PATH}"),
        "-v".to_string(),
        format!("{repo_mount}:{repo_mount}"),
        "-v".to_string(),
        format!("{LIMA_RUNTIME_CLI_STAGE_PATH}:{LOCAL_RUNTIME_CLI_PATH}:ro"),
        "-e".to_string(),
        format!("{SHIM_ADDR_ENV}=127.0.0.1:{LOCAL_DAEMON_RUNTIME_PORT}"),
        "-e".to_string(),
        format!("{DAEMON_AUTH_TOKEN_ENV}={daemon_auth_token}"),
    ]);
    if let Some(token) = context.github_token.as_deref().and_then(trimmed_str) {
        docker_args.push("-e".to_string());
        docker_args.push(format!("GH_TOKEN={token}"));
    }
    if context.ssh_auth_sock.is_some() {
        docker_args.push("-e".to_string());
        docker_args.push(format!("SSH_AUTH_SOCK={LOCAL_SSH_AUTH_SOCK_PATH}"));
    }
    if let Some(api_key) = context.anthropic_api_key.as_deref().and_then(trimmed_str) {
        docker_args.push("-e".to_string());
        docker_args.push(format!("ANTHROPIC_API_KEY={api_key}"));
    }
    if let Some(token) = context.claude_oauth_token.as_deref().and_then(trimmed_str) {
        docker_args.push("-e".to_string());
        docker_args.push(format!("CLAUDE_CODE_OAUTH_TOKEN={token}"));
    }
    for mount in lima_container_mounts(instance, data_dir, context)? {
        docker_args.push("-v".to_string());
        let mut spec = format!("{}:{}", mount.source, mount.target);
        if mount.read_only {
            spec.push_str(":ro");
        }
        docker_args.push(spec);
    }
    docker_args.extend([
        "--workdir".to_string(),
        repo_mount,
        trimmed_required(&instance.image, "local image")?.to_string(),
        "-lc".to_string(),
        format!("exec {LOCAL_RUNTIME_CLI_PATH} daemon"),
    ]);

    let mut args = vec![
        "shell".to_string(),
        "--workdir".to_string(),
        "/".to_string(),
        name.to_string(),
    ];
    args.extend(docker_args);
    Ok(LocalRuntimeCommand {
        program: "limactl".to_string(),
        args,
    })
}

pub(crate) fn lima_vm_mounts(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
    context: &LocalDockerHostContext,
) -> anyhow::Result<Vec<LimaVmMount>> {
    let mut mounts = vec![LimaVmMount {
        location: lima_repo_mount_path(instance)?,
        mount_point: lima_repo_mount_path(instance)?,
        writable: true,
    }];
    if let Some(path) = &context.gh_config_dir {
        mounts.push(LimaVmMount {
            location: path.display().to_string(),
            mount_point: "/home/{{.User}}.guest/.config/gh".to_string(),
            writable: true,
        });
    }
    let git_dir = local_lima_git_state_dir(instance, data_dir);
    if git_dir.join(".gitconfig").exists() {
        mounts.push(LimaVmMount {
            location: git_dir.display().to_string(),
            mount_point: "/home/{{.User}}.guest/.codewire-git".to_string(),
            writable: false,
        });
    }
    if let Some(path) = &context.ssh_dir {
        mounts.push(LimaVmMount {
            location: path.display().to_string(),
            mount_point: "/mnt/host-ssh".to_string(),
            writable: false,
        });
    }
    if let Some(path) = &context.codex_dir {
        mounts.push(LimaVmMount {
            location: path.display().to_string(),
            mount_point: "/home/{{.User}}.guest/.codex".to_string(),
            writable: true,
        });
    }
    for mount in &instance.mounts {
        if let Some(source) = trimmed_str(&mount.source) {
            mounts.push(LimaVmMount {
                location: source.to_string(),
                mount_point: local_mount_target(mount).to_string(),
                writable: !mount.readonly.unwrap_or(false),
            });
        }
    }
    Ok(mounts)
}

pub(crate) fn lima_container_mounts(
    instance: &config::LocalInstanceConfig,
    data_dir: &Path,
    context: &LocalDockerHostContext,
) -> anyhow::Result<Vec<LimaContainerMount>> {
    let vm_user = env::var("USER").unwrap_or_default();
    let vm_home = format!("/home/{vm_user}.guest");
    let mut mounts = Vec::new();
    if context.ssh_auth_sock.is_some() {
        mounts.push(LimaContainerMount {
            source: LOCAL_SSH_AUTH_SOCK_PATH.to_string(),
            target: LOCAL_SSH_AUTH_SOCK_PATH.to_string(),
            read_only: false,
        });
    }
    if local_lima_git_state_dir(instance, data_dir)
        .join(".gitconfig")
        .exists()
    {
        mounts.push(LimaContainerMount {
            source: format!("{vm_home}/.codewire-git/.gitconfig"),
            target: "/home/codewire/.gitconfig".to_string(),
            read_only: true,
        });
    }
    if context.gh_config_dir.is_some() {
        mounts.push(LimaContainerMount {
            source: format!("{vm_home}/.config/gh"),
            target: "/home/codewire/.config/gh".to_string(),
            read_only: false,
        });
    }
    if context.ssh_dir.is_some() {
        mounts.push(LimaContainerMount {
            source: "/mnt/host-ssh".to_string(),
            target: "/home/codewire/.ssh".to_string(),
            read_only: true,
        });
    }
    if context.codex_dir.is_some() {
        mounts.push(LimaContainerMount {
            source: format!("{vm_home}/.codex"),
            target: "/home/codewire/.codex".to_string(),
            read_only: false,
        });
    }
    for mount in &instance.mounts {
        if let Some(source) = trimmed_str(&mount.source) {
            mounts.push(LimaContainerMount {
                source: source.to_string(),
                target: local_mount_target(mount).to_string(),
                read_only: mount.readonly.unwrap_or(false),
            });
        }
    }
    Ok(mounts)
}

pub(crate) fn local_mount_target(mount: &config::LocalMountConfig) -> &str {
    trimmed_str(&mount.target).unwrap_or_else(|| mount.source.trim())
}

pub(crate) fn lima_repo_mount_path(
    instance: &config::LocalInstanceConfig,
) -> anyhow::Result<String> {
    trimmed_str(&instance.repo_path)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("repo path is empty"))
}

pub(crate) fn lima_ssh_agent_forward_set_expr(
    context: &LocalDockerHostContext,
) -> anyhow::Result<Option<String>> {
    let Some(host_socket) = context.ssh_auth_sock.as_ref() else {
        return Ok(None);
    };
    #[derive(serde::Serialize)]
    struct Forward<'a> {
        #[serde(rename = "guestSocket")]
        guest_socket: &'a str,
        #[serde(rename = "hostSocket")]
        host_socket: String,
    }
    let payload = serde_json::to_string(&[Forward {
        guest_socket: LOCAL_SSH_AUTH_SOCK_PATH,
        host_socket: host_socket.display().to_string(),
    }])?;
    Ok(Some(format!(
        ".portForwards = ((.portForwards // []) | map(select(.guestSocket != {:?})) + {payload})",
        LOCAL_SSH_AUTH_SOCK_PATH
    )))
}

pub(crate) fn local_docker_create_command_spec(
    instance: &config::LocalInstanceConfig,
    context: &LocalDockerHostContext,
) -> anyhow::Result<LocalRuntimeCommand> {
    let runtime = local_runtime_name(instance)?;
    let daemon_host_port = local_daemon_host_port(instance)?;
    let daemon_auth_token = local_daemon_auth_token(instance)?;
    let mut args = vec![
        "create".to_string(),
        "--name".to_string(),
        runtime.to_string(),
        "--restart".to_string(),
        "unless-stopped".to_string(),
        "--hostname".to_string(),
        runtime.to_string(),
        "--add-host".to_string(),
        "host.docker.internal:host-gateway".to_string(),
        "--publish".to_string(),
        format!("127.0.0.1:{daemon_host_port}:{LOCAL_DAEMON_RUNTIME_PORT}/tcp"),
        "--entrypoint".to_string(),
        "/bin/sh".to_string(),
        "--workdir".to_string(),
        LOCAL_WORKSPACE_PATH.to_string(),
        "--volume".to_string(),
        format!(
            "{}:{LOCAL_WORKSPACE_PATH}",
            trimmed_required(&instance.repo_path, "repo path")?
        ),
    ];

    push_volume(
        &mut args,
        context.claude_dir.as_ref(),
        "/home/codewire/.claude",
    );
    push_volume(
        &mut args,
        context.claude_json.as_ref(),
        "/home/codewire/.claude.json",
    );
    push_volume(
        &mut args,
        context.gh_config_dir.as_ref(),
        "/home/codewire/.config/gh",
    );
    push_volume(
        &mut args,
        context.git_config_path.as_ref(),
        "/home/codewire/.gitconfig:ro",
    );
    push_volume(
        &mut args,
        context.ssh_auth_sock.as_ref(),
        LOCAL_SSH_AUTH_SOCK_PATH,
    );
    push_volume(
        &mut args,
        context.ssh_dir.as_ref(),
        "/home/codewire/.ssh:ro",
    );
    push_volume(
        &mut args,
        context.codex_dir.as_ref(),
        "/home/codewire/.codex",
    );

    if instance.cpu > 0 {
        args.push("--cpus".to_string());
        args.push(format_docker_cpus(instance.cpu));
    }
    if instance.memory > 0 {
        args.push("--memory".to_string());
        args.push(format!("{}m", instance.memory));
    }
    if let Some(token) = context.github_token.as_deref().and_then(trimmed_str) {
        args.push("--env".to_string());
        args.push(format!("GH_TOKEN={token}"));
    }
    if context.ssh_auth_sock.is_some() {
        args.push("--env".to_string());
        args.push(format!("SSH_AUTH_SOCK={LOCAL_SSH_AUTH_SOCK_PATH}"));
    }
    if let Some(token) = context.claude_oauth_token.as_deref().and_then(trimmed_str) {
        args.push("--env".to_string());
        args.push(format!("CLAUDE_CODE_OAUTH_TOKEN={token}"));
    }
    if let Some(api_key) = context.anthropic_api_key.as_deref().and_then(trimmed_str) {
        args.push("--env".to_string());
        args.push(format!("ANTHROPIC_API_KEY={api_key}"));
    }
    args.push("--env".to_string());
    args.push(format!(
        "{SHIM_ADDR_ENV}=0.0.0.0:{LOCAL_DAEMON_RUNTIME_PORT}"
    ));
    args.push("--env".to_string());
    args.push(format!("{DAEMON_AUTH_TOKEN_ENV}={daemon_auth_token}"));
    for (key, value) in &instance.env {
        args.push("--env".to_string());
        args.push(format!("{key}={value}"));
    }
    args.push(trimmed_required(&instance.image, "local image")?.to_string());
    args.push("-lc".to_string());
    args.push(format!("exec {LOCAL_RUNTIME_CLI_PATH} daemon"));

    Ok(LocalRuntimeCommand {
        program: "docker".to_string(),
        args,
    })
}
