#[cfg(target_os = "linux")]
mod local_mesh_helper;

fn main() {
    #[cfg(target_os = "linux")]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "__platform-cw-runtime")
    {
        std::process::exit(codewire_cli::run_platform_cw_runtime_from(
            std::env::args_os(),
        ));
    }
    #[cfg(target_os = "linux")]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "__host-agent-control")
    {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
        else {
            eprintln!("host agent control failed");
            std::process::exit(1);
        };
        if runtime
            .block_on(codewire_cli::run_host_agent_control_from(
                std::env::args_os().skip(2).collect(),
            ))
            .is_err()
        {
            eprintln!("host agent control failed");
            std::process::exit(1);
        }
        return;
    }
    // Helper roles must not resolve ordinary CLI settings, credentials or the
    // mutable managed entry. The parent already selected this exact executable.
    #[cfg(target_os = "linux")]
    if let Some(role) = std::env::args_os().nth(1)
        && local_mesh_helper::is_role(&role)
    {
        if let Err(error) = local_mesh_helper::run(&role) {
            eprintln!("local Mesh helper failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(target_os = "linux")]
    if std::env::args_os()
        .next()
        .as_deref()
        .is_some_and(codewire_cli::is_local_git_ssh_helper)
    {
        if codewire_cli::run_local_git_ssh_helper(std::env::args_os().skip(1).collect()).is_err() {
            eprintln!("repository SSH failed");
            std::process::exit(1);
        }
        return;
    }
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "__hosted-exec")
    {
        std::process::exit(codewire_cli::run_hosted_exec_from(std::env::args_os()));
    }
    #[cfg(target_os = "linux")]
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "__environment-launch")
    {
        if codewire_cli::run_environment_launcher_from(std::env::args_os()).is_err() {
            eprintln!("environment launch failed");
            std::process::exit(1);
        }
        return;
    }
    let network_worker = std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "__native-network-worker");
    let egress_broker = std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "__native-egress-broker");
    let mesh_transport = std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "__native-mesh-transport");
    let mesh_enrollment_broker = std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "__native-mesh-enrollment-broker");
    #[cfg(target_os = "linux")]
    let broker = std::env::args_os().nth(1).is_some_and(|argument| {
        matches!(
            argument.to_str(),
            Some(
                "__local-credential-broker"
                    | "__local-credential-broker-confinement-probe"
                    | "__local-git-repository-executor"
                    | "__local-git-credential-helper"
            )
        )
    });
    #[cfg(not(target_os = "linux"))]
    let broker = false;

    #[cfg(target_os = "linux")]
    if broker && codewire_cli::prepare_local_credential_broker_process().is_err() {
        eprintln!("prepare local credential broker process failed");
        std::process::exit(1);
    }

    let isolated_process =
        network_worker || egress_broker || mesh_transport || mesh_enrollment_broker || broker;
    let mut runtime = if isolated_process {
        tokio::runtime::Builder::new_current_thread()
    } else {
        tokio::runtime::Builder::new_multi_thread()
    };
    if isolated_process {
        runtime.enable_io().enable_time();
    } else {
        runtime.enable_all();
    }
    let runtime = runtime.build().unwrap_or_else(|error| {
        eprintln!("failed to initialize async runtime: {error}");
        std::process::exit(1);
    });
    if let Err(err) = runtime.block_on(codewire_cli::run()) {
        if isolated_process {
            #[cfg(target_os = "linux")]
            let exit_code = if network_worker {
                codewire_cli::native_network_worker_exit_code(&err)
            } else if egress_broker {
                codewire_cli::native_egress_broker_exit_code(&err)
            } else if mesh_transport {
                codewire_cli::native_mesh_transport_exit_code(&err)
            } else if mesh_enrollment_broker {
                codewire_cli::native_mesh_enrollment_broker_exit_code(&err)
            } else {
                None
            }
            .unwrap_or(1);
            #[cfg(not(target_os = "linux"))]
            let exit_code = 1;
            std::process::exit(exit_code);
        }
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}
