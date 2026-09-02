fn main() {
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
    let isolated_process =
        network_worker || egress_broker || mesh_transport || mesh_enrollment_broker;
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
            } else {
                codewire_cli::native_mesh_enrollment_broker_exit_code(&err)
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
