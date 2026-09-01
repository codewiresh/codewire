fn main() {
    let network_worker = std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == "__native-network-worker");
    let mut runtime = if network_worker {
        tokio::runtime::Builder::new_current_thread()
    } else {
        tokio::runtime::Builder::new_multi_thread()
    };
    if network_worker {
        runtime.enable_io().enable_time();
    } else {
        runtime.enable_all();
    }
    let runtime = runtime.build().unwrap_or_else(|error| {
        eprintln!("failed to initialize async runtime: {error}");
        std::process::exit(1);
    });
    if let Err(err) = runtime.block_on(codewire_cli::run()) {
        if network_worker {
            #[cfg(target_os = "linux")]
            let exit_code = codewire_cli::native_network_worker_exit_code(&err).unwrap_or(1);
            #[cfg(not(target_os = "linux"))]
            let exit_code = 1;
            std::process::exit(exit_code);
        }
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}
