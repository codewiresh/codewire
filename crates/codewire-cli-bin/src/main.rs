fn main() {
    #[cfg(target_os = "linux")]
    let broker = std::env::args_os().nth(1).is_some_and(|argument| {
        matches!(
            argument.to_str(),
            Some("__local-credential-broker" | "__local-credential-broker-confinement-probe")
        )
    });
    #[cfg(not(target_os = "linux"))]
    let broker = false;

    #[cfg(target_os = "linux")]
    if broker && codewire_cli::prepare_local_credential_broker_process().is_err() {
        eprintln!("prepare local credential broker process failed");
        std::process::exit(1);
    }

    let mut runtime = if broker {
        tokio::runtime::Builder::new_current_thread()
    } else {
        tokio::runtime::Builder::new_multi_thread()
    };
    let runtime = match runtime.enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("initialize Codewire runtime: {error}");
            std::process::exit(1);
        }
    };
    if let Err(err) = runtime.block_on(codewire_cli::run()) {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}
