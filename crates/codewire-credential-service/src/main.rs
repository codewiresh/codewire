use codewire_credential_service::runtime::{
    CredentialServiceConfig, DEFAULT_LOG_FILTER, RuntimeError, harden_process, run,
};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Keep the isolated service independent of shared SESSION_SECRET/DB
    // defaults. Structured diagnostics below contain closed failure classes.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(DEFAULT_LOG_FILTER)),
        )
        .with_current_span(false)
        .init();
    let result = async {
        // Before any configuration, database or provider material: this
        // process is never dumpable and never writes a core file.
        harden_process()?;
        let config = CredentialServiceConfig::from_env()?;
        #[cfg(unix)]
        {
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .map_err(|_| RuntimeError::Signal)?;
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .map_err(|_| RuntimeError::Signal)?;
            run(config, async move {
                tokio::select! {
                    _ = terminate.recv() => Ok(()),
                    _ = interrupt.recv() => Ok(()),
                }
            })
            .await
        }
        #[cfg(not(unix))]
        run(config, async {
            tokio::signal::ctrl_c()
                .await
                .map_err(|_| RuntimeError::Signal)
        })
        .await
    }
    .await;
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(failure = %error, "isolated credential service stopped");
            std::process::ExitCode::FAILURE
        }
    }
}
