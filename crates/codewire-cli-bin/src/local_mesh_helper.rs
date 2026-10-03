//! Linux service roles in the same immutable executable as their controller.
use std::ffi::OsStr;

pub(super) fn is_role(role: &OsStr) -> bool {
    role == "__local-mesh" || role == "__local-derp"
}

pub(super) fn run(role: &OsStr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        if role == "__local-derp" {
            if std::env::args_os().nth(2).is_some() {
                return Err(
                    "DERP helper accepts configuration only through its launch environment".into(),
                );
            }
            codewire_derp::run_from_env().await
        } else {
            let arguments = std::env::args_os()
                .skip(2)
                .map(|argument| argument.into_string().map_err(|_| "invalid Mesh argument"))
                .collect::<Result<Vec<_>, _>>()?;
            let config =
                codewire_mesh::Config::from_sources(arguments, |key| std::env::var(key).ok())?;
            let mut terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            let mut interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
            codewire_mesh::serve(config, async move {
                tokio::select! {
                    _ = terminate.recv() => {},
                    _ = interrupt.recv() => {},
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            })
            .await?;
            Ok(())
        }
    })
}
