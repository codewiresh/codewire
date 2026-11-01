//! Service roles in the same immutable executable as their controller: the
//! local Mesh owner and its DERP child on Linux and macOS (#3797), and the
//! Linux host member.
use std::ffi::OsStr;

pub(super) fn is_role(role: &OsStr) -> bool {
    role == "__local-mesh"
        || role == "__local-derp"
        || cfg!(target_os = "linux") && role == "__host-member"
}

pub(super) fn run(role: &OsStr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // The DERP process is the owner's child and ends with it.
    if role == "__local-derp" {
        codewire_local_vmm::process_peer::exit_with_parent()?;
    }
    // The owner starts its DERP child here, on the main thread and before any
    // runtime thread exists, so the child's parent-death signal follows a
    // thread that lives as long as the owner.
    let owner = if role == "__local-mesh" {
        Some(codewire_cli::LocalMeshOwner::prepare()?)
    } else {
        None
    };
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        #[cfg(target_os = "linux")]
        if role == "__host-member" {
            return codewire_cli::run_host_member_helper_from(
                std::env::args_os().skip(2).collect(),
            )
            .await
            .map_err(Into::into);
        }
        if role == "__local-derp" {
            if std::env::args_os().nth(2).is_some() {
                return Err(
                    "DERP helper accepts configuration only through its launch environment".into(),
                );
            }
            return codewire_derp::run_from_env().await;
        }
        let control = owner
            .as_ref()
            .ok_or("the local Mesh owner was not prepared")?
            .control()?;
        let arguments = std::env::args_os()
            .skip(2)
            .map(|argument| argument.into_string().map_err(|_| "invalid Mesh argument"))
            .collect::<Result<Vec<_>, _>>()?;
        let config = codewire_mesh::Config::from_sources(arguments, |key| std::env::var(key).ok())?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let stopping = std::sync::Arc::new(tokio::sync::Notify::new());
        let stop = stopping.clone();
        let serve = codewire_mesh::serve(config, async move {
            tokio::select! {
                _ = terminate.recv() => {},
                _ = interrupt.recv() => {},
                result = control => {
                    if let Err(error) = result {
                        eprintln!("local Mesh control socket failed: {error}");
                    }
                },
            }
            stop.notify_one();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        });
        // A graceful drain waits for every open connection; bound it.
        tokio::select! {
            result = serve => result?,
            () = async {
                stopping.notified().await;
                tokio::time::sleep(codewire_cli::LocalMeshOwner::DRAIN_GRACE).await;
            } => {}
        }
        Ok(())
    });
    if let Some(owner) = owner {
        owner.finish();
    }
    result
}
