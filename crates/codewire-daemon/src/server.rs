use std::future::Future;
use std::process::Stdio;

use anyhow::{Context, Result};
use axum::Json;
use axum::http::StatusCode;
use axum::routing::get;
use codewire_gateway_proto::daemon::v1::daemon_service_server::DaemonServiceServer;
use serde_json::json;
use tokio::net::TcpListener;
use tonic::service::Routes;

use crate::Config;
use crate::env::default_shell;
use crate::service::{DaemonRuntimeState, DaemonServiceImpl};

pub async fn run<F>(config: Config, shutdown: F) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("listen daemon {}", config.listen_addr))?;
    let local_addr = listener.local_addr().context("read daemon listener addr")?;
    tracing::info!(shim_listen_addr = %local_addr, "workspace daemon listening");

    axum::serve(listener, router(config))
        .with_graceful_shutdown(shutdown)
        .await
        .context("serve workspace daemon")?;
    Ok(())
}

pub fn router(config: Config) -> axum::Router {
    router_with_runtime_state(config, DaemonRuntimeState::ready())
}

pub fn router_with_runtime_state(
    config: Config,
    runtime_state: DaemonRuntimeState,
) -> axum::Router {
    let daemon = DaemonServiceServer::new(DaemonServiceImpl::with_runtime_state(
        config.clone(),
        runtime_state,
    ));
    let grpc = Routes::new(daemon).into_axum_router();

    axum::Router::new()
        .route(
            "/health",
            get({
                let listen_addr = config.listen_addr.clone();
                move || health(listen_addr.clone())
            }),
        )
        .route("/exec-check", get(exec_check))
        .merge(grpc)
}

async fn health(listen_addr: String) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "addr": listen_addr,
    }))
}

async fn exec_check() -> (StatusCode, Json<serde_json::Value>) {
    let shell = default_shell();
    let shell_info = match std::fs::metadata(&shell) {
        Ok(metadata) => json!({
            "path": shell,
            "mode": format!("{:o}", mode(&metadata)),
            "size": metadata.len(),
        }),
        Err(err) => json!({
            "path": shell,
            "stat_error": err.to_string(),
        }),
    };

    let output = tokio::process::Command::new(default_shell())
        .arg("-c")
        .arg("echo ok")
        .stdin(Stdio::null())
        .output()
        .await;

    let mut result = json!({
        "shell": shell_info,
        "pid": std::process::id(),
        "uid": uid(),
        "gid": gid(),
    });

    match output {
        Ok(output) if output.status.success() => {
            result["exec_ok"] = json!(true);
            result["output"] = json!(String::from_utf8_lossy(&output.stdout).trim());
            (StatusCode::OK, Json(result))
        }
        Ok(output) => {
            result["exec_ok"] = json!(false);
            result["error"] = json!(String::from_utf8_lossy(&output.stderr).trim());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(result))
        }
        Err(err) => {
            result["exec_ok"] = json!(false);
            result["error"] = json!(err.to_string());
            (StatusCode::INTERNAL_SERVER_ERROR, Json(result))
        }
    }
}

#[cfg(unix)]
fn mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn mode(_metadata: &std::fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .unwrap_or(0)
}

#[cfg(not(unix))]
fn uid() -> u32 {
    0
}

#[cfg(unix)]
fn gid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.gid())
        .unwrap_or(0)
}

#[cfg(not(unix))]
fn gid() -> u32 {
    0
}
