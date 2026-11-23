//! The entry of `cw cp`. A missing or refused remote path fails in the same
//! words in both placements (docs/dev/CLI-PARITY.md, W4).

use super::*;
use codewire_client::ErrorCode;

pub(super) async fn handle_unified_environment_cp(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: EnvCpArgs,
) -> anyhow::Result<()> {
    let (src_remote, dst_remote) = env_cp_remote_paths(&args.src, &args.dst)?;
    let (direction, environment, path) = match (src_remote, dst_remote) {
        (Some((environment, path)), _) => ("download", environment.to_owned(), path.to_owned()),
        (None, Some((environment, path))) => ("upload", environment.to_owned(), path.to_owned()),
        (None, None) => unreachable!("validated copy direction has one remote environment"),
    };
    let target = resolve_unified_environment_target(globals, placement, &environment, "cp").await?;
    copy(globals, target, args)
        .await
        .map_err(|error| transfer_failed(error, direction, &environment, &path))
}

/// `error` in the user's terms when the remote path is missing or refused:
/// the path as `ENV:PATH`, with no service code. Any other failure is left
/// as it came.
fn transfer_failed(
    error: anyhow::Error,
    direction: &str,
    environment: &str,
    path: &str,
) -> anyhow::Error {
    let remote = format!("{environment}:{path}");
    // A cloud answer keeps the id of the trace it named.
    let trace_id = crate::error_report::trace_id(&error);
    match rpc_code(&error) {
        Some(ErrorCode::NotFound) => {
            crate::reworded::reworded(format!("{direction}: there is no file {remote}"), trace_id)
        }
        Some(ErrorCode::InvalidArgument | ErrorCode::PermissionDenied) => {
            crate::reworded::reworded(
                format!("{direction}: cw can't copy {remote}: the path is invalid or not allowed"),
                trace_id,
            )
        }
        _ => error,
    }
}

/// The service code of the first service error in `error`'s chain, from
/// either placement.
fn rpc_code(error: &anyhow::Error) -> Option<ErrorCode> {
    error.chain().find_map(|cause| {
        if let Some(error) = cause.downcast_ref::<codewire_client::ClientError>() {
            return Some(error.code());
        }
        if let Some(error) = cause.downcast_ref::<connectrpc::ConnectError>() {
            return Some(error.code);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(codewire_local_vmm::public_client::NativePublicClientError::Rpc(error)) =
            cause.downcast_ref::<codewire_local_vmm::public_client::NativePublicClientError>()
        {
            return Some(error.code);
        }
        None
    })
}

async fn copy(
    globals: &Globals,
    target: UnifiedEnvironmentTarget,
    args: EnvCpArgs,
) -> anyhow::Result<()> {
    let (src_remote, dst_remote) = env_cp_remote_paths(&args.src, &args.dst)?;
    let target_ref = src_remote
        .or(dst_remote)
        .map(|(environment, _)| environment)
        .expect("validated copy direction has one remote environment");
    match target {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        UnifiedEnvironmentTarget::NativeLocal(name) => match (src_remote, dst_remote) {
            (None, Some((_environment, remote_path))) => {
                let client = native_environment_data_client(&name).await?;
                let client = &client;
                transfer::upload_from_file(Path::new(&args.src), |chunks| async move {
                    let stored = client
                        .upload_file_stream(remote_path, chunks)
                        .await
                        .context("upload")?;
                    Ok(u64::try_from(stored.size).unwrap_or(0))
                })
                .await?;
                print!(
                    "{}",
                    format_env_cp_upload_text(&args.src, &name, remote_path)
                );
                Ok(())
            }
            (Some((_environment, remote_path)), None) => {
                let responses = native_environment_data_client(&name)
                    .await?
                    .download_file_stream(remote_path.to_owned())
                    .await
                    .context("download")?;
                let written = transfer::download_to_file(Path::new(&args.dst), responses)
                    .await
                    .context("download")?;
                print!(
                    "{}",
                    format_env_cp_download_text(&name, remote_path, &args.dst, written)
                );
                Ok(())
            }
            _ => unreachable!("validated copy direction"),
        },
        UnifiedEnvironmentTarget::Platform(_) => {
            let env = OsEnv;
            let paths = ResolvePaths::from_env(&env)?;
            let platform = resolve_platform(globals, &paths, &env)?;
            let orgs = organization_client(&platform)?.list_orgs().await?;
            let org_id = current_org_id(&platform, &orgs)?;
            let environment_client = EnvironmentClient::new(&platform)?;
            let named = target_ref.to_owned();
            match handle_env_cp_command(&environment_client, &org_id, args).await {
                Err(error) => {
                    Err(crate::commands::explain_not_running(globals, Some(&named), error).await)
                }
                done => done,
            }
        }
    }
}
