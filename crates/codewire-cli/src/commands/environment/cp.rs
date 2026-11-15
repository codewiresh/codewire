//! The entry of `cw cp`, moved from the parent module with no change in
//! behaviour.

use super::*;

pub(super) async fn handle_unified_environment_cp(
    globals: &Globals,
    placement: Option<EnvironmentPlacement>,
    args: EnvCpArgs,
) -> anyhow::Result<()> {
    let (src_remote, dst_remote) = env_cp_remote_paths(&args.src, &args.dst)?;
    let target_ref = src_remote
        .or(dst_remote)
        .map(|(environment, _)| environment)
        .expect("validated copy direction has one remote environment");
    let target = resolve_unified_environment_target(globals, placement, target_ref, "cp").await?;
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
