//! Qualified-host proof for public Exec/File over the owner-only supervisor UDS.
//!
//! The repository-owned native product smoke invokes this exact binary after
//! creating a disposable environment. Failures are deliberately rendered as
//! one fixed message so guest-controlled bytes never reach smoke logs.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("codewire-local-public-data-smoke requires Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    if linux::run().await.is_err() {
        eprintln!("codewire-local-public-data-smoke: ERROR: public data-plane proof failed");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::error::Error;
    use std::io;
    use std::path::PathBuf;

    use codewire_local_vmm::public_client::{NativePublicClientError, NativePublicDataClient};
    use codewire_local_vmm::supervisor::NativeRuntimeConfig;
    use connectrpc::ErrorCode;

    type SmokeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

    struct Args {
        state_root: PathBuf,
        artifact_root: PathBuf,
        artifact_lock: PathBuf,
        cw_bin: PathBuf,
        target: String,
    }

    pub(super) async fn run() -> SmokeResult<()> {
        let args = Args::parse(std::env::args().skip(1))?;
        let client = NativePublicDataClient::connect_or_start(
            &NativeRuntimeConfig {
                root: args.state_root.clone(),
                artifact_root: args.artifact_root,
                artifact_lock: args.artifact_lock,
                mesh_data_dir: args.state_root.join("unused-mesh-auth"),
                platform_config_dir: args.state_root.join("unused-platform-auth"),
                executable: args.cw_bin,
            },
            &args.target,
        )
        .await?;

        let output = client
            .exec(
                vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "printf 'out\\377'; printf 'err\\376' >&2; exit 23".into(),
                ],
                "/workspace",
                BTreeMap::new(),
            )
            .await?;
        require(
            output.exit_code == 23 && output.stdout == b"out\xff" && output.stderr == b"err\xfe",
        )?;

        let payload = (0..(2 * 64 * 1024 + 777))
            .map(|index| ((index * 31 + 17) % 251) as u8)
            .collect::<Vec<_>>();
        let uploaded = client
            .upload_file("/workspace/public-file.bin", &payload)
            .await?;
        require(
            uploaded.path == "/workspace/public-file.bin"
                && uploaded.size == i64::try_from(payload.len())?,
        )?;
        let entry = client
            .list_files("/workspace")
            .await?
            .into_iter()
            .find(|entry| entry.name == "public-file.bin")
            .ok_or_else(failed)?;
        require(
            entry.size == i64::try_from(payload.len())?
                && !entry.is_dir
                && entry.mode & 0o170000 == 0o100000
                && entry.mod_time.is_set(),
        )?;
        let downloaded = client.download_file("/workspace/public-file.bin").await?;
        require(downloaded.info == entry && downloaded.data == payload)?;

        require_exec_success(
            &client,
            "rm -f /workspace/public-read-link /workspace/public-upload-link; printf outside-sentinel > /tmp/codewire-public-outside; ln -s /tmp/codewire-public-outside /workspace/public-read-link; ln -s /tmp/codewire-public-outside /workspace/public-upload-link",
        )
        .await?;
        match client.download_file("/workspace/public-read-link").await {
            Err(NativePublicClientError::Rpc(error))
                if error.code == ErrorCode::InvalidArgument => {}
            _ => return Err(failed()),
        }
        client
            .upload_file("/workspace/public-upload-link", b"workspace-replacement")
            .await?;
        let output = client
            .exec(
                vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "printf 'outside='; cat /tmp/codewire-public-outside; printf '\\nworkspace='; cat /workspace/public-upload-link"
                        .into(),
                ],
                "/workspace",
                BTreeMap::new(),
            )
            .await?;
        require(
            output.exit_code == 0
                && output.stderr.is_empty()
                && output.stdout == b"outside=outside-sentinel\nworkspace=workspace-replacement",
        )?;

        require_exec_success(
            &client,
            "rm -f /workspace/public-file.bin /workspace/public-read-link /workspace/public-upload-link /tmp/codewire-public-outside",
        )
        .await?;
        println!("codewire-local-public-data-smoke: PASS");
        Ok(())
    }

    async fn require_exec_success(
        client: &NativePublicDataClient,
        command: &str,
    ) -> SmokeResult<()> {
        let output = client
            .exec(
                vec!["/bin/sh".into(), "-c".into(), command.into()],
                "/workspace",
                BTreeMap::new(),
            )
            .await?;
        require(output.exit_code == 0 && output.stderr.is_empty())
    }

    impl Args {
        fn parse(arguments: impl IntoIterator<Item = String>) -> SmokeResult<Self> {
            let mut arguments = arguments.into_iter();
            let mut state_root = None;
            let mut artifact_root = None;
            let mut artifact_lock = None;
            let mut cw_bin = None;
            let mut target = None;
            while let Some(flag) = arguments.next() {
                let value = arguments.next().ok_or_else(failed)?;
                let slot = match flag.as_str() {
                    "--state-root" => &mut state_root,
                    "--artifact-root" => &mut artifact_root,
                    "--artifact-lock" => &mut artifact_lock,
                    "--cw-bin" => &mut cw_bin,
                    "--target" => &mut target,
                    _ => return Err(failed()),
                };
                if slot.replace(value).is_some() {
                    return Err(failed());
                }
            }
            Ok(Self {
                state_root: absolute_path(state_root)?,
                artifact_root: absolute_path(artifact_root)?,
                artifact_lock: absolute_path(artifact_lock)?,
                cw_bin: absolute_path(cw_bin)?,
                target: target
                    .filter(|value| !value.is_empty())
                    .ok_or_else(failed)?,
            })
        }
    }

    fn absolute_path(value: Option<String>) -> SmokeResult<PathBuf> {
        let path = PathBuf::from(value.ok_or_else(failed)?);
        require(path.is_absolute())?;
        Ok(path)
    }

    fn require(condition: bool) -> SmokeResult<()> {
        if condition { Ok(()) } else { Err(failed()) }
    }

    fn failed() -> Box<dyn Error + Send + Sync> {
        Box::new(io::Error::other("public data-plane smoke assertion failed"))
    }
}
