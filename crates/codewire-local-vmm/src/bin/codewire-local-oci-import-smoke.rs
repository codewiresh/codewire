#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("codewire-local-oci-import-smoke requires Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if run().await.is_err() {
        eprintln!("codewire-local-oci-import-smoke: ERROR: synthetic OCI import failed");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
async fn run() -> Result<(), ()> {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use codewire_local_vmm::oci::{SyntheticOciArchiveInput, import_synthetic_oci_archive};

    let mut archive: Option<OsString> = None;
    let mut archive_sha256 = None;
    let mut archive_size = None;
    let mut source_digest = None;
    let mut state_root: Option<OsString> = None;
    let mut arguments = std::env::args_os().skip(1);
    while let Some(flag) = arguments.next() {
        let value = arguments.next().ok_or(())?;
        match flag.to_str() {
            Some("--archive") if archive.is_none() => archive = Some(value),
            Some("--archive-sha256") if archive_sha256.is_none() => {
                archive_sha256 = Some(value.into_string().map_err(|_| ())?)
            }
            Some("--archive-size") if archive_size.is_none() => {
                let value = value.into_string().map_err(|_| ())?;
                if value.is_empty()
                    || (value.len() > 1 && value.starts_with('0'))
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(());
                }
                archive_size = Some(value.parse::<u64>().map_err(|_| ())?);
            }
            Some("--source-digest") if source_digest.is_none() => {
                source_digest = Some(value.into_string().map_err(|_| ())?)
            }
            Some("--state-root") if state_root.is_none() => state_root = Some(value),
            _ => return Err(()),
        }
    }
    let reference = import_synthetic_oci_archive(SyntheticOciArchiveInput {
        archive: PathBuf::from(archive.ok_or(())?),
        archive_sha256: archive_sha256.ok_or(())?,
        archive_size: archive_size.ok_or(())?,
        source_digest: source_digest.ok_or(())?,
        state_root: PathBuf::from(state_root.ok_or(())?),
    })
    .await
    .map_err(|_| ())?;
    println!("{reference}");
    Ok(())
}
