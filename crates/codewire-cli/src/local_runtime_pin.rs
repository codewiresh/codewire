//! The local VM runtime this cw pins (#2539). A release's cw embeds its
//! runtime document, so the runtime's exact digests are covered by the trust
//! already placed in this cw; `cw setup --local`, or the next local VM start
//! (#2582), downloads exactly those files. A development build embeds
//! nothing and installs only `--from DIR`.

use std::future::Future;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use codewire_local_vmm::runtime_install::{
    self, InstallError, InstallOutcome, InstalledRuntime, LocalRuntimeDocument, RuntimePaths,
};

/// How long a local VM start waits for another cw installing the runtime.
const INSTALL_WAIT: Duration = Duration::from_secs(600);
const INSTALL_POLL: Duration = Duration::from_secs(1);

include!(concat!(env!("OUT_DIR"), "/local_runtime.rs"));

/// This cw's pinned runtime, or `None` for a development build.
pub(crate) fn embedded() -> anyhow::Result<Option<LocalRuntimeDocument>> {
    let revision = crate::build_record::embedded()?.source_revision;
    decode(LOCAL_RUNTIME, revision.as_deref())
}

fn decode(bytes: &[u8], revision: Option<&str>) -> anyhow::Result<Option<LocalRuntimeDocument>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let document = LocalRuntimeDocument::decode(bytes)
        .context("this cw's pinned local VM runtime is invalid")?;
    anyhow::ensure!(
        revision == Some(document.source_revision.as_str()),
        "this cw's pinned local VM runtime was built from other source"
    );
    Ok(Some(document))
}

/// Before creating or starting a local VM, make the runtime this cw pins the
/// installed one (#2582), with `install` (the same path as `cw setup
/// --local`). A start never uses a runtime another cw installed: if this
/// one cannot be installed, the start fails. Running VMs keep the generation
/// they started with. A development build, or a host this cw pins no runtime
/// for, is unchanged.
pub(crate) async fn ensure_installed<F, Fut>(
    paths: &RuntimePaths,
    mut install: F,
) -> anyhow::Result<()>
where
    F: FnMut(LocalRuntimeDocument) -> Fut,
    Fut: Future<Output = anyhow::Result<InstallOutcome>>,
{
    let Some(document) = embedded()? else {
        return Ok(());
    };
    if runtime_install::host_runtime(&document).is_err() {
        return Ok(());
    }
    let generation = runtime_install::pinned_generation(&document)?;
    ensure_with(
        &generation,
        || Ok(runtime_install::installed_runtime(paths, &document)?),
        || install(document.clone()),
        INSTALL_WAIT,
        INSTALL_POLL,
    )
    .await
}

async fn ensure_with<C, I, Fut>(
    generation: &str,
    mut check: C,
    mut install: I,
    wait: Duration,
    poll: Duration,
) -> anyhow::Result<()>
where
    C: FnMut() -> anyhow::Result<InstalledRuntime>,
    I: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<InstallOutcome>>,
{
    let short = &generation[..generation.len().min(12)];
    let deadline = Instant::now() + wait;
    let mut waiting = false;
    loop {
        let reason = match check()? {
            InstalledRuntime::Same => return Ok(()),
            InstalledRuntime::Missing => "is not installed",
            InstalledRuntime::Incomplete => "is incomplete",
            InstalledRuntime::Different => "is another cw version's",
        };
        if !waiting {
            eprintln!(
                "The local VM runtime {reason}; installing the one this cw pins ({short}). Running VMs keep theirs."
            );
        }
        match install().await {
            Ok(InstallOutcome::Installed { .. } | InstallOutcome::AlreadyInstalled { .. }) => {
                eprintln!("Local VM runtime installed ({short}).");
                return Ok(());
            }
            // Another cw is installing: wait for it, then check again.
            Err(error) if busy(&error) && Instant::now() < deadline => {
                if !waiting {
                    eprintln!("Waiting for another cw that is installing the local VM runtime...");
                    waiting = true;
                }
                tokio::time::sleep(poll).await;
            }
            Err(error) => {
                return Err(error.context(format!(
                    "this cw needs its local VM runtime ({short}), which {reason} and could not be installed now; reconnect to the network and retry, or install it with `cw setup --local`"
                )));
            }
        }
    }
}

fn busy(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<InstallError>(),
            Some(InstallError::Busy)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const GENERATION: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn installed() -> InstallOutcome {
        InstallOutcome::Installed {
            generation: GENERATION.into(),
        }
    }

    /// Runs ensure_with over a sequence of observed states and install results.
    async fn ensure(
        states: Vec<InstalledRuntime>,
        results: Vec<anyhow::Result<InstallOutcome>>,
        wait: Duration,
    ) -> (anyhow::Result<()>, usize, usize) {
        let states = RefCell::new(states.into_iter());
        let results = RefCell::new(results.into_iter());
        let (checks, installs) = (RefCell::new(0), RefCell::new(0));
        let outcome = ensure_with(
            GENERATION,
            || {
                *checks.borrow_mut() += 1;
                Ok(states
                    .borrow_mut()
                    .next()
                    .expect("an unexpected state check"))
            },
            || {
                *installs.borrow_mut() += 1;
                let result = results.borrow_mut().next().expect("an unexpected install");
                async move { result }
            },
            wait,
            Duration::from_millis(1),
        )
        .await;
        (outcome, checks.into_inner(), installs.into_inner())
    }

    #[tokio::test]
    async fn the_pinned_runtime_starts_without_an_install() {
        let (outcome, checks, installs) =
            ensure(vec![InstalledRuntime::Same], vec![], INSTALL_WAIT).await;
        outcome.unwrap();
        assert_eq!((checks, installs), (1, 0));
    }

    #[tokio::test]
    async fn a_missing_stale_or_incomplete_runtime_is_installed_before_the_start() {
        for state in [
            InstalledRuntime::Missing,
            InstalledRuntime::Different,
            InstalledRuntime::Incomplete,
        ] {
            let (outcome, checks, installs) =
                ensure(vec![state], vec![Ok(installed())], INSTALL_WAIT).await;
            outcome.unwrap();
            assert_eq!((checks, installs), (1, 1));
        }
    }

    #[tokio::test]
    async fn a_start_waits_for_another_installer_and_checks_again() {
        let (outcome, checks, installs) = ensure(
            vec![
                InstalledRuntime::Different,
                InstalledRuntime::Different,
                InstalledRuntime::Same,
            ],
            vec![
                Err(InstallError::Busy.into()),
                Err(InstallError::Busy.into()),
            ],
            INSTALL_WAIT,
        )
        .await;
        outcome.unwrap();
        assert_eq!((checks, installs), (3, 2));
    }

    #[tokio::test]
    async fn an_installer_that_never_finishes_fails_the_start() {
        let (outcome, _, installs) = ensure(
            vec![InstalledRuntime::Missing],
            vec![Err(InstallError::Busy.into())],
            Duration::ZERO,
        )
        .await;
        let message = format!("{:#}", outcome.unwrap_err());
        assert_eq!(installs, 1);
        assert!(
            message.contains("another local VM runtime install is running"),
            "{message}"
        );
        assert!(message.contains("`cw setup --local`"), "{message}");
    }

    #[tokio::test]
    async fn offline_the_start_fails_clearly_and_never_uses_another_runtime() {
        let (outcome, checks, installs) = ensure(
            vec![InstalledRuntime::Different],
            vec![Err(anyhow::anyhow!(
                "connect releases.codewire.sh: network is unreachable"
            ))],
            INSTALL_WAIT,
        )
        .await;
        let message = format!("{:#}", outcome.unwrap_err());
        assert_eq!((checks, installs), (1, 1));
        assert!(message.starts_with("this cw needs its local VM runtime (0123456789ab), which is another cw version's and could not be installed now; reconnect to the network and retry, or install it with `cw setup --local`"), "{message}");
        assert!(message.ends_with("network is unreachable"), "{message}");
    }

    #[test]
    fn an_embedded_runtime_must_decode_and_match_this_source() {
        assert!(decode(b"", Some(&"a".repeat(40))).unwrap().is_none());
        assert!(decode(b"", None).unwrap().is_none());
        assert!(decode(b"{}\n", Some(&"a".repeat(40))).is_err());

        let revision = "a".repeat(40);
        let digest = |seed: u8| format!("{seed:02x}").repeat(32);
        let spec = |path: &str, seed: u8| serde_json::json!({"path": path, "size": 10, "sha256": digest(seed), "architecture": "aarch64"});
        let document = serde_json::json!({
            "schema": runtime_install::LOCAL_RUNTIME_SCHEMA,
            "source_revision": revision,
            "targets": {"macos-aarch64": {"lock": {
                "schema_version": 1,
                "vz_runner": spec("codewire-vz-runner", 1),
                "kernel": spec("kernel", 2),
                "initramfs": spec("initramfs", 3),
                "e2fsprogs": {
                    "mkfs_ext4": spec("mkfs.ext4", 4), "e2fsck": spec("e2fsck", 5),
                    "resize2fs": spec("resize2fs", 6), "debugfs": spec("debugfs", 7),
                    "mke2fs_conf": spec("mke2fs.conf", 8),
                },
                "git": {"git": spec("git", 9), "git_remote_https": spec("git-remote-https", 10)},
            }}},
        });
        let bytes = codewire_cw_release::identity::canonical_json(&document).unwrap();
        assert!(decode(&bytes, Some(&revision)).unwrap().is_some());
        assert!(decode(&bytes, Some(&"b".repeat(40))).is_err());
        assert!(decode(&bytes, None).is_err());
    }
}
