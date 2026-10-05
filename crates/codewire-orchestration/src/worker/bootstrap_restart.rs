//! The bootstrap-mismatch restart loop guard (#2364), keyed on the daemon
//! image digest.
//!
//! A restart goes through suspend and resume, and the resume re-pins the
//! Sandbox's daemon image to the current support image (owner decision
//! 2026-10-05). A mismatch on a replacement whose daemon digest differs from
//! every Pod a restart already replaced is progress, so it gets one more
//! restart. A mismatch on a digest a restart already replaced is a real
//! incompatibility and stops. A Pod that copies its daemon, or names no
//! digest, has no digest, and its second mismatch stops as before.

use std::future::Future;

use super::create::WorkspaceBootstrapMismatch;

/// Restarts one attempt may make: the first, and one more only after a
/// restart that changed the daemon digest. The configured support image is
/// fixed for an orchestration process, so a re-pin changes the digest at most
/// once; the cap bounds the loop whatever the Pods report.
const MAX_BOOTSTRAP_RESTARTS: usize = 2;

/// One attempt's restarts, by the daemon digest of each Pod a restart
/// replaced.
#[derive(Debug, Default)]
pub(super) struct BootstrapRestartGuard {
    replaced: Vec<Option<String>>,
}

impl BootstrapRestartGuard {
    /// Whether a mismatch on a Pod with this daemon digest may restart it,
    /// recording the restart when it may.
    fn admit(&mut self, daemon_image_digest: Option<&str>) -> bool {
        if self.replaced.len() >= MAX_BOOTSTRAP_RESTARTS
            || self
                .replaced
                .iter()
                .any(|digest| digest.as_deref() == daemon_image_digest)
        {
            return false;
        }
        self.replaced.push(daemon_image_digest.map(str::to_owned));
        true
    }
}

/// Check the observed runtime and, on an admitted bootstrap mismatch, restart
/// it and check the replacement. Returns the runtime that passed and whether
/// any restart happened. A refused mismatch, or any other error, ends the
/// attempt with that error.
pub(super) async fn check_or_restart<R, Check, CheckFuture, Restart, RestartFuture>(
    guard: &mut BootstrapRestartGuard,
    mut runtime: R,
    mut check: Check,
    mut restart: Restart,
) -> anyhow::Result<(R, bool)>
where
    Check: FnMut(&R) -> CheckFuture,
    CheckFuture: Future<Output = anyhow::Result<()>>,
    Restart: FnMut() -> RestartFuture,
    RestartFuture: Future<Output = anyhow::Result<R>>,
{
    let mut restarted = false;
    loop {
        let error = match check(&runtime).await {
            Ok(()) => return Ok((runtime, restarted)),
            Err(error) => error,
        };
        let digest = match error.downcast_ref::<WorkspaceBootstrapMismatch>() {
            Some(mismatch) => mismatch.daemon_image_digest.clone(),
            None => return Err(error),
        };
        if !guard.admit(digest.as_deref()) {
            tracing::warn!(
                daemon_image_digest = digest.as_deref().unwrap_or("none"),
                restarts = guard.replaced.len(),
                "workspace bootstrap mismatch persists on this daemon image; not restarting again"
            );
            return Err(error);
        }
        runtime = restart().await?;
        restarted = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const OLD: &str = "sha256:a59dfec0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NEW: &str = "sha256:1f5972c44d7063815d4d5163f06fc8db5428a5a57dacc4816841cc5cd97ce190";

    /// A workspace Pod as the guard sees it: its name and daemon digest.
    #[derive(Clone, Debug, PartialEq)]
    struct Pod {
        name: &'static str,
        digest: Option<&'static str>,
    }

    fn pod(name: &'static str, digest: Option<&'static str>) -> Pod {
        Pod { name, digest }
    }

    /// Drive the guard over a check that mismatches every Pod named in
    /// `stale` and restarts into the next of `replacements`. Returns the
    /// outcome and the Pods each restart replaced.
    async fn run(
        guard: &mut BootstrapRestartGuard,
        first: Pod,
        stale: &[&'static str],
        replacements: Vec<Pod>,
    ) -> (anyhow::Result<(Pod, bool)>, Vec<Pod>) {
        let replacements = RefCell::new(replacements.into_iter());
        let checked = RefCell::new(Vec::new());
        let replaced = RefCell::new(Vec::new());
        let result = check_or_restart(
            guard,
            first,
            |pod: &Pod| {
                checked.borrow_mut().push(pod.clone());
                let mismatch = stale
                    .contains(&pod.name)
                    .then(|| WorkspaceBootstrapMismatch {
                        daemon_image_digest: pod.digest.map(str::to_owned),
                    });
                async move { mismatch.map_or(Ok(()), |mismatch| Err(mismatch.into())) }
            },
            || {
                replaced
                    .borrow_mut()
                    .push(checked.borrow().last().cloned().unwrap());
                let next = replacements
                    .borrow_mut()
                    .next()
                    .expect("unexpected restart");
                async move { Ok(next) }
            },
        )
        .await;
        (result, replaced.into_inner())
    }

    fn is_mismatch(result: &anyhow::Result<(Pod, bool)>) -> bool {
        result
            .as_ref()
            .err()
            .is_some_and(|error| error.is::<WorkspaceBootstrapMismatch>())
    }

    #[tokio::test]
    async fn a_current_runtime_never_restarts() {
        let mut guard = BootstrapRestartGuard::default();
        let (result, replaced) = run(&mut guard, pod("a", Some(OLD)), &[], vec![]).await;
        assert_eq!(result.unwrap(), (pod("a", Some(OLD)), false));
        assert!(replaced.is_empty());
    }

    /// The incident: a stale Pod on the old daemon restarts, the resume
    /// re-pins its daemon, and the replacement certifies.
    #[tokio::test]
    async fn a_mismatch_restarts_re_pins_and_recovers() {
        let mut guard = BootstrapRestartGuard::default();
        let (result, replaced) = run(
            &mut guard,
            pod("a", Some(OLD)),
            &["a"],
            vec![pod("b", Some(NEW))],
        )
        .await;
        assert_eq!(result.unwrap(), (pod("b", Some(NEW)), true));
        assert_eq!(replaced, [pod("a", Some(OLD))]);
    }

    /// A restart that changed the digest is progress: a replacement that
    /// still mismatches gets one more restart, and certifies.
    #[tokio::test]
    async fn a_re_pin_that_still_mismatches_is_progress() {
        let mut guard = BootstrapRestartGuard::default();
        let (result, replaced) = run(
            &mut guard,
            pod("a", Some(OLD)),
            &["a", "b"],
            vec![pod("b", Some(NEW)), pod("c", Some(NEW))],
        )
        .await;
        assert_eq!(result.unwrap(), (pod("c", Some(NEW)), true));
        assert_eq!(replaced, [pod("a", Some(OLD)), pod("b", Some(NEW))]);
    }

    /// The same digest after a restart is a real incompatibility: the guard
    /// stops after exactly one restart.
    #[tokio::test]
    async fn a_mismatch_on_an_unchanged_digest_stops() {
        for digest in [Some(OLD), Some(NEW), None] {
            let mut guard = BootstrapRestartGuard::default();
            let (result, replaced) = run(
                &mut guard,
                pod("a", digest),
                &["a", "b"],
                vec![pod("b", digest)],
            )
            .await;
            assert!(is_mismatch(&result), "{digest:?}");
            assert_eq!(replaced, [pod("a", digest)], "{digest:?}");
        }
    }

    /// A re-pinned daemon that keeps mismatching stops on its second
    /// mismatch: two restarts, never a third.
    #[tokio::test]
    async fn a_re_pin_that_keeps_mismatching_stops_at_the_cap() {
        let mut guard = BootstrapRestartGuard::default();
        let (result, replaced) = run(
            &mut guard,
            pod("a", Some(OLD)),
            &["a", "b", "c"],
            vec![pod("b", Some(NEW)), pod("c", Some(NEW))],
        )
        .await;
        assert!(is_mismatch(&result));
        assert_eq!(replaced, [pod("a", Some(OLD)), pod("b", Some(NEW))]);

        // Whatever digests the Pods report, an attempt restarts at most twice.
        let third = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let mut guard = BootstrapRestartGuard::default();
        let (result, replaced) = run(
            &mut guard,
            pod("a", Some(OLD)),
            &["a", "b", "c"],
            vec![pod("b", Some(NEW)), pod("c", Some(third))],
        )
        .await;
        assert!(is_mismatch(&result));
        assert_eq!(replaced.len(), MAX_BOOTSTRAP_RESTARTS);
    }

    /// The guard spans one attempt: a later check in the same attempt sees the
    /// restarts an earlier one made.
    #[tokio::test]
    async fn the_guard_spans_every_check_of_an_attempt() {
        let mut guard = BootstrapRestartGuard::default();
        let (result, _) = run(
            &mut guard,
            pod("a", Some(OLD)),
            &["a"],
            vec![pod("b", Some(NEW))],
        )
        .await;
        assert!(result.is_ok());
        let (result, replaced) = run(&mut guard, pod("b", Some(OLD)), &["b"], vec![]).await;
        assert!(is_mismatch(&result));
        assert!(replaced.is_empty());
    }

    #[tokio::test]
    async fn other_errors_never_restart() {
        let mut guard = BootstrapRestartGuard::default();
        let result = check_or_restart(
            &mut guard,
            pod("a", Some(OLD)),
            |_: &Pod| async { Err(anyhow::anyhow!("workspace Pod was replaced")) },
            || async { panic!("restarted after a non-mismatch error") },
        )
        .await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "workspace Pod was replaced"
        );
        assert!(guard.replaced.is_empty());
    }

    #[tokio::test]
    async fn a_failed_restart_ends_the_attempt() {
        let mut guard = BootstrapRestartGuard::default();
        let result = check_or_restart(
            &mut guard,
            pod("a", Some(OLD)),
            |_: &Pod| async {
                Err(WorkspaceBootstrapMismatch {
                    daemon_image_digest: Some(OLD.into()),
                }
                .into())
            },
            || async { Err(anyhow::anyhow!("suspend was not admitted")) },
        )
        .await;
        assert_eq!(result.unwrap_err().to_string(), "suspend was not admitted");
    }
}
