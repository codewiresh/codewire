//! What ends a workspace Pod's readiness wait early: a container that cannot
//! start (#4431), what the wait reports and how it is read from the statuses
//! the kubelet writes, and a scheduler that refuses the Pod for lack of
//! capacity (#3635).

use super::*;

/// A container of the workspace Pod could not start, and stayed that way for
/// its grace. More waiting cannot make the claim Ready. `reason` and `message`
/// are the kubelet's own, so they say whether the image or the node is at
/// fault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerStartFailed {
    pub container: String,
    /// The container's image as the Pod's spec names it, which is what the
    /// create asked for, never the runtime's report of it; empty for a Pod
    /// that ended as a whole.
    pub image: String,
    pub reason: String,
    pub message: String,
    /// The exit code, when the container ran and ended.
    pub exit_code: Option<i32>,
}

impl std::fmt::Display for ContainerStartFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the message: it is the runtime's own text and can quote a
        // secret, and an error's text travels to logs and stored rows (#4483).
        write!(
            f,
            "container {} could not start: {}",
            self.container, self.reason
        )
    }
}

impl std::error::Error for ContainerStartFailed {}

/// Which grace a container start failure gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StartFailureKind {
    /// The image cannot be pulled; the kubelet keeps retrying.
    ImagePull,
    /// The container cannot be created, run or started, or the Pod is over.
    Start,
}

impl StartFailureKind {
    pub(super) fn grace(self) -> Duration {
        match self {
            Self::ImagePull => IMAGE_PULL_FAILURE_GRACE,
            Self::Start => CONTAINER_START_FAILURE_GRACE,
        }
    }
}

impl SandboxClient {
    /// Ends once a container of the environment's workspace Pod has been
    /// unable to start for its grace without a break, and never otherwise, so
    /// each wait for a new Pod races it (#4431). A Pod that cannot be read, or
    /// a failure of the other kind, breaks the run. A container that is still
    /// being created or initialized is not a failure, however long it takes.
    pub(in crate::sandbox) async fn refused_for_start_failure(
        &self,
        env_id: &str,
    ) -> ContainerStartFailed {
        let name = claim_name(env_id);
        let mut failing_since: Option<(StartFailureKind, tokio::time::Instant)> = None;
        loop {
            let pod = self.claim_workspace_pod(&name).await;
            match pod.as_ref().and_then(container_start_failure) {
                Some((kind, failure)) => {
                    let since = match failing_since {
                        Some((seen, since)) if seen == kind => since,
                        _ => tokio::time::Instant::now(),
                    };
                    failing_since = Some((kind, since));
                    if since.elapsed() >= kind.grace() {
                        tracing::warn!(claim = name, error = %failure, "container start failure detected");
                        return failure;
                    }
                }
                None => failing_since = None,
            }
            tokio::time::sleep(START_FAILURE_POLL).await;
        }
    }

    /// Ends once the scheduler has refused the environment's workspace Pod for
    /// lack of resources for [`NO_CAPACITY_GRACE`] without a break, and never
    /// otherwise, so each wait for a new Pod races it (#3635). An unreadable Pod
    /// breaks the run, so only an unbroken refusal counts.
    pub(in crate::sandbox) async fn refused_for_no_capacity(&self, env_id: &str) -> NoCapacity {
        let name = claim_name(env_id);
        let mut refused_since = None;
        loop {
            let pod = self.claim_workspace_pod(&name).await;
            match pod.as_ref().and_then(capacity_refusal) {
                Some(refusal) => {
                    let since = *refused_since.get_or_insert_with(tokio::time::Instant::now);
                    if since.elapsed() >= NO_CAPACITY_GRACE {
                        return NoCapacity(refusal);
                    }
                }
                None => refused_since = None,
            }
            tokio::time::sleep(NO_CAPACITY_POLL).await;
        }
    }
}

/// The image the spec of `pod` gives its container `name`, or nothing.
fn spec_image(pod: &Pod, name: &str) -> String {
    pod.spec
        .iter()
        .flat_map(|spec| {
            spec.init_containers
                .iter()
                .flatten()
                .chain(spec.containers.iter())
        })
        .find(|container| container.name == name)
        .and_then(|container| container.image.clone())
        .unwrap_or_default()
}

/// The first container of `pod` that cannot start, and how (#4431). It reads
/// only the container statuses the kubelet writes:
///
/// - a Pod that is over (`Failed` or `Succeeded`) before its claim was Ready;
/// - a waiting reason of [`TERMINAL_WAITING_REASONS`], where the two image
///   pull reasons get the longer grace;
/// - `CrashLoopBackOff`, with the last termination as its message;
/// - a container that terminated with a non-zero exit, such as `StartError`,
///   which a Pod that is still `Running` shows when another container runs.
///
/// A container that is waiting to be created or initialized
/// (`ContainerCreating`, `PodInitializing`) is healthy, and so is one that
/// exited zero.
pub(super) fn container_start_failure(
    pod: &Pod,
) -> Option<(StartFailureKind, ContainerStartFailed)> {
    if let Some((reason, message)) = terminal_pod_failure_reason(pod)
        && pod
            .status
            .as_ref()
            .and_then(|status| status.phase.as_deref())
            .is_some_and(|phase| matches!(phase, "Failed" | "Succeeded"))
    {
        return Some((
            StartFailureKind::Start,
            ContainerStartFailed {
                container: "workspace Pod".to_string(),
                image: String::new(),
                reason,
                message,
                exit_code: None,
            },
        ));
    }
    let status = pod.status.as_ref()?;
    status
        .init_container_statuses
        .as_deref()
        .into_iter()
        .flatten()
        .chain(status.container_statuses.as_deref().into_iter().flatten())
        .find_map(|container| {
            let state = container.state.as_ref()?;
            let failed =
                |reason: &str, message: String, exit_code: Option<i32>| ContainerStartFailed {
                    container: container.name.clone(),
                    image: spec_image(pod, &container.name),
                    reason: reason.to_string(),
                    message,
                    exit_code,
                };
            if let Some(waiting) = state.waiting.as_ref() {
                let reason = waiting.reason.as_deref().unwrap_or_default();
                let message = waiting.message.clone().unwrap_or_default();
                if matches!(reason, "ImagePullBackOff" | "ErrImagePull") {
                    return Some((StartFailureKind::ImagePull, failed(reason, message, None)));
                }
                if TERMINAL_WAITING_REASONS.contains(&reason) {
                    return Some((StartFailureKind::Start, failed(reason, message, None)));
                }
                if reason == "CrashLoopBackOff" {
                    let last = container
                        .last_state
                        .as_ref()
                        .and_then(|last| last.terminated.as_ref());
                    return Some((
                        StartFailureKind::Start,
                        failed(
                            reason,
                            last.map(termination_detail).unwrap_or(message),
                            last.map(|terminated| terminated.exit_code),
                        ),
                    ));
                }
                return None;
            }
            let terminated = state.terminated.as_ref().filter(|t| t.exit_code != 0)?;
            let reason = terminated
                .reason
                .as_deref()
                .filter(|reason| !reason.is_empty())
                .unwrap_or("Error");
            Some((
                StartFailureKind::Start,
                failed(
                    reason,
                    termination_detail(terminated),
                    Some(terminated.exit_code),
                ),
            ))
        })
}

/// How a container ended: its exit code, then the runtime's message when it
/// left one (for a failed start, the reason the container could not be made).
fn termination_detail(terminated: &k8s_openapi::api::core::v1::ContainerStateTerminated) -> String {
    let exit = format!("exit code {}", terminated.exit_code);
    match terminated
        .message
        .as_deref()
        .map(str::trim)
        .filter(|message| !message.is_empty())
    {
        Some(message) => format!("{exit}: {message}"),
        None => exit,
    }
}
