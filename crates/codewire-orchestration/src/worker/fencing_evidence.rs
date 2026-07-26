//! Host-only observable barriers and fault injection for the #916 Kind gate.
//!
//! This module is compiled only with `kind-e2e`. Production binaries cannot
//! enable, observe, or be controlled by these hooks.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum FencingEvidence {
    ClaimAttemptStarted {
        environment_id: String,
        workflow_run_id: String,
    },
    ClaimRowLockHeld {
        environment_id: String,
        claim_name: String,
        claim_uid: String,
    },
    ExecAttached {
        environment_id: String,
        phase: i32,
        pod_uid: String,
    },
    ExecWaitFailed {
        environment_id: String,
        phase: i32,
        pod_uid: String,
        error: String,
    },
    FailOnceInjected {
        environment_id: String,
        phase: i32,
        pod_uid: String,
    },
    RecoveryStarted {
        environment_id: String,
        phase: i32,
        pod_uid: String,
    },
    NoPodObserved {
        environment_id: String,
        pod_uid: String,
    },
    QuiescenceComplete {
        environment_id: String,
        pod_uid: String,
        wait_ms: u64,
    },
    ReplacementReady {
        environment_id: String,
        old_pod_uid: String,
        new_pod_uid: String,
    },
    RecoveryComplete {
        environment_id: String,
        phase: i32,
        old_pod_uid: String,
    },
    CloneGroupJoined {
        environment_id: String,
        launched: usize,
        observed: usize,
    },
}

pub fn emit(event: FencingEvidence) {
    let Ok(path) = std::env::var("CODEWIRE_KIND_FENCING_EVIDENCE_FILE") else {
        return;
    };
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return;
    };
    if let Ok(json) = serde_json::to_string(&event) {
        let _ = writeln!(file, "{json}");
        let _ = file.flush();
    }
}

/// Preserve the exact completion boundary needed by the Kind fencing driver
/// without copying remote command output into the host evidence file.
#[cfg(feature = "kind-e2e")]
pub fn safe_exec_wait_error(error: &anyhow::Error) -> String {
    let message = format!("{error:#}");
    if message == "workspace exec completion status unavailable"
        || message.starts_with("workspace exec completion: ")
        || message.starts_with("workspace exec stdout: ")
        || message.starts_with("workspace exec stderr: ")
    {
        return message;
    }
    if message.starts_with("workspace exec: ") {
        return "workspace exec remote status failure (details redacted)".to_string();
    }
    "workspace exec wait failure (details redacted)".to_string()
}

/// Hold the environment-row serialization lock after the real SandboxClaim
/// exists but before claim bookkeeping commits. The Kind driver releases the
/// operation only after it has observed both the lifecycle-intent writer and
/// replacement generation claim waiting behind this lock.
pub async fn hold_claim_row_lock(
    environment_id: &str,
    claim_name: &str,
    claim_uid: &str,
) -> anyhow::Result<()> {
    let Ok(release_path) = std::env::var("CODEWIRE_KIND_FENCING_CLAIM_RELEASE_FILE") else {
        return Ok(());
    };
    emit(FencingEvidence::ClaimRowLockHeld {
        environment_id: environment_id.to_string(),
        claim_name: claim_name.to_string(),
        claim_uid: claim_uid.to_string(),
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    while !Path::new(&release_path).exists() {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("Kind claim-row-lock barrier was not released");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// Inject one retryable failure after a real workspace exec completed while
/// its running lease is still durable. `create_new` makes the fault exactly
/// once across process restarts as well as activity attempts.
pub fn fail_once_after_exec(environment_id: &str, phase: i32, pod_uid: &str) -> bool {
    let Ok(marker_path) = std::env::var("CODEWIRE_KIND_FENCING_FAIL_ONCE_FILE") else {
        return false;
    };
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker_path)
    {
        Ok(_) => {
            emit(FencingEvidence::FailOnceInjected {
                environment_id: environment_id.to_string(),
                phase,
                pod_uid: pod_uid.to_string(),
            });
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => false,
    }
}

/// Feature-only clone fixtures exercise two simultaneous workspace execs
/// without depending on an external Git host or a particular workspace image's
/// Git installation.
pub fn clone_fixture_command(url: &str) -> Option<Vec<String>> {
    match url {
        "kind-e2e://clone-fail" => Some(vec![
            "sh".into(),
            "-c".into(),
            "sleep 1; echo injected-clone-failure >&2; exit 42".into(),
        ]),
        "kind-e2e://clone-sibling" => Some(vec!["sh".into(), "-c".into(), "sleep 60".into()]),
        _ => None,
    }
}

#[cfg(all(test, feature = "kind-e2e"))]
mod tests {
    use super::safe_exec_wait_error;

    #[test]
    fn exec_wait_evidence_preserves_structural_completion_errors() {
        for message in [
            "workspace exec completion status unavailable",
            "workspace exec completion: websocket closed",
            "workspace exec stdout: stream reset",
            "workspace exec stderr: stream reset",
        ] {
            assert_eq!(safe_exec_wait_error(&anyhow::anyhow!(message)), message);
        }
    }

    #[test]
    fn exec_wait_evidence_redacts_remote_output_and_unknown_errors() {
        assert_eq!(
            safe_exec_wait_error(&anyhow::anyhow!(
                "workspace exec: failed: sensitive command output"
            )),
            "workspace exec remote status failure (details redacted)"
        );
        assert_eq!(
            safe_exec_wait_error(&anyhow::anyhow!("unexpected sensitive detail")),
            "workspace exec wait failure (details redacted)"
        );
    }
}
