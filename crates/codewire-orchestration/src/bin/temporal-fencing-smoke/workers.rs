//! The fencing smoke's worker subprocesses: the production workflow and
//! activity code on a scenario's own task queue.

use super::*;

impl Driver {
    pub(super) fn spawn_worker(
        &self,
        queue: &str,
        evidence: &Path,
        claim_release: Option<&Path>,
        fail_once: Option<&Path>,
    ) -> anyhow::Result<WorkerProcess> {
        Ok(WorkerProcess {
            child: self
                .worker_command(queue, evidence, claim_release, fail_once)?
                .spawn()?,
        })
    }

    /// A worker that renders environments with a credential selection,
    /// trusting the deployed credential broker, as orchestration does.
    pub(super) fn spawn_selected_worker(
        &self,
        queue: &str,
        evidence: &Path,
    ) -> anyhow::Result<WorkerProcess> {
        let mut command = self.worker_command(queue, evidence, None, None)?;
        command.env("SANDBOX_CREDENTIAL_BROKER_NAMESPACE", SERVER_NAMESPACE);
        Ok(WorkerProcess {
            child: command.spawn()?,
        })
    }

    pub(super) fn worker_command(
        &self,
        queue: &str,
        evidence: &Path,
        claim_release: Option<&Path>,
        fail_once: Option<&Path>,
    ) -> anyhow::Result<Command> {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("worker")
            .env("DATABASE_URL", &self.database_url)
            .env("TEMPORAL_ADDRESS", &self.temporal_address)
            .env("TEMPORAL_TASK_QUEUE", queue)
            .env("CODEWIRE_KIND_FENCING_EVIDENCE_FILE", evidence)
            .env("CODEWIRE_KIND_TENANT_SECRET_TEST_PROVIDER", "true")
            .env("ENVIRONMENT", "local")
            .env("SESSION_SECRET", "kind-e2e-not-a-real-secret")
            .env("SANDBOX_NAMESPACE", SANDBOX_NAMESPACE)
            // The deployed orchestration's runtime images, as this
            // process was given them.
            .env(runtime_images::DAEMON_IMAGE_ENV, &self.daemon_image)
            .env(
                runtime_images::WORKSPACE_IMAGE_REPOSITORY_ENV,
                self.runtime_images.workspace_repository(),
            )
            .env(
                runtime_images::APPROVED_IMAGE_REGISTRIES_ENV,
                self.runtime_images.approved_registries().join(","),
            )
            .env("SANDBOX_RUNTIME_PROFILE", "runc")
            .env("SANDBOX_ALLOW_DIAGNOSTIC_RUNTIME", "true")
            .env("SANDBOX_WORKSPACE_STORAGE_CLASS", "standard")
            .env("SANDBOX_NETWORK_POLICY_MANAGEMENT", "Managed")
            .env("SANDBOX_DIND_ENABLED", "false")
            .env("SIDECAR_READY_TIMEOUT_SECS", "120")
            // Only a bound daemon serves SSH and records its host key, so
            // the worker binds workspaces through the in-cluster listener,
            // with the overlay's settings (tests/e2e/kind/support.yaml).
            .env("POD_NAMESPACE", SERVER_NAMESPACE)
            .env(
                "CODEWIRE_API_URL",
                format!("http://codewire-orchestration.{SERVER_NAMESPACE}.svc.cluster.local:8084"),
            )
            .env(
                "CODEWIRE_COORDINATOR_URL",
                format!("http://codewire-coordinator.{SERVER_NAMESPACE}.svc.cluster.local:8090"),
            )
            .env("SANDBOX_COORDINATOR_EXTRA_ROOTS", "true")
            .env("SANDBOX_INGRESS_NAMESPACE", "ingress-nginx")
            .env("SANDBOX_INGRESS_POD_NAME", "ingress-nginx")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        if let Some(path) = claim_release {
            command.env("CODEWIRE_KIND_FENCING_CLAIM_RELEASE_FILE", path);
        }
        if let Some(path) = fail_once {
            command.env("CODEWIRE_KIND_FENCING_FAIL_ONCE_FILE", path);
        }
        Ok(command)
    }
}
