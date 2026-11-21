//! Kubernetes calls of an environment resize: reading whether the workspace
//! Pod can be resized in place, the in-place resize and its wait, settling a
//! failed one, and the disk's growth. They stand apart from the rest of
//! [`SandboxClient`] so that file, long past the size at which a file stops
//! growing, loses a concern instead of gaining lines.

use super::*;

impl SandboxClient {
    /// Read the runtime facts that determine whether CPU/memory can be
    /// changed without replacing or restarting the workspace container, from
    /// the Pod the environment's current Sandbox controls.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %env_id))]
    pub async fn workspace_pod_resize_state(
        &self,
        env_id: &str,
    ) -> anyhow::Result<WorkspacePodResizeState> {
        let pod = self.current_workspace_pod_object(env_id).await?;
        workspace_pod_resize_state(&pod, "")
    }

    /// Apply CPU and memory through the Kubernetes Pod `/resize` subresource
    /// and wait for the kubelet-reported resources to converge. This path
    /// never deletes the Pod and fails if its identity or restart count moves.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %env_id))]
    pub async fn resize_workspace_pod_in_place(
        &self,
        env_id: &str,
        expected_uid: &str,
        cpu_millicores: i32,
        memory_mb: i32,
        timeout: Duration,
    ) -> anyhow::Result<WorkspacePodResizeState> {
        if expected_uid.trim().is_empty() {
            anyhow::bail!("expected workspace Pod UID is required");
        }
        if cpu_millicores <= 0 || memory_mb <= 0 {
            anyhow::bail!("workspace CPU and memory must be greater than zero");
        }
        let accepted = self
            .submit_workspace_pod_resize(env_id, expected_uid, cpu_millicores, memory_mb)
            .await?;
        self.wait_for_workspace_pod_resize(&accepted, timeout).await
    }

    /// Submit a `/resize` request bound to the exact Pod incarnation the
    /// environment's current Sandbox controls. A refusal because the Pod
    /// changed re-resolves it through the Sandbox and rechecks its identity
    /// and resize policy before submitting again.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %env_id))]
    async fn submit_workspace_pod_resize(
        &self,
        env_id: &str,
        expected_uid: &str,
        cpu_millicores: i32,
        memory_mb: i32,
    ) -> anyhow::Result<AcceptedPodResize> {
        for _ in 0..POD_RESIZE_SUBMIT_ATTEMPTS {
            let pod = self.current_workspace_pod_object(env_id).await?;
            let compute =
                WorkspaceCompute::new(cpu_millicores, memory_mb, workspace_pod_cpu_sharing(&pod));
            if let Some(accepted) = self
                .submit_pod_resize_once(&pod, expected_uid, &compute)
                .await?
            {
                return Ok(accepted);
            }
        }
        anyhow::bail!(
            "workspace Pod changed before each of {POD_RESIZE_SUBMIT_ATTEMPTS} live resize submissions; nothing was resized"
        )
    }

    /// One `/resize` request conditioned on `pod`, the observed incarnation.
    /// The patch carries its UID and resourceVersion, which the API server
    /// enforces: a replacement under the same name, or any change since the
    /// observation, is refused without mutation (`Ok(None)`).
    async fn submit_pod_resize_once(
        &self,
        pod: &Pod,
        expected_uid: &str,
        compute: &WorkspaceCompute,
    ) -> anyhow::Result<Option<AcceptedPodResize>> {
        let before = workspace_pod_resize_state(pod, "")?;
        if before.identity.uid != expected_uid {
            anyhow::bail!(
                "workspace Pod was replaced before live resize: expected UID {expected_uid}, got {}",
                before.identity.uid
            );
        }
        if !before.live_resize_compatible {
            anyhow::bail!(
                "workspace container cannot be resized live: {}",
                before
                    .incompatibility_reason
                    .as_deref()
                    .unwrap_or("incompatible resize policy")
            );
        }
        let resource_version = pod
            .metadata
            .resource_version
            .as_deref()
            .filter(|version| !version.is_empty())
            .ok_or_else(|| anyhow::anyhow!("workspace Pod has no resourceVersion"))?;
        let patch = pod_resize_patch(expected_uid, resource_version, compute);
        match self
            .pods()
            .patch_resize(
                &before.identity.name,
                &PatchParams::default(),
                &Patch::Strategic(&patch),
            )
            .await
        {
            Ok(accepted) => Ok(Some(AcceptedPodResize {
                before,
                compute: compute.clone(),
                generation: accepted.metadata.generation.filter(|value| *value > 0),
            })),
            Err(kube::Error::Api(error)) if error.code == 409 => Ok(None),
            Err(error) => anyhow::bail!(
                "resize workspace Pod {} through /resize: {error}",
                before.identity.name
            ),
        }
    }

    /// Wait until the kubelet reports the requested resources on the same
    /// incarnation. A failure condition counts only while the Pod still asks
    /// for this request and its generation acknowledges it; an older or
    /// unacknowledged one keeps the wait going, and is named if the wait
    /// times out.
    #[tracing::instrument(level = "debug", skip_all)]
    async fn wait_for_workspace_pod_resize(
        &self,
        accepted: &AcceptedPodResize,
        timeout: Duration,
    ) -> anyhow::Result<WorkspacePodResizeState> {
        let before = &accepted.before;
        let compute = &accepted.compute;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let pod = self
                .pods()
                .get(&before.identity.name)
                .await
                .map_err(|error| {
                    anyhow::anyhow!(
                        "observe resized workspace Pod {}: {error}",
                        before.identity.name
                    )
                })?;
            let observed = workspace_pod_resize_state(&pod, &before.identity.name)?;
            if observed.identity.uid != before.identity.uid {
                anyhow::bail!(
                    "workspace Pod was replaced during live resize: expected UID {}, got {}",
                    before.identity.uid,
                    observed.identity.uid
                );
            }
            if observed.restart_count != before.restart_count {
                anyhow::bail!(
                    "workspace container restarted during live resize: restart count changed from {} to {}",
                    before.restart_count,
                    observed.restart_count
                );
            }
            let infeasible = infeasible_pod_resize(&pod, accepted.generation);
            if let Some((message, true)) = &infeasible
                && workspace_spec_resources_match(&pod, compute)
            {
                return Err(PodResizeInfeasible(message.clone()).into());
            }
            if workspace_resources_match(&pod, compute)
                && pod_resize_acknowledged(&pod, accepted.generation)
            {
                return Ok(observed);
            }
            if tokio::time::Instant::now() >= deadline {
                let unacknowledged = infeasible
                    .map(|(message, _)| {
                        format!("; an earlier or unacknowledged request is reported infeasible: {message}")
                    })
                    .unwrap_or_default();
                anyhow::bail!(
                    "timeout waiting for workspace Pod {} live resize to converge{unacknowledged}",
                    before.identity.name
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Settle what a failed resize left on the workspace Pod incarnation it
    /// may have asked to resize. An applied request is kept. A pending one is
    /// withdrawn by a preconditioned `/resize` back to the previous CPU and
    /// memory on that same incarnation; if the Pod changes first, it is
    /// classified again, so an increase that lands meanwhile is kept rather
    /// than shrunk. Another incarnation is never mutated: a replaced,
    /// terminating or unreadable Pod is `Unknown`.
    pub async fn settle_failed_live_resize(
        &self,
        env_id: &str,
        expected_uid: &str,
        previous: (i32, i32),
        requested: (i32, i32),
        timeout: Duration,
    ) -> FailedLiveResize {
        let mut withdrawal = None;
        for _ in 0..POD_RESIZE_SUBMIT_ATTEMPTS {
            let pod = match self.observe_failed_live_resize(env_id, expected_uid).await {
                Ok(pod) => pod,
                Err(error) => return FailedLiveResize::Unknown(format!("{error:#}")),
            };
            if let Some(outcome) = failed_live_resize_outcome(&pod, previous, requested) {
                return outcome;
            }
            if let Some(error) = withdrawal {
                return FailedLiveResize::Unknown(format!(
                    "withdrawing the pending request did not settle: {error:#}"
                ));
            }
            let compute =
                WorkspaceCompute::new(previous.0, previous.1, workspace_pod_cpu_sharing(&pod));
            let accepted = match self
                .submit_pod_resize_once(&pod, expected_uid, &compute)
                .await
            {
                Ok(Some(accepted)) => accepted,
                Ok(None) => continue,
                Err(error) => {
                    withdrawal = Some(error);
                    continue;
                }
            };
            match self.wait_for_workspace_pod_resize(&accepted, timeout).await {
                Ok(_) => return FailedLiveResize::Settled,
                Err(error) => withdrawal = Some(error),
            }
        }
        FailedLiveResize::Unknown(match withdrawal {
            Some(error) => format!("withdrawing the pending request did not settle: {error:#}"),
            None => "the workspace Pod changed during every withdrawal attempt".into(),
        })
    }

    async fn observe_failed_live_resize(
        &self,
        env_id: &str,
        expected_uid: &str,
    ) -> anyhow::Result<Pod> {
        let pod = self.current_workspace_pod_object(env_id).await?;
        let uid = pod.metadata.uid.as_deref().unwrap_or_default();
        anyhow::ensure!(
            uid == expected_uid,
            "the workspace Pod was replaced (UID {uid}, expected {expected_uid}) and is not compensated"
        );
        Ok(pod)
    }

    /// Verify a requested disk size before the resize operation is admitted.
    pub async fn require_workspace_storage_resize(
        &self,
        anchor: &WorkspacePvcAnchor,
        desired_disk_gb: i32,
    ) -> anyhow::Result<WorkspaceStorage> {
        let storage = self.workspace_storage(anchor).await?;
        if desired_disk_gb < storage.requested_disk_gb {
            anyhow::bail!(
                "persistent storage cannot shrink from {} Gi to {} Gi",
                storage.requested_disk_gb,
                desired_disk_gb
            );
        }
        // The guest-encrypted confidential raw-block profile cannot expand in
        // place. Reject here so Kubernetes never persists a larger PVC request
        // before the downstream CSI/CDH refusal. A commodity Block workspace
        // grows: its next Pod's `mount-workspace` grows the filesystem online.
        if desired_disk_gb > storage.requested_disk_gb && storage.confidential {
            anyhow::bail!("confidential workspace storage expansion is not supported");
        }
        if desired_disk_gb > storage.requested_disk_gb && !storage.expansion_allowed {
            anyhow::bail!(
                "StorageClass {} does not allow volume expansion",
                storage.storage_class_name
            );
        }
        Ok(storage)
    }

    /// Persist desired compute on the current claim, its private
    /// per-environment template when present, and the already-owned Sandbox.
    /// Storage is applied to the PVC directly; the pinned Sandbox CRD makes
    /// an existing Sandbox's volumeClaimTemplates immutable.
    /// The existing agent-sandbox controller does not copy claim resource
    /// changes to an existing Sandbox, so the Sandbox patch is intentional.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %env_id))]
    pub async fn apply_resize_desired_state(
        &self,
        env_id: &str,
        cpu_millicores: i32,
        memory_mb: i32,
        disk_gb: i32,
    ) -> anyhow::Result<()> {
        if cpu_millicores <= 0 || memory_mb <= 0 || disk_gb <= 0 {
            anyhow::bail!("resize resources must be greater than zero");
        }
        let storage = format!("{disk_gb}Gi");

        let sandbox_name = self.bound_sandbox_name(env_id).await?;
        let sandboxes = self.sandboxes();
        let mut sandbox = sandboxes
            .get(&sandbox_name)
            .await
            .map_err(|error| anyhow::anyhow!("get Sandbox {sandbox_name}: {error}"))?;
        let compute = WorkspaceCompute::new(
            cpu_millicores,
            memory_mb,
            runtime_object_cpu_sharing(&sandbox.data),
        );

        let claim = claim_name(env_id);
        let claim_patch = serde_json::json!({
            "spec": {
                "workspaceResources": [{
                    "containerName": "workspace",
                    "resources": {
                        "requests": { "cpu": compute.cpu_request, "memory": compute.memory },
                        "limits": { "cpu": compute.cpu_limit, "memory": compute.memory },
                    },
                }],
            },
        });
        self.claims
            .patch(&claim, &PatchParams::default(), &Patch::Merge(&claim_patch))
            .await
            .map_err(|error| anyhow::anyhow!("patch SandboxClaim {claim}: {error}"))?;

        set_workspace_resources(&mut sandbox.data, &compute)?;
        set_docker_data_size(&mut sandbox.data, disk_gb)?;
        sandboxes
            .replace(&sandbox_name, &PostParams::default(), &sandbox)
            .await
            .map_err(|error| anyhow::anyhow!("update Sandbox {sandbox_name}: {error}"))?;

        // Only a private per-environment template follows the resize; a
        // shared warm-pool template (Program #2238 C3) is never written for
        // one environment.
        if let Some(template_name) = self.claim_template_name(env_id).await?
            && !crate::sandbox::warm_pool::is_warm_pool_name(&template_name)
            && template_name.ends_with(&format!("-{env_id}"))
        {
            let templates = self.templates();
            let mut template = templates
                .get(&template_name)
                .await
                .map_err(|error| anyhow::anyhow!("get SandboxTemplate {template_name}: {error}"))?;
            set_workspace_resources(&mut template.data, &compute)?;
            set_workspace_volume_request(&mut template.data, &storage)?;
            set_docker_data_size(&mut template.data, disk_gb)?;
            templates
                .replace(&template_name, &PostParams::default(), &template)
                .await
                .map_err(|error| {
                    anyhow::anyhow!("update SandboxTemplate {template_name}: {error}")
                })?;
        }

        Ok(())
    }

    async fn claim_template_name(&self, env_id: &str) -> anyhow::Result<Option<String>> {
        let Some(claim) = self.get_sandbox_claim(env_id).await? else {
            anyhow::bail!("SandboxClaim {} not found", claim_name(env_id));
        };
        let Some(warm_pool_name) = claim
            .data
            .pointer("/spec/warmPoolRef/name")
            .and_then(Value::as_str)
        else {
            return Ok(None);
        };
        let warm_pool = self
            .warm_pools()
            .get(warm_pool_name)
            .await
            .map_err(|error| anyhow::anyhow!("get SandboxWarmPool {warm_pool_name}: {error}"))?;
        Ok(warm_pool
            .data
            .pointer("/spec/sandboxTemplateRef/name")
            .and_then(Value::as_str)
            .map(str::to_string))
    }

    /// Apply only the PVC request. StorageClass capability was checked before
    /// admission and is rechecked here so a changed class fails closed.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn apply_workspace_storage_resize(
        &self,
        anchor: &WorkspacePvcAnchor,
        desired_disk_gb: i32,
    ) -> anyhow::Result<WorkspaceStorage> {
        let storage = self
            .require_workspace_storage_resize(anchor, desired_disk_gb)
            .await?;
        if desired_disk_gb == storage.requested_disk_gb {
            return Ok(storage);
        }
        // The UID in the patch is a precondition: a same-name substitute
        // created after resolution is refused, never resized.
        let patch = serde_json::json!({
            "metadata": { "uid": storage.pvc_uid },
            "spec": {
                "resources": {
                    "requests": { "storage": format!("{desired_disk_gb}Gi") },
                },
            },
        });
        self.persistent_volume_claims()
            .patch(
                &storage.pvc_name,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
            .map_err(|error| {
                anyhow::anyhow!("expand workspace PVC {}: {error}", storage.pvc_name)
            })?;
        Ok(WorkspaceStorage {
            requested_disk_gb: desired_disk_gb,
            ..storage
        })
    }

    /// Observe PVC expansion before Codewire advances durable applied resources.
    /// A filesystem resize that Kubernetes explicitly defers to Pod restart is
    /// returned to the workflow; this method never replaces the Pod itself.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn wait_for_workspace_storage_resize(
        &self,
        anchor: &WorkspacePvcAnchor,
        desired_disk_gb: i32,
        timeout: Duration,
    ) -> anyhow::Result<WorkspaceStorageResizeOutcome> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let storage = self.workspace_storage(anchor).await?;
            if storage
                .applied_disk_gb
                .is_some_and(|size| size >= desired_disk_gb)
            {
                // A commodity Block device grows under a running guest, but
                // its filesystem grows only in the next Pod's
                // `mount-workspace` (#3718).
                return Ok(if storage.raw_block && !storage.confidential {
                    WorkspaceStorageResizeOutcome::RequiresPodRestart
                } else {
                    WorkspaceStorageResizeOutcome::Applied
                });
            }
            if storage.filesystem_resize_pending {
                return Ok(WorkspaceStorageResizeOutcome::RequiresPodRestart);
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "workspace PVC {} did not report {} Gi capacity before timeout",
                    storage.pvc_name,
                    desired_disk_gb
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Wait for the post-restart filesystem capacity, ignoring the transient
    /// FileSystemResizePending condition which is expected to clear on mount.
    #[tracing::instrument(level = "debug", skip_all)]
    pub async fn wait_for_workspace_storage_capacity(
        &self,
        anchor: &WorkspacePvcAnchor,
        desired_disk_gb: i32,
        timeout: Duration,
    ) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let storage = self.workspace_storage(anchor).await?;
            if storage
                .applied_disk_gb
                .is_some_and(|size| size >= desired_disk_gb)
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "workspace PVC {} did not report {} Gi capacity after Pod restart",
                    storage.pvc_name,
                    desired_disk_gb
                );
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}
