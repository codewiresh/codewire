//! Bringing a suspended workspace's template and Sandbox to the current
//! rendering before it resumes (design §12; B2c for a measured runtime).

use super::*;

impl SandboxClient {
    /// Bring the suspended private template and its allocated Sandbox to the
    /// current rendering before resume. Works while suspended without a Pod.
    /// The caller holds the environment-row publication fence, and owns
    /// suspension and replacement; this never mutates a live Pod.
    #[tracing::instrument(level = "debug", skip_all, fields(environment_id = %opts.environment_id))]
    pub async fn reconcile_workspace_bootstrap(
        &self,
        opts: &TemplateOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected_sandbox: &WorkspaceSandboxIdentity,
    ) -> anyhow::Result<()> {
        // A Sandbox made before hosted egress moves to it first (#4000). The
        // move writes the whole render, and its new generation is not yet
        // the one the suspension was observed at, so nothing else is checked
        // or written.
        if self
            .move_to_hosted_egress(
                opts,
                expected_claim_name,
                expected_claim_uid,
                expected_sandbox,
            )
            .await?
        {
            return Ok(());
        }
        // A confidential workspace publishes its whole measured Pod template
        // (B2c), which also upgrades a legacy one.
        if opts.measured_workspace_environment().is_some() {
            return self
                .reconcile_measured_bootstrap(
                    opts,
                    expected_claim_name,
                    expected_claim_uid,
                    expected_sandbox,
                )
                .await;
        }
        anyhow::ensure!(
            opts.runtime_profile_spec().profile
                != super::super::template::RUNTIME_PROFILE_CONFIDENTIAL,
            "a confidential workspace starts only with its measured binding anchors"
        );
        anyhow::ensure!(
            !opts.workspace_binding_url.trim().is_empty(),
            "a workspace starts only with its binding listener"
        );
        self.reconcile_identity_free_bootstrap(
            opts,
            expected_claim_name,
            expected_claim_uid,
            expected_sandbox,
        )
        .await
    }

    /// Start of a confidential workspace (B2c): publish the measured Pod
    /// template its start just authorized onto the suspended template and
    /// Sandbox, under UID and resourceVersion tests, and check that both carry
    /// it before resume. A start after a release, a roots change or a legacy
    /// rendering therefore boots exactly what Trustee authorizes.
    async fn reconcile_measured_bootstrap(
        &self,
        opts: &TemplateOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected_sandbox: &WorkspaceSandboxIdentity,
    ) -> anyhow::Result<()> {
        let measured = MeasuredPodTemplate::render(&self.namespace, opts)?;
        let before = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&before.sandbox)?;
        anyhow::ensure!(
            !before.shared,
            "a confidential workspace never runs from a shared template"
        );
        anyhow::ensure!(
            sandbox_suspension_observed(&before.sandbox),
            "workspace bootstrap refresh requires current controller-completed suspension"
        );
        for (object, api, egress) in [
            (&before.template, self.templates(), true),
            (&before.sandbox, self.sandboxes(), false),
        ] {
            let Some(patch) = measured.json_patch(object, egress)? else {
                continue;
            };
            let name = object
                .metadata
                .name
                .as_deref()
                .expect("validated runtime name");
            let updated = api
                .patch(name, &PatchParams::default(), &patch)
                .await
                .map_err(|_| anyhow::anyhow!("measured workspace runtime was not admitted"))?;
            anyhow::ensure!(
                runtime_object_uid(&updated.metadata, &self.namespace, name)?
                    == object
                        .metadata
                        .uid
                        .as_deref()
                        .expect("validated runtime UID")
                    && measured.published_on(&updated)
                    && (!egress || measured.egress_published_on(&updated)),
                "measured workspace runtime did not converge"
            );
        }
        let after = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&after.sandbox)?;
        anyhow::ensure!(
            after
                .sandbox
                .data
                .pointer("/spec/operatingMode")
                .and_then(Value::as_str)
                == Some("Suspended")
                && before.pool.metadata.uid == after.pool.metadata.uid
                && before.template.metadata.uid == after.template.metadata.uid
                && before.sandbox.metadata.uid == after.sandbox.metadata.uid
                && measured.published_on(&after.template)
                && measured.egress_published_on(&after.template)
                && measured.published_on(&after.sandbox),
            "measured workspace runtime is no longer current"
        );
        Ok(())
    }

    /// Upgrade on start (design §12): a legacy suspended environment's
    /// template and Sandbox get the whole
    /// identity-free workspace Pod spec (containers, init containers,
    /// volumes, probes, current images) and the template its identity-free
    /// egress. `volumeClaimTemplates` and the Pod template metadata are kept.
    /// Each object is patched under UID and resourceVersion tests; an object
    /// that is already identity-free and current is left alone, so a partly
    /// upgraded environment converges on its next start. The resumed Pod then
    /// binds with `credential_scope='pod'`.
    async fn reconcile_identity_free_bootstrap(
        &self,
        opts: &TemplateOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected_sandbox: &WorkspaceSandboxIdentity,
    ) -> anyhow::Result<()> {
        let before = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&before.sandbox)?;
        anyhow::ensure!(
            sandbox_suspension_observed(&before.sandbox),
            "workspace bootstrap refresh requires current controller-completed suspension"
        );
        // A broker Sandbox keeps its mode (#6070): a direct render under its
        // broker label would leave it hollow, so nothing is written.
        anyhow::ensure!(
            opts.hosted_egress.is_some()
                || !crate::egress::pre_switch::template_whole_broker(
                    before.sandbox.data.pointer("/spec/podTemplate")
                ),
            "a broker-mode workspace is never refreshed with a direct rendering"
        );
        let rendered = render_sandbox_template(&self.namespace, opts);
        let pod_spec = rendered
            .pointer("/spec/podTemplate/spec")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("identity-free workspace rendering has no Pod spec"))?;
        let network_policy = rendered.pointer("/spec/networkPolicy").cloned();
        // A shared pool template serves every member: only the Sandbox is
        // ever patched for one environment.
        let objects = if before.shared {
            vec![(&before.sandbox, self.sandboxes(), None)]
        } else {
            vec![
                (&before.template, self.templates(), network_policy.as_ref()),
                (&before.sandbox, self.sandboxes(), None),
            ]
        };
        for (object, api, network_policy) in objects {
            let Some(patch) = identity_free_upgrade_patch(object, &pod_spec, network_policy)?
            else {
                continue;
            };
            let name = object
                .metadata
                .name
                .as_deref()
                .expect("validated runtime name");
            let updated = api
                .patch(name, &PatchParams::default(), &patch)
                .await
                .map_err(|_| anyhow::anyhow!("workspace identity upgrade was not admitted"))?;
            anyhow::ensure!(
                runtime_object_uid(&updated.metadata, &self.namespace, name)?
                    == object
                        .metadata
                        .uid
                        .as_deref()
                        .expect("validated runtime UID")
                    && workspace_object_identity_free(&updated)?
                    && !workspace_object_has_legacy_codex_home(&updated)?,
                "workspace identity upgrade did not converge"
            );
        }
        let after = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&after.sandbox)?;
        anyhow::ensure!(
            after
                .sandbox
                .data
                .pointer("/spec/operatingMode")
                .and_then(Value::as_str)
                == Some("Suspended")
                && before.pool.metadata.uid == after.pool.metadata.uid
                && before.template.metadata.uid == after.template.metadata.uid
                && before.sandbox.metadata.uid == after.sandbox.metadata.uid
                && workspace_object_identity_free(&after.template)?
                && workspace_object_identity_free(&after.sandbox)?
                // A shared pool template is the reconciler's to rotate, never
                // this environment's to upgrade.
                && (after.shared || !workspace_object_has_legacy_codex_home(&after.template)?)
                && !workspace_object_has_legacy_codex_home(&after.sandbox)?,
            "workspace identity upgrade is no longer current"
        );
        Ok(())
    }
}
