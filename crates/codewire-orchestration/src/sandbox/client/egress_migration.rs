//! A start moves a Sandbox made while hosted egress was off to create's
//! render for its environment (#4000; private-docs `designs/hosted-egress.md`,
//! "Production: migrate on start", with cw-security's conditions on #4000).
//!
//! Only a claimed Sandbox moves, only once its suspension is complete and it
//! has no Pod, and in one patch that replaces its whole pod template with the
//! render, so no write leaves it with part of the broker shape. Admission's
//! Sandbox UPDATE arm holds that patch to the same broker checks a created
//! template passes. Nothing here ever stops a running Sandbox: the start that
//! calls it already did.
//!
//! The sandbox controller holds a claimed Sandbox's pod-template metadata,
//! and the template-reference label its Pod's policies select it by, to the
//! template of the pool its Claim names (the fork's
//! `extensions/controllers/sandboxclaim_controller.go`, the fast path of
//! `reconcileActive`). So the environment's own template moves first: for
//! an environment created cold, its template takes the render; for one
//! adopted from a shared pool, whose pool template stays as it is, the
//! environment gets its own template and zero-replica shadow pool, as a cold
//! create makes them, and its Claim then names that shadow. Only then is the
//! Sandbox patched, with the label that selects it by its own template. The
//! controller's policy for that template selects no Pod until the patch, and
//! the old template's policy none after it. The environment's NetworkPolicy
//! follows the patch, before the start creates the Pod, so the lockdown check
//! reads what it reads for a created Sandbox.
//!
//! The startup re-apply of a broker environment's NetworkPolicy (#6070,
//! `egress::reapply`) is here too.

use serde_json::json;

use super::*;
use crate::egress::admission::{EGRESS_MODE_BROKER, EGRESS_MODE_LABEL};
use crate::egress::confidential_hold::ConfidentialHeld;
use crate::egress::pre_switch::{self, MoveOutcome};
use crate::egress::reapply::PolicyReapply;
use crate::sandbox::warm_pool::{MEMBER_POOL_LABEL, TEMPLATE_REF_HASH_LABEL};

/// Why a start did not move a Sandbox made before hosted egress. Nothing was
/// written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MoveRefused {
    #[error("an unclaimed warm-pool member is replaced, never moved to hosted egress")]
    PoolMember,
    #[error("a Sandbox moves to hosted egress only once its suspension is complete")]
    NotSuspended,
    #[error("a Sandbox moves to hosted egress only while it has no Pod")]
    PodPresent,
    /// The deployment now renders this environment under another runtime,
    /// which would read its disks as that runtime's, and make a `standard`
    /// VM's state afresh over a used workspace (#5602). `none` is no class.
    #[error(
        "this environment runs on the {from} runtime and can't move to hosted egress on the {to} runtime this deployment now uses"
    )]
    RuntimeClassChanged { from: String, to: String },
}

/// A pod template's runtime class, `none` when it names none.
fn runtime_class(spec: Option<&Value>) -> String {
    spec.and_then(|spec| spec.get("runtimeClassName"))
        .and_then(Value::as_str)
        .unwrap_or("none")
        .to_owned()
}

/// The controller's reserved prefixes: the labels it sets on a claimed
/// Sandbox's pod template itself (the claim's UID, its creator and the
/// template reference), which a move keeps.
const CONTROLLER_LABEL_PREFIXES: [&str; 2] = ["agents.x-k8s.io/", "extensions.agents.x-k8s.io/"];

/// A conflicting Sandbox write (a status or label update by the controller)
/// is read and planned again, at most this many times.
const MOVE_ATTEMPTS: usize = 3;

fn broker_mode(object: &DynamicObject) -> bool {
    object
        .data
        .pointer("/spec/podTemplate/metadata/labels")
        .and_then(|labels| labels.get(EGRESS_MODE_LABEL))
        .and_then(Value::as_str)
        == Some(EGRESS_MODE_BROKER)
}

/// The broker label without the rest of the broker shape
/// (`pre_switch::template_whole_broker`, which admission's `wholeBroker`
/// matches). A start moves such a Sandbox as if it had no label.
fn hollow_broker_mode(object: &DynamicObject) -> bool {
    broker_mode(object)
        && !pre_switch::template_whole_broker(object.data.pointer("/spec/podTemplate"))
}

impl SandboxClient {
    /// Apply the environment's NetworkPolicy again where it exists, rendered
    /// as [`Self::ensure_access_stack`] renders it, with the same writer
    /// (#6070, the startup re-apply, `egress::reapply`). One that is absent
    /// stays absent: a stopped environment's went with its access stack, and
    /// its start makes it again.
    pub(crate) async fn reapply_workspace_network_policy(
        &self,
        opts: &TemplateOpts,
    ) -> anyhow::Result<PolicyReapply> {
        if !(opts.network_policy_management.is_empty()
            || opts.network_policy_management == "Managed")
        {
            return Ok(PolicyReapply::Absent);
        }
        let opts = self.resolve_direct_udp_service_opts(opts).await?;
        let name = workspace_daemon_network_policy_name(&opts.environment_id);
        let rendered = render_workspace_daemon_network_policy(&self.namespace, &opts);
        let Some(live) = self
            .network_policies()
            .get_opt(&name)
            .await
            .map_err(|error| anyhow::anyhow!("get NetworkPolicy {name}: {error}"))?
        else {
            return Ok(PolicyReapply::Absent);
        };
        if live.data.get("spec") == rendered.get("spec") {
            return Ok(PolicyReapply::Current);
        }
        self.ensure_dynamic(self.network_policies(), &name, rendered)
            .await?;
        Ok(PolicyReapply::Applied)
    }

    /// With hosted egress on, bring a suspended environment made before it to
    /// create's render. True when the Sandbox moved: its whole pod template
    /// is then the render, so the bootstrap refresh has nothing left to
    /// write. A no-op for one already moved or created under the switch.
    pub(super) async fn move_to_hosted_egress(
        &self,
        opts: &TemplateOpts,
        expected_claim_name: &str,
        expected_claim_uid: &str,
        expected_sandbox: &WorkspaceSandboxIdentity,
    ) -> anyhow::Result<bool> {
        let Some(egress) = opts.hosted_egress.as_ref() else {
            return Ok(false);
        };
        let before = self
            .read_workspace_bootstrap(opts, expected_claim_name, expected_claim_uid)
            .await?;
        expected_sandbox.require_match(&before.sandbox)?;
        let name = before
            .sandbox
            .metadata
            .name
            .clone()
            .ok_or_else(|| anyhow::anyhow!("workspace Sandbox has no name"))?;
        if pre_switch::check_sandbox(true, &name, &before.sandbox.data).is_ok()
            && !hollow_broker_mode(&before.sandbox)
        {
            return Ok(false);
        }
        let result = self
            .move_sandbox(
                opts,
                &before,
                &name,
                expected_claim_name,
                expected_claim_uid,
            )
            .await;
        let outcome = match &result {
            Ok(()) => MoveOutcome::Moved,
            Err(error) if error.is::<MoveRefused>() || error.is::<ConfidentialHeld>() => {
                MoveOutcome::Refused
            }
            Err(_) => MoveOutcome::NotAdmitted,
        };
        pre_switch::count_move(outcome);
        if outcome == MoveOutcome::Moved {
            tracing::info!(
                environment_id = %opts.environment_id,
                sandbox = %name,
                pool_born = before.shared,
                fence_revision = %egress.fence_revision,
                "moved a Sandbox made before hosted egress to it"
            );
        } else {
            tracing::warn!(
                environment_id = %opts.environment_id,
                sandbox = %name,
                pool_born = before.shared,
                outcome = outcome.label(),
                "did not move a Sandbox made before hosted egress to it"
            );
        }
        result?;
        self.ensure_access_stack(opts).await?;
        Ok(true)
    }

    /// The environment's own template, then the one Sandbox patch, fenced by
    /// the Sandbox's UID, resourceVersion and suspension and written only
    /// after a read finds no Pod. A Pod made after that read changes the
    /// Sandbox, so the fence fails.
    async fn move_sandbox(
        &self,
        opts: &TemplateOpts,
        before: &WorkspaceBootstrapSnapshot,
        name: &str,
        expected_claim_name: &str,
        expected_claim_uid: &str,
    ) -> anyhow::Result<()> {
        let sandbox = &before.sandbox;
        // A measured runtime publishes its own whole template (B2c), and a
        // confidential guest can't boot under hosted egress yet.
        if opts.measured_workspace_environment().is_some() {
            return Err(ConfidentialHeld.into());
        }
        let pool_owned = sandbox
            .metadata
            .owner_references
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|owner| owner.kind == "SandboxWarmPool");
        if pool_owned
            || sandbox
                .metadata
                .labels
                .as_ref()
                .is_some_and(|labels| labels.contains_key(MEMBER_POOL_LABEL))
        {
            return Err(MoveRefused::PoolMember.into());
        }
        if !sandbox_suspension_observed(sandbox) {
            return Err(MoveRefused::NotSuspended.into());
        }
        if self.sandbox_pod_exists(sandbox, name).await? {
            return Err(MoveRefused::PodPresent.into());
        }
        let rendered = render_sandbox_template(&self.namespace, opts);
        let (from, to) = (
            runtime_class(sandbox.data.pointer("/spec/podTemplate/spec")),
            runtime_class(rendered.pointer("/spec/podTemplate/spec")),
        );
        if from != to {
            return Err(MoveRefused::RuntimeClassChanged { from, to }.into());
        }
        let uid = runtime_object_uid(&sandbox.metadata, &self.namespace, name)?.to_owned();
        let claim = self
            .get_sandbox_claim(&opts.environment_id)
            .await?
            .filter(|claim| {
                claim.metadata.name.as_deref() == Some(expected_claim_name)
                    && claim.metadata.uid.as_deref() == Some(expected_claim_uid)
            })
            .ok_or_else(|| anyhow::anyhow!("workspace Claim was replaced"))?;
        if before.shared {
            self.create_environment_template(opts).await?;
            let shadow = super::super::shadow_warm_pool_name(&opts.name);
            self.ensure_shadow_pool(&shadow, &opts.name, &opts.environment_id)
                .await?;
            self.point_claim_at(&claim, &shadow).await?;
        } else {
            self.move_template(opts, &before.template).await?;
        }
        let template_hash = sandbox_name_hash(&opts.name);
        let mut current = sandbox.clone();
        let mut conflict = String::new();
        for attempt in 0..MOVE_ATTEMPTS {
            if attempt > 0 {
                current = self
                    .sandboxes()
                    .get(name)
                    .await
                    .map_err(|error| anyhow::anyhow!("get Sandbox {name}: {error}"))?;
                anyhow::ensure!(
                    runtime_object_uid(&current.metadata, &self.namespace, name)? == uid,
                    "Sandbox {name} was replaced during its move to hosted egress"
                );
                // A broker label without the shape (the controller's, were
                // the writer policy absent) is never taken as moved: the
                // patch writes the whole render either way.
                if !sandbox_suspension_observed(&current) {
                    return Err(MoveRefused::NotSuspended.into());
                }
            }
            let version = current
                .metadata
                .resource_version
                .clone()
                .filter(|version| !version.is_empty())
                .ok_or_else(|| anyhow::anyhow!("Sandbox {name} has no resource version"))?;
            let (metadata, spec) =
                moved_pod_template(&current.data, &rendered, &claim.data, &template_hash)?;
            let mut labels = current.metadata.labels.clone().unwrap_or_default();
            labels.insert(TEMPLATE_REF_HASH_LABEL.to_owned(), template_hash.clone());
            if self.sandbox_pod_exists(&current, name).await? {
                return Err(MoveRefused::PodPresent.into());
            }
            let patch = Patch::Json::<()>(serde_json::from_value(json!([
                {"op": "test", "path": "/metadata/uid", "value": uid},
                {"op": "test", "path": "/metadata/resourceVersion", "value": version},
                {"op": "test", "path": "/spec/operatingMode", "value": "Suspended"},
                {"op": "add", "path": "/metadata/labels", "value": labels},
                {"op": "add", "path": "/spec/podTemplate/metadata", "value": metadata},
                {"op": "replace", "path": "/spec/podTemplate/spec", "value": spec},
            ]))?);
            match self
                .sandboxes()
                .patch(name, &PatchParams::default(), &patch)
                .await
            {
                Ok(updated) => {
                    anyhow::ensure!(
                        runtime_object_uid(&updated.metadata, &self.namespace, name)? == uid
                            && broker_mode(&updated),
                        "the move to hosted egress did not converge"
                    );
                    return Ok(());
                }
                // A failed `test` is 422; an apiserver conflict is 409.
                Err(kube::Error::Api(status)) if matches!(status.code, 409 | 422) => {
                    conflict = kube::Error::Api(status).to_string();
                }
                Err(_) => anyhow::bail!("the move to hosted egress was not admitted"),
            }
        }
        anyhow::bail!("the move to hosted egress kept conflicting: {conflict}")
    }

    async fn sandbox_pod_exists(
        &self,
        sandbox: &DynamicObject,
        name: &str,
    ) -> anyhow::Result<bool> {
        Ok(self
            .pods()
            .get_opt(sandbox_pod_name(sandbox, name))
            .await
            .map_err(|error| anyhow::anyhow!("read the Pod of Sandbox {name}: {error}"))?
            .is_some())
    }

    /// A pool-born environment's own template, as a cold create makes it.
    /// One a failed earlier start already made is moved like a cold one's.
    async fn create_environment_template(&self, opts: &TemplateOpts) -> anyhow::Result<()> {
        let template = match self.templates().get_opt(&opts.name).await {
            Ok(template) => template,
            Err(error) => anyhow::bail!("get SandboxTemplate {}: {error}", opts.name),
        };
        if let Some(template) = template {
            require_bootstrap_object(&template, &self.namespace, &opts.name, "SandboxTemplate")?;
            self.move_template(opts, &template).await?;
            return Ok(());
        }
        let rendered: DynamicObject =
            serde_json::from_value(render_sandbox_template(&self.namespace, opts))?;
        self.templates()
            .create(&PostParams::default(), &rendered)
            .await
            .map_err(|_| {
                anyhow::anyhow!("the environment's own template for hosted egress was not admitted")
            })?;
        Ok(())
    }

    /// A pool-born environment's Claim names its own shadow pool from now on,
    /// so the controller holds its Sandbox to the environment's template, not
    /// the shared pool's. Fenced by the Claim's UID and resourceVersion and the
    /// pool it named.
    async fn point_claim_at(&self, claim: &DynamicObject, shadow: &str) -> anyhow::Result<()> {
        let selected = claim
            .data
            .pointer("/spec/warmPoolRef/name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if selected == shadow {
            return Ok(());
        }
        let name = claim
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("workspace Claim has no name"))?;
        let patch = Patch::Json::<()>(serde_json::from_value(json!([
            {"op": "test", "path": "/metadata/uid", "value": claim.metadata.uid},
            {"op": "test", "path": "/metadata/resourceVersion", "value": claim.metadata.resource_version},
            {"op": "test", "path": "/spec/warmPoolRef/name", "value": selected},
            {"op": "replace", "path": "/spec/warmPoolRef/name", "value": shadow},
        ]))?);
        self.claims
            .patch(name, &PatchParams::default(), &patch)
            .await
            .map_err(|_| {
                anyhow::anyhow!("the Claim's move to its own template was not admitted")
            })?;
        Ok(())
    }

    /// The environment's own template takes create's render too, so the
    /// policy the controller makes from it is the one the lockdown check
    /// renders. True when it was patched.
    async fn move_template(
        &self,
        opts: &TemplateOpts,
        template: &DynamicObject,
    ) -> anyhow::Result<bool> {
        if broker_mode(template) {
            return Ok(false);
        }
        let name = template
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("workspace template has no name"))?;
        let uid = runtime_object_uid(&template.metadata, &self.namespace, name)?.to_owned();
        let version = template
            .metadata
            .resource_version
            .as_deref()
            .filter(|version| !version.is_empty())
            .ok_or_else(|| anyhow::anyhow!("workspace template has no resource version"))?;
        let rendered = render_sandbox_template(&self.namespace, opts);
        let mut operations = vec![
            json!({"op": "test", "path": "/metadata/uid", "value": uid}),
            json!({"op": "test", "path": "/metadata/resourceVersion", "value": version}),
            json!({"op": "replace", "path": "/spec/podTemplate", "value": rendered["spec"]["podTemplate"]}),
            json!({"op": "add", "path": "/spec/networkPolicy", "value": rendered["spec"]["networkPolicy"]}),
        ];
        if let Some(management) = rendered.pointer("/spec/networkPolicyManagement") {
            operations.push(
                json!({"op": "add", "path": "/spec/networkPolicyManagement", "value": management}),
            );
        }
        let patch = Patch::Json::<()>(serde_json::from_value(Value::Array(operations))?);
        let updated = self
            .templates()
            .patch(name, &PatchParams::default(), &patch)
            .await
            .map_err(|_| {
                anyhow::anyhow!("the template's move to hosted egress was not admitted")
            })?;
        anyhow::ensure!(
            runtime_object_uid(&updated.metadata, &self.namespace, name)? == uid
                && broker_mode(&updated),
            "the template's move to hosted egress did not converge"
        );
        Ok(true)
    }
}

/// The pod template a moved Sandbox gets: `rendered`'s whole Pod spec, with
/// what the Sandbox has recorded of its own disks ([`keep_disk_state`]); and
/// the metadata the controller computes for a claimed Sandbox from its
/// template (the fork's `sandboxclaim_controller.go`, `reconcileActive`):
/// `rendered`'s labels and annotations, the controller's own labels the
/// Sandbox carries, the Claim's `additionalPodMetadata`, and the reference to
/// the environment's own template, `template_hash`. So the controller has
/// nothing to put back, and the label the old template's policy selected by
/// is gone.
fn moved_pod_template(
    sandbox: &Value,
    rendered: &Value,
    claim: &Value,
    template_hash: &str,
) -> anyhow::Result<(Value, Value)> {
    let template = rendered
        .pointer("/spec/podTemplate")
        .ok_or_else(|| anyhow::anyhow!("the render has no pod template"))?;
    let mut spec = template["spec"].clone();
    if let Some(current) = sandbox.pointer("/spec/podTemplate/spec") {
        keep_disk_state(current, &mut spec)?;
    }
    let mut labels = template["metadata"]["labels"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    let mut annotations = template["metadata"]["annotations"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    if let Some(current) = sandbox
        .pointer("/spec/podTemplate/metadata/labels")
        .and_then(Value::as_object)
    {
        for (key, value) in current {
            if CONTROLLER_LABEL_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix))
            {
                labels.insert(key.clone(), value.clone());
            }
        }
    }
    for (field, into) in [("labels", &mut labels), ("annotations", &mut annotations)] {
        if let Some(extra) = claim
            .pointer(&format!("/spec/additionalPodMetadata/{field}"))
            .and_then(Value::as_object)
        {
            into.extend(
                extra
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
        }
    }
    labels.insert(TEMPLATE_REF_HASH_LABEL.to_owned(), json!(template_hash));
    Ok((json!({"labels": labels, "annotations": annotations}), spec))
}

/// A Sandbox whose workspace volume or `standard` VM state was already
/// marked `existing` keeps the mark: a render reads `new` for a volume that
/// isn't a restore, and a moved Sandbox must never format its disk
/// (#3718) or create its VM state afresh (#5602).
fn keep_disk_state(current: &Value, moved: &mut Value) -> anyhow::Result<()> {
    let mount_state = |spec: &Value| {
        spec["initContainers"].as_array().and_then(|inits| {
            inits
                .iter()
                .position(|init| init["name"] == MOUNT_WORKSPACE_CONTAINER)
        })
    };
    // As `workspace_volume_existing` reads it: the state only where the
    // command names mount-workspace's own script.
    if let (Some(from), Some(to)) = (mount_state(current), mount_state(moved))
        && current["initContainers"][from]["command"][3] == MOUNT_WORKSPACE_CONTAINER
        && current["initContainers"][from]["command"][4]
            .as_str()
            .and_then(WorkspaceVolume::parse_argument)
            == Some(WorkspaceVolume::Existing)
    {
        let argument = moved["initContainers"][to]["command"]
            .get_mut(4)
            .ok_or_else(|| anyhow::anyhow!("the render's mount-workspace has no volume state"))?;
        *argument = json!(WorkspaceVolume::Existing.argument());
    }
    let vm_state = |spec: &Value| {
        spec["containers"].as_array().and_then(|containers| {
            containers
                .iter()
                .position(|container| container["name"] == "workspace")
                .and_then(|index| {
                    containers[index]["env"].as_array().and_then(|env| {
                        env.iter()
                            .position(|entry| {
                                entry["name"] == codewire_daemon_proto::POD_RUNTIME_VM_STATE_ENV
                            })
                            .map(|entry| (index, entry))
                    })
                })
        })
    };
    if let (Some((from, from_entry)), Some((to, to_entry))) = (vm_state(current), vm_state(moved))
        && current["containers"][from]["env"][from_entry]["value"]
            == codewire_daemon_proto::POD_RUNTIME_VM_STATE_EXISTING
    {
        moved["containers"][to]["env"][to_entry]["value"] =
            json!(codewire_daemon_proto::POD_RUNTIME_VM_STATE_EXISTING);
    }
    Ok(())
}

#[cfg(test)]
#[path = "egress_migration_tests.rs"]
mod tests;
