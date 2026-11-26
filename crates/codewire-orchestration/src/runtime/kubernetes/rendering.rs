//! How the Kubernetes driver turns a [`RenderingIntent`] into the options its
//! templates render from (#3628 PR 8b). The intent is the environment's; every
//! deployment-wide setting is this driver's own [`KubernetesRenderConfig`].

use crate::egress::own_mode::{HostedEgress, SandboxMode};
use crate::runtime::{Isolation, RenderingIntent, WorkspaceShape};
use crate::sandbox::environment_template_name;
use crate::sandbox::template::{
    CpuSharingRatio, CredentialRuntimeTemplateConfig, DOCKER_MODE_LOCAL_DIND_DIRECT,
    HostedEgressTemplate, RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL,
    RUNTIME_PROFILE_NONE, RUNTIME_PROFILE_RUNC, RUNTIME_PROFILE_STANDARD, RuntimeProfileSpec,
    StandardRuntime, TemplateOpts, WORKSPACE_KEEPALIVE_COMMAND, render_template_network_policy,
    render_warm_member_bridge, render_workspace_daemon_network_policy, runtime_profile_spec,
    validate_managed_runtime_profile,
};
use crate::sandbox::{
    CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME, canonical_workspace_runtime_image,
    is_canonical_workspace_runtime_image,
};

/// Everything deployment-wide a workspace renders with. Orchestration builds
/// it from its configuration once; the driver holds it.
#[derive(Clone, Debug, Default)]
pub struct KubernetesRenderConfig {
    pub credential_runtime: Option<CredentialRuntimeTemplateConfig>,
    pub daemon_image: String,
    pub dind_image: String,
    /// The runtime of a standard-tier environment.
    pub runtime_profile: String,
    /// Optional runtime profile override for shared warm pools (empty uses
    /// `runtime_profile`).
    pub warm_pool_runtime_profile: String,
    pub docker_mode: String,
    pub dind_enabled: bool,
    /// Diagnostic runtimes, and unpinned pool images, are allowed.
    pub allow_diagnostic_runtime: bool,
    pub workspace_storage_class: String,
    /// A confidential environment's raw Block claim class; empty refuses
    /// confidential renderings.
    pub confidential_workspace_storage_class: String,
    /// The binding listener's roots a confidential workspace measures.
    pub confidential_binding_roots_pem: String,
    /// The listener every hosted workspace binds through; empty when this
    /// deployment can't bind identity-free workspaces.
    pub workspace_binding_url: String,
    pub api_base_url: String,
    pub coordinator_url: String,
    pub server_namespace: String,
    pub coordinator_extra_roots: bool,
    pub codex_login_check_period_seconds: Option<u64>,
    pub ingress_namespace: String,
    pub ingress_pod_name: String,
    pub egress_bandwidth: String,
    pub derp_host: String,
    /// The hosted egress switch, which decides what a create renders, and
    /// the broker settings every broker Sandbox renders from whatever the
    /// switch says (`egress::settings::startup`, #6070).
    pub hosted_egress: HostedEgress,
    /// What a `standard` workspace runs; `None` where none is configured.
    pub standard_runtime: Option<StandardRuntime>,
    pub derp_port: i64,
    pub stun_host: String,
    pub stun_port: i64,
    pub stun_servers: String,
    pub direct_udp_lb_enabled: bool,
    pub direct_udp_lb_ip: String,
    pub direct_udp_lb_port_start: i64,
    pub direct_udp_lb_port_end: i64,
    pub direct_udp_lb_class: String,
    pub direct_udp_lb_sharing_key: String,
    pub direct_udp_transport_zone: String,
    pub udp_relay_allocator_url: String,
    pub udp_relay_bind_addrs: String,
    /// Relays come from the runtime transport registry, not fixed settings.
    pub uses_runtime_transport_registry: bool,
    pub cpu_sharing_ratio: CpuSharingRatio,
    pub network_policy_management: String,
    pub kata_agent_policy_enabled: bool,
    pub kata_coco_init_data_enabled: bool,
    pub kata_coco_kbs_url: String,
    pub kata_coco_kbs_ca_pem: String,
    pub kata_coco_kbs_peer: Option<crate::sandbox::template::KbsPeer>,
    pub kata_coco_image_registry_auth_uri: String,
    pub kata_coco_test_resource_uri: String,
    pub kata_coco_test_resource_path: String,
    pub debug_tailnet: bool,
}

/// `egress` on a VM runtime profile, the only ones broker mode runs on; none
/// on another profile.
fn on_vm(profile: &str, egress: Option<&HostedEgressTemplate>) -> Option<HostedEgressTemplate> {
    egress
        .filter(|_| {
            matches!(
                profile,
                RUNTIME_PROFILE_COMMODITY | RUNTIME_PROFILE_CONFIDENTIAL | RUNTIME_PROFILE_STANDARD
            )
        })
        .cloned()
}

/// Codewire base images supervise the daemon beneath PID 1.
fn is_first_party_workspace_image(image_ref: &str) -> bool {
    image_ref.contains("codewiresh/workspace-")
        || image_ref.contains("codewiresh/base")
        || image_ref.contains("codewiresh/workspace")
}

impl KubernetesRenderConfig {
    /// Whether this deployment can have running `standard` Pods, either by
    /// default, through warm pools, or through per-organization selection (#6333).
    pub fn may_have_standard_pods(&self) -> bool {
        self.standard_runtime.is_some()
            || self.runtime_profile.trim() == RUNTIME_PROFILE_STANDARD
            || self.warm_pool_runtime_profile.trim() == RUNTIME_PROFILE_STANDARD
    }

    /// The runtime an isolation runs on here.
    pub fn runtime_spec(&self, isolation: Isolation) -> RuntimeProfileSpec {
        match isolation {
            Isolation::Standard => {
                runtime_profile_spec(&self.runtime_profile, &self.docker_mode, self.dind_enabled)
            }
            Isolation::Confidential => runtime_profile_spec(
                RUNTIME_PROFILE_CONFIDENTIAL,
                &self.docker_mode,
                self.dind_enabled,
            ),
        }
    }

    /// Whether the runtime `intent` runs on is a managed one, or a diagnostic
    /// one this deployment allows.
    pub fn check_runtime_profile(&self, intent: &RenderingIntent) -> Result<(), String> {
        validate_managed_runtime_profile(
            &self.environment_spec(intent),
            self.allow_diagnostic_runtime,
        )
    }

    /// The runtime spec of the options `intent` renders, as
    /// [`TemplateOpts::runtime_profile_spec`] resolves it.
    fn environment_spec(&self, intent: &RenderingIntent) -> RuntimeProfileSpec {
        self.shape(
            &intent.image,
            &self.intent_runtime_spec(intent),
            intent.shape,
        )
        .runtime_profile_spec()
    }

    /// The runtime `intent` renders on: the profile its create recorded
    /// (`environments.runtime_profile`, #5602), never the deployment's
    /// current default or `standard` disk, so neither moves it on a restart.
    fn intent_runtime_spec(&self, intent: &RenderingIntent) -> RuntimeProfileSpec {
        let spec = self.runtime_spec(intent.isolation);
        // Confidential stays confidential, as its record says (0056's check).
        if intent.isolation == Isolation::Confidential {
            return spec;
        }
        let recorded = intent.runtime_profile.trim();
        // A local Kind deployment's diagnostic profile has no VM runtime, so
        // it renders a `commodity` record, as 0056's backfill wrote it, on
        // its own profile.
        let diagnostic = matches!(
            spec.profile.as_str(),
            RUNTIME_PROFILE_RUNC | RUNTIME_PROFILE_NONE
        );
        if recorded == spec.profile || (diagnostic && recorded == RUNTIME_PROFILE_COMMODITY) {
            return spec;
        }
        runtime_profile_spec(recorded, &self.docker_mode, self.dind_enabled)
    }

    /// The runtime a warm pool member of `image` renders on: the pool's
    /// configured profile ([`crate::sandbox::template::runtime_profile_of`]).
    fn pool_image_runtime_spec(
        &self,
        configured: &RuntimeProfileSpec,
        image: &str,
    ) -> RuntimeProfileSpec {
        let profile = crate::sandbox::template::runtime_profile_of(
            &configured.profile,
            self.standard_runtime.as_ref(),
            image,
        );
        if profile != configured.profile {
            return runtime_profile_spec(profile, &self.docker_mode, self.dind_enabled);
        }
        configured.clone()
    }

    /// The environment's own rendering: its identity on top of the cluster
    /// and shape inputs of [`Self::shape`].
    pub fn environment(&self, intent: &RenderingIntent) -> anyhow::Result<TemplateOpts> {
        let identity = &intent.identity;
        anyhow::ensure!(
            identity.projection_selection_sha256.is_none() || self.credential_runtime.is_some(),
            "selected environment sources require credential runtime trust"
        );
        let runtime_spec = self.intent_runtime_spec(intent);
        // A record unlike the deployment's own profile renders only a managed
        // runtime, or a diagnostic one this deployment allows: every write, a
        // create's or an existing environment's, comes through here. The
        // deployment's own profile is checked where it is configured.
        if runtime_spec.profile != self.runtime_spec(intent.isolation).profile {
            validate_managed_runtime_profile(&runtime_spec, self.allow_diagnostic_runtime)
                .map_err(anyhow::Error::msg)?;
        }
        // An environment created on `standard` keeps it: once the deployment
        // no longer makes it available, its start is refused, never rendered
        // onto another profile.
        anyhow::ensure!(
            runtime_spec.profile != RUNTIME_PROFILE_STANDARD || self.standard_runtime.is_some(),
            "this environment was created on the standard runtime, which this deployment no \
             longer makes available"
        );
        // A confidential claim is the guest-encrypted raw Block volume of its
        // own class; without one the environment is refused, never given the
        // commodity class.
        anyhow::ensure!(
            runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL
                || !self.confidential_workspace_storage_class.is_empty(),
            "confidential workspace storage has no StorageClass: set {}",
            crate::sandbox::template::CONFIDENTIAL_WORKSPACE_STORAGE_CLASS_ENV
        );
        // A systemd workspace renders from its record, and only while the
        // deployment still offers it on the profile it renders on, with its
        // organization's opt-in where that profile needs one: otherwise its
        // Pod is refused, never rendered as a plain custom image
        // (docs/dev/SYSTEMD-WORKSPACE.md, "Where it is checked").
        if intent.systemd_workspace
            && let Some(refusal) = crate::sandbox::systemd_workspace::bring_up_refusal(
                crate::sandbox::runtime_images::configured(),
                &intent.image,
                match intent.isolation {
                    Isolation::Standard => "standard",
                    Isolation::Confidential => "confidential",
                },
                &runtime_spec.profile,
                intent.systemd_opted_in,
            )
        {
            anyhow::bail!(refusal.detail);
        }
        let template_base = if is_canonical_workspace_runtime_image(&intent.image) {
            CANONICAL_WORKSPACE_RUNTIME_TEMPLATE_NAME
        } else {
            intent.template_base.as_str()
        };
        // A confidential workspace measures the roots its daemon trusts (B2c);
        // without them no confidential rendering exists.
        anyhow::ensure!(
            runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL
                || !self.confidential_binding_roots_pem.trim().is_empty(),
            "confidential workspaces need orchestration's internal TLS roots to measure"
        );

        let opts = TemplateOpts {
            name: environment_template_name(template_base, &identity.environment_id),
            environment_id: identity.environment_id.clone(),
            organization_id: identity.organization_id.clone(),
            operation_generation: identity.operation_generation,
            projection_selection_sha256: identity.projection_selection_sha256,
            managed_credential_clients: identity.managed_credential_clients,
            confidential_storage_manifest_uri: identity.confidential_storage_manifest_uri.clone(),
            codex_login_check_period_seconds: self.codex_login_check_period_seconds,
            workspace_source_snapshot: identity
                .source_snapshot_id
                .as_deref()
                .map(crate::sandbox::snapshots::kept_snapshot_name),
            systemd_workspace: intent.systemd_workspace,
            ..self.shape(&intent.image, &runtime_spec, intent.shape)
        };
        let opts = if intent.dedicated_cpu {
            TemplateOpts {
                cpu_sharing: CpuSharingRatio::NONE,
                ..opts
            }
        } else {
            opts
        };
        // Its binding listener is one of the measured anchors: a confidential
        // rendering without one is refused here, never rendered.
        anyhow::ensure!(
            runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL
                || !opts.workspace_binding_url.trim().is_empty(),
            "confidential workspaces need the workspace binding listener to measure"
        );
        opts.validate_standard_runtime()?;
        Ok(opts)
    }

    /// [`Self::environment`] for a write to an environment whose Sandbox is
    /// `sandbox`: its hosted egress follows that Sandbox's own mode, never the
    /// switch (#6070). A broker Sandbox renders broker mode from the broker
    /// settings, or is refused without them; any other renders direct. With
    /// no Sandbox it is a create's.
    pub fn existing(
        &self,
        intent: &RenderingIntent,
        sandbox: Option<&SandboxMode>,
    ) -> anyhow::Result<TemplateOpts> {
        self.as_sandbox(self.environment(intent)?, sandbox)
    }

    /// [`Self::pool`] as the pool `member` was born of rendered it: in the
    /// member's own egress mode, so a member claimed before a switch and
    /// bound after it is judged by its own pool revision (#6070). A broker
    /// member without the broker settings is refused.
    pub fn pool_of(
        &self,
        shape: WorkspaceShape,
        member: &SandboxMode,
    ) -> anyhow::Result<TemplateOpts> {
        self.as_sandbox(self.pool(shape)?, Some(member))
    }

    fn as_sandbox(
        &self,
        opts: TemplateOpts,
        sandbox: Option<&SandboxMode>,
    ) -> anyhow::Result<TemplateOpts> {
        let Some(sandbox) = sandbox else {
            return Ok(opts);
        };
        Ok(TemplateOpts {
            hosted_egress: self.hosted_egress.existing(sandbox)?.cloned(),
            ..opts
        })
    }

    /// The NetworkPolicy a broker Sandbox's access stack applies, as the
    /// egress lockdown check expects to read it back (#4000 P6), or `None`
    /// when this deployment leaves workspace NetworkPolicies to someone else. Of an
    /// environment's own inputs the policy reads only its ID and isolation,
    /// so it renders from those; a new per-environment input must be added
    /// here too, which the test beside this file holds.
    pub fn workspace_network_policy(
        &self,
        namespace: &str,
        environment_id: &str,
        isolation: Isolation,
    ) -> Option<serde_json::Value> {
        self.workspace_policy_opts(environment_id, isolation)
            .map(|opts| render_workspace_daemon_network_policy(namespace, &opts))
    }

    /// The bridge an adopted warm member of `environment_id` carries (#2434),
    /// selecting the member whose Sandbox UID the binding recorded, as the
    /// egress lockdown check expects to read it back; `None` when this
    /// deployment leaves workspace NetworkPolicies to someone else, or the
    /// binding recorded no Sandbox UID. It grants the environment policy's
    /// ingress, from the same inputs.
    pub fn warm_member_bridge(
        &self,
        namespace: &str,
        environment_id: &str,
        isolation: Isolation,
        sandbox_uid: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        if sandbox_uid.is_empty() {
            return Ok(None);
        }
        self.workspace_policy_opts(environment_id, isolation)
            .map(|opts| render_warm_member_bridge(namespace, &opts, sandbox_uid))
            .transpose()
    }

    /// The options a broker Sandbox's own NetworkPolicies render from, or
    /// `None` when this deployment leaves them to someone else.
    fn workspace_policy_opts(
        &self,
        environment_id: &str,
        isolation: Isolation,
    ) -> Option<TemplateOpts> {
        if !self.network_policy_management.is_empty() && self.network_policy_management != "Managed"
        {
            return None;
        }
        let opts = self.broker_shape(isolation);
        Some(TemplateOpts {
            environment_id: environment_id.to_owned(),
            // The policies read whether a direct UDP port is allocated, never
            // which, and the access stack allocates one for every environment
            // where the LoadBalancer is enabled.
            direct_udp_lb_port: i64::from(opts.direct_udp_lb_enabled),
            ..opts
        })
    }

    /// The NetworkPolicy the sandbox controller makes from a broker workspace
    /// template of `isolation`, selecting the Sandboxes whose template hash is
    /// `template_ref_hash`, as the egress lockdown check expects to read it
    /// back (#4964), or `None` when this deployment leaves workspace
    /// NetworkPolicies to someone else. The template's rules read only this
    /// configuration and the runtime profile, never a shape or an
    /// environment, so every template of one isolation has the same policy.
    pub fn template_network_policy(
        &self,
        isolation: Isolation,
        template_ref_hash: &str,
    ) -> Option<serde_json::Value> {
        if !self.network_policy_management.is_empty() && self.network_policy_management != "Managed"
        {
            return None;
        }
        Some(render_template_network_policy(
            &self.broker_shape(isolation),
            template_ref_hash,
        ))
    }

    /// The shape inputs a broker guest's policies render from, as the egress
    /// lockdown check expects them: broker mode from the broker settings,
    /// whatever the switch says (#6070), since only a guest whose Sandbox is
    /// whole broker is ever checked. No shape or environment is read.
    fn broker_shape(&self, isolation: Isolation) -> TemplateOpts {
        let runtime_spec = self.runtime_spec(isolation);
        let opts = self.shape(
            canonical_workspace_runtime_image(),
            &runtime_spec,
            WorkspaceShape {
                cpu_millicores: 0,
                memory_mib: 0,
                disk_gib: 0,
            },
        );
        TemplateOpts {
            hosted_egress: on_vm(&runtime_spec.profile, self.hosted_egress.broker.as_ref()),
            ..opts
        }
    }

    /// The identity-free inputs of one warm-pool shape (Program #2238 C1): the
    /// canonical workspace image on the standard tier, from the shape and this
    /// configuration alone. A confidential runtime, a diagnostic runtime
    /// outside diagnostic clusters, a `standard` runtime whose disk does not
    /// boot the canonical image and a configuration that cannot render
    /// identity-free workspaces render no pool.
    pub fn pool(&self, shape: WorkspaceShape) -> anyhow::Result<TemplateOpts> {
        let configured = if self.warm_pool_runtime_profile.trim().is_empty() {
            self.runtime_spec(Isolation::Standard)
        } else {
            runtime_profile_spec(
                &self.warm_pool_runtime_profile,
                &self.docker_mode,
                self.dind_enabled,
            )
        };
        anyhow::ensure!(
            configured.profile != RUNTIME_PROFILE_CONFIDENTIAL,
            "confidential workspaces are never pooled"
        );
        // A pool member must render exactly as the environment that adopts
        // it: the canonical image's own runtime, as `environment` picks it.
        // On a `standard` pool whose disk does not boot that image the
        // environment goes to `commodity`, so no member would ever be
        // adopted (#5602).
        let image = canonical_workspace_runtime_image();
        let runtime_spec = self.pool_image_runtime_spec(&configured, image);
        anyhow::ensure!(
            runtime_spec.profile == configured.profile,
            "the standard disk does not boot the canonical workspace image, so no standard member could be adopted"
        );
        validate_managed_runtime_profile(&runtime_spec, self.allow_diagnostic_runtime)
            .map_err(|error| anyhow::anyhow!("warm pool runtime profile: {error}"))?;
        let opts = self.shape(image, &runtime_spec, shape);
        anyhow::ensure!(
            !opts.workspace_binding_url.is_empty(),
            "warm pools require identity-free workspaces (POD_NAMESPACE and a coordinator)"
        );
        // A pool never renders what a create would refuse.
        opts.validate_standard_runtime()?;
        Ok(opts)
    }

    /// The cluster and shape inputs of a workspace rendering, with no
    /// environment identity: images, runtime, resources, storage, transport
    /// and the identity mode. Every field is listed, so a new one must be
    /// placed on one side or the other.
    pub(crate) fn shape(
        &self,
        image_ref: &str,
        runtime_spec: &RuntimeProfileSpec,
        shape: WorkspaceShape,
    ) -> TemplateOpts {
        // Codewire base images supervise the daemon beneath PID 1. Custom
        // images also retain a keepalive alongside that managed daemon.
        let image_command = if is_first_party_workspace_image(image_ref) {
            Vec::new()
        } else {
            WORKSPACE_KEEPALIVE_COMMAND.map(str::to_owned).to_vec()
        };
        let confidential = runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL;

        TemplateOpts {
            // Environment identity: none.
            name: String::new(),
            environment_id: String::new(),
            organization_id: String::new(),
            operation_generation: 0,
            projection_selection_sha256: None,
            managed_credential_clients: Default::default(),
            confidential_storage_manifest_uri: String::new(),
            // Cluster and shape.
            measured_binding_roots: if confidential {
                self.confidential_binding_roots_pem.clone()
            } else {
                String::new()
            },
            image: image_ref.to_string(),
            image_command,
            // Only an environment's own rendering is one, from its record.
            systemd_workspace: false,
            support_image: self.daemon_image.clone(),
            dind_image: self.dind_image.clone(),
            // Hosted egress (#4000): with the switch on, every template a
            // create renders on a VM runtime profile is broker-mode.
            hosted_egress: on_vm(&runtime_spec.profile, self.hosted_egress.create()),
            standard_runtime: self
                .standard_runtime
                .clone()
                .filter(|_| runtime_spec.profile == RUNTIME_PROFILE_STANDARD),
            runtime_profile: runtime_spec.profile.clone(),
            docker_mode: runtime_spec.docker_mode.clone(),
            credential_runtime: self.credential_runtime.clone(),
            workspace_binding_url: self.workspace_binding_url.clone(),
            api_base_url: self.api_base_url.clone(),
            coordinator_url: self.coordinator_url.clone(),
            server_namespace: self.server_namespace.clone(),
            coordinator_extra_roots: self.coordinator_extra_roots,
            ingress_namespace: self.ingress_namespace.clone(),
            ingress_pod_name: self.ingress_pod_name.clone(),
            egress_bandwidth: self.egress_bandwidth.clone(),
            // Kind's test deployment only, and the same as an environment's
            // own rendering: a pool member must render exactly as the
            // environment that adopts it, or every create of its shape routes
            // cold (#3852).
            codex_login_check_period_seconds: self.codex_login_check_period_seconds,
            derp_host: self.derp_host.clone(),
            derp_port: self.derp_port,
            stun_host: self.stun_host.clone(),
            stun_port: self.stun_port,
            stun_servers: self.stun_servers.clone(),
            direct_udp_lb_enabled: self.direct_udp_lb_enabled
                && matches!(
                    runtime_spec.profile.as_str(),
                    RUNTIME_PROFILE_COMMODITY | RUNTIME_PROFILE_CONFIDENTIAL
                ),
            direct_udp_lb_ip: self.direct_udp_lb_ip.clone(),
            direct_udp_lb_port: 0,
            direct_udp_lb_port_start: self.direct_udp_lb_port_start,
            direct_udp_lb_port_end: self.direct_udp_lb_port_end,
            direct_udp_lb_class: self.direct_udp_lb_class.clone(),
            direct_udp_lb_sharing_key: self.direct_udp_lb_sharing_key.clone(),
            direct_udp_transport_zone: self.direct_udp_transport_zone.clone(),
            udp_relay_allocator_url: if self.uses_runtime_transport_registry {
                String::new()
            } else {
                self.udp_relay_allocator_url.clone()
            },
            udp_relay_bind_addrs: if self.uses_runtime_transport_registry {
                String::new()
            } else {
                self.udp_relay_bind_addrs.clone()
            },
            udp_relay_allocator_egress_enabled: self.uses_runtime_transport_registry,
            cpu_millicores: shape.cpu_millicores,
            // Nothing has measured a confidential VM under sharing.
            cpu_sharing: if confidential {
                CpuSharingRatio::NONE
            } else {
                self.cpu_sharing_ratio
            },
            memory_mib: shape.memory_mib,
            disk_gib: shape.disk_gib,
            workspace_source_snapshot: None,
            workspace_storage_class: if confidential {
                self.confidential_workspace_storage_class.clone()
            } else {
                self.workspace_storage_class.clone()
            },
            network_policy_management: self.network_policy_management.clone(),
            dind_enabled: runtime_spec.docker_mode == DOCKER_MODE_LOCAL_DIND_DIRECT,
            kata_agent_policy_enabled: self.kata_agent_policy_enabled,
            kata_coco_init_data_enabled: self.kata_coco_init_data_enabled,
            kata_coco_kbs_url: self.kata_coco_kbs_url.clone(),
            kata_coco_kbs_ca_pem: self.kata_coco_kbs_ca_pem.clone(),
            kata_coco_kbs_peer: self.kata_coco_kbs_peer.clone(),
            kata_coco_image_registry_auth_uri: self.kata_coco_image_registry_auth_uri.clone(),
            kata_coco_test_resource_uri: self.kata_coco_test_resource_uri.clone(),
            kata_coco_test_resource_path: self.kata_coco_test_resource_path.clone(),
            debug_tailnet: self.debug_tailnet,
        }
    }
}

#[cfg(test)]
mod tests;
