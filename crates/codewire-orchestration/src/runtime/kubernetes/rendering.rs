//! How the Kubernetes driver turns a [`RenderingIntent`] into the options its
//! templates render from (#3628 PR 8b). The intent is the environment's; every
//! deployment-wide setting is this driver's own [`KubernetesRenderConfig`].

use crate::runtime::{Isolation, RenderingIntent, WorkspaceShape};
use crate::sandbox::environment_template_name;
use crate::sandbox::template::{
    CpuSharingRatio, CredentialRuntimeTemplateConfig, DOCKER_MODE_LOCAL_DIND_DIRECT,
    HostedEgressTemplate, RUNTIME_PROFILE_COMMODITY, RUNTIME_PROFILE_CONFIDENTIAL,
    RUNTIME_PROFILE_STANDARD, RuntimeProfileSpec, StandardRuntime, TemplateOpts,
    WORKSPACE_KEEPALIVE_COMMAND, render_template_network_policy, render_warm_member_bridge,
    render_workspace_daemon_network_policy, runtime_profile_spec, validate_managed_runtime_profile,
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
    /// What a broker-mode template renders, read at startup while hosted
    /// egress is on (`egress::settings::startup`); `None` off.
    pub hosted_egress: Option<HostedEgressTemplate>,
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

/// Codewire base images supervise the daemon beneath PID 1.
fn is_first_party_workspace_image(image_ref: &str) -> bool {
    image_ref.contains("codewiresh/workspace-")
        || image_ref.contains("codewiresh/base")
        || image_ref.contains("codewiresh/workspace")
}

impl KubernetesRenderConfig {
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

    /// The runtime `intent` renders on. A systemd workspace renders on the
    /// profile its create recorded
    /// ([`crate::sandbox::systemd_workspace::existing_profile`]); any other
    /// environment on [`Self::image_runtime_spec`].
    fn intent_runtime_spec(&self, intent: &RenderingIntent) -> RuntimeProfileSpec {
        if !intent.systemd_workspace {
            return self.image_runtime_spec(intent.isolation, &intent.image);
        }
        let spec = self.runtime_spec(intent.isolation);
        let profile = crate::sandbox::systemd_workspace::existing_profile(
            &spec.profile,
            intent.systemd_runtime_profile.as_deref(),
        );
        if profile != spec.profile {
            return runtime_profile_spec(profile, &self.docker_mode, self.dind_enabled);
        }
        spec
    }

    /// The runtime an environment of `image` is created on
    /// ([`crate::sandbox::template::runtime_profile_of`]).
    fn image_runtime_spec(&self, isolation: Isolation, image: &str) -> RuntimeProfileSpec {
        let spec = self.runtime_spec(isolation);
        let profile = crate::sandbox::template::runtime_profile_of(
            &spec.profile,
            self.standard_runtime.as_ref(),
            image,
        );
        if profile != spec.profile {
            return runtime_profile_spec(profile, &self.docker_mode, self.dind_enabled);
        }
        spec
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

    /// The NetworkPolicy an environment's access stack applies, as the egress
    /// lockdown check expects to read it back (#4000 P6), or `None` when this
    /// deployment leaves workspace NetworkPolicies to someone else. Of an
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

    /// The options an environment's own NetworkPolicies render from, or
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
        let shape = WorkspaceShape {
            cpu_millicores: 0,
            memory_mib: 0,
            disk_gib: 0,
        };
        let opts = self.shape(
            canonical_workspace_runtime_image(),
            &self.runtime_spec(isolation),
            shape,
        );
        Some(TemplateOpts {
            environment_id: environment_id.to_owned(),
            // The policies read whether a direct UDP port is allocated, never
            // which, and the access stack allocates one for every environment
            // where the LoadBalancer is enabled.
            direct_udp_lb_port: i64::from(opts.direct_udp_lb_enabled),
            ..opts
        })
    }

    /// The NetworkPolicy the sandbox controller makes from a workspace
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
        let shape = WorkspaceShape {
            cpu_millicores: 0,
            memory_mib: 0,
            disk_gib: 0,
        };
        let opts = self.shape(
            canonical_workspace_runtime_image(),
            &self.runtime_spec(isolation),
            shape,
        );
        Some(render_template_network_policy(&opts, template_ref_hash))
    }

    /// The identity-free inputs of one warm-pool shape (Program #2238 C1): the
    /// canonical workspace image on the standard tier, from the shape and this
    /// configuration alone. A confidential runtime, a diagnostic runtime
    /// outside diagnostic clusters and a configuration that cannot render
    /// identity-free workspaces render no pool.
    pub fn pool(&self, shape: WorkspaceShape) -> anyhow::Result<TemplateOpts> {
        let runtime_spec = self.runtime_spec(Isolation::Standard);
        anyhow::ensure!(
            runtime_spec.profile != RUNTIME_PROFILE_CONFIDENTIAL,
            "confidential workspaces are never pooled"
        );
        // A pool member must render exactly as the environment that adopts
        // it, and its first-bind checks know only the Kata classes (#5602).
        anyhow::ensure!(
            runtime_spec.profile != RUNTIME_PROFILE_STANDARD,
            "standard workspaces are not pooled yet"
        );
        validate_managed_runtime_profile(&runtime_spec, self.allow_diagnostic_runtime)
            .map_err(|error| anyhow::anyhow!("warm pool runtime profile: {error}"))?;
        let opts = self.shape(canonical_workspace_runtime_image(), &runtime_spec, shape);
        anyhow::ensure!(
            !opts.workspace_binding_url.is_empty(),
            "warm pools require identity-free workspaces (POD_NAMESPACE and a coordinator)"
        );
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
            // Hosted egress (#4000): with the switch on, every template on a
            // VM runtime profile is broker-mode. Another profile never is.
            hosted_egress: self.hosted_egress.clone().filter(|_| {
                matches!(
                    runtime_spec.profile.as_str(),
                    RUNTIME_PROFILE_COMMODITY
                        | RUNTIME_PROFILE_CONFIDENTIAL
                        | RUNTIME_PROFILE_STANDARD
                )
            }),
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
