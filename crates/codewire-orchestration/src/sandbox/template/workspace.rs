//! Workspace SandboxTemplate, pod, storage, and daemon-service rendering.

use serde_json::{Map, Value, json};

use super::credentials;
use super::encoding::kata_policy_init_data_annotation;
use super::naming::{workspace_daemon_service_name, workspace_selector, workspace_template_labels};
use super::network::{identity_free_workspace_egress_rules, identity_free_workspace_ingress_rules};
use super::runtime_policy::{
    DOCKER_MODE_GUEST_DIND, DOCKER_MODE_LOCAL_DIND_DIRECT, RUNTIME_PROFILE_COMMODITY,
    RUNTIME_PROFILE_CONFIDENTIAL, RuntimeProfileSpec, dind_image, dind_memory_limit_gib,
    docker_data_size_gib, kata_coco_kernel_params_annotation, uses_kata_policy_init_data,
    workspace_storage_class,
};
use codewire_daemon_proto::{
    WORKSPACE_BINDING_TLS_ROOTS_MOUNT_PATH, WORKSPACE_BINDING_TOKEN_AUDIENCE,
    WORKSPACE_BINDING_TOKEN_EXPIRATION_SECONDS, WORKSPACE_BINDING_TOKEN_MOUNT_PATH,
    WORKSPACE_BINDING_URL_ENV, WORKSPACE_POD_UID_ENV,
};
// The binding recorder recognizes a Pod-scope Pod by this exact volume.
use crate::worker::workspace_binding::WORKSPACE_BINDING_VOLUME;

use super::{
    CONFIDENTIAL_WORKSPACE_READY_TIMEOUT, DIND_SOCKET_PATH, EXTENSIONS_API_VERSION, HOME_ROOT,
    KATA_COCO_INIT_DATA_ANNOTATION_KEY, KATA_CONFIDENTIAL_VOLUME_ANNOTATION,
    KATA_CONFIDENTIAL_WORKSPACE_DEVICE_PATH, KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY,
    SANDBOX_SERVICE_ACCOUNT, TemplateOpts, WORKSPACE_ANNOTATION_KEY, WORKSPACE_DAEMON_LISTEN_ADDR,
    WORKSPACE_DAEMON_PORT, WORKSPACE_DISK_GIB_ANNOTATION_KEY, WORKSPACE_EPHEMERAL_STORAGE_GI,
    WORKSPACE_READY_TIMEOUT,
};

/// Copies the daemon from the support image into `codewire-bin` where the
/// daemon cannot be mounted from the image itself.
pub(crate) const DAEMON_INIT_CONTAINER: &str = "codewire-daemon-init";
/// The volume that holds `/codewire/bin/cw` in the workspace container.
pub(crate) const DAEMON_VOLUME: &str = "codewire-bin";
/// The directory of the support image that holds `cw`.
const SUPPORT_IMAGE_DAEMON_SUBPATH: &str = "usr/local/bin";

/// Commodity Kata pods mount the daemon read-only from the support image, so
/// the workspace starts without an init container. The kubelet pulls the
/// image volume with the Pod's credentials, and Kata shares it into the guest
/// through virtiofs (proven on Dev, Program #2238 A8c). Confidential guests
/// pull images inside the guest, where image volumes do not apply, and Kind
/// and diagnostic profiles keep the copy, so they keep the init container.
fn daemon_from_image_volume(runtime_spec: &RuntimeProfileSpec) -> bool {
    runtime_spec.profile == RUNTIME_PROFILE_COMMODITY
}

/// Mirrors `sandbox.RenderSandboxTemplate`.
pub fn render_sandbox_template(namespace: &str, opts: &TemplateOpts) -> Value {
    assert!(
        opts.managed_credential_clients == Default::default()
            || (opts.credential_runtime.is_some() && opts.projection_selection_sha256.is_some()),
        "managed credential clients require selected runtime bootstrap"
    );
    if let Some(config) = &opts.credential_runtime {
        config.assert_namespace(namespace);
    }
    // A workspace template carries no environment label (design §13); its
    // environment-owned shadow pool names it.
    let labels = json!({});
    json!({
        "apiVersion": EXTENSIONS_API_VERSION,
        "kind": "SandboxTemplate",
        "metadata": {
            "name": opts.name, "namespace": namespace,
            "labels": labels,
        },
        "spec": render_sandbox_blueprint(opts),
    })
}

/// Render the exact environment-scoped SandboxBlueprint.
pub(super) fn render_sandbox_blueprint(opts: &TemplateOpts) -> Value {
    let support_image = opts.effective_support_image();

    const ENSURE_USER_CMD: &str = "user_shell=/bin/bash; [ -x /bin/bash ] || user_shell=/bin/sh; grep -q '^[^:]*:[^:]*:1000:' /etc/passwd || echo \"codewire:x:1000:1000:codewire:/home/codewire:${user_shell}\" >> /etc/passwd; grep -q '^[^:]*:[^:]*:1000:' /etc/group || echo 'codewire:x:1000:' >> /etc/group;";
    const WAIT_DAEMON_CMD: &str = "while [ ! -x /codewire/bin/cw ]; do sleep 0.1; done;";
    const HOSTED_DAEMON_CMD: &str = "/codewire/bin/cw __hosted-daemon";

    let ws_command: Vec<Value> = if !opts.image_command.is_empty() {
        let entrypoint = opts
            .image_command
            .iter()
            .map(|argument| shell_quote(argument))
            .collect::<Vec<_>>()
            .join(" ");
        vec![
            "sh".into(),
            "-c".into(),
            custom_workspace_supervisor_command(
                ENSURE_USER_CMD,
                WAIT_DAEMON_CMD,
                HOSTED_DAEMON_CMD,
                &entrypoint,
            )
            .into(),
        ]
    } else {
        vec![
            "sh".into(),
            "-c".into(),
            managed_workspace_supervisor_command(
                ENSURE_USER_CMD,
                WAIT_DAEMON_CMD,
                HOSTED_DAEMON_CMD,
            )
            .into(),
        ]
    };

    let mut ws_container = json!({
        "name": "workspace",
        "image": opts.image,
        "command": ws_command,
        "env": build_workspace_env(opts),
        "ports": [
            { "name": "daemon", "containerPort": WORKSPACE_DAEMON_PORT, "protocol": "TCP" },
        ],
        "resources": {
            "requests": {
                "cpu": format!("{}m", opts.cpu_sharing.request_millicores(opts.cpu_millicores)),
                "memory": format!("{}Mi", opts.memory_mib),
                "ephemeral-storage": format!("{WORKSPACE_EPHEMERAL_STORAGE_GI}Gi"),
            },
            "limits": {
                "cpu": format!("{}m", opts.cpu_millicores),
                "memory": format!("{}Mi", opts.memory_mib),
                "ephemeral-storage": format!("{WORKSPACE_EPHEMERAL_STORAGE_GI}Gi"),
            },
        },
        "resizePolicy": [
            { "resourceName": "cpu", "restartPolicy": "NotRequired" },
            { "resourceName": "memory", "restartPolicy": "NotRequired" },
        ],
        "volumeMounts": [
            { "name": "workspace", "mountPath": "/home/codewire" },
            { "name": "workspace", "mountPath": "/workspace" },
            daemon_mount(&opts.runtime_profile_spec()),
            { "name": "codewire-run", "mountPath": "/codewire/run" },
        ],
    });

    build_template_spec(opts, &mut ws_container, support_image)
}

/// Keep an intentional PID-1 owner around the daemon. The launch helper must
/// authenticate its actual daemon parent, not accept PID 1 as a substitute.
/// Kubernetes owns restart policy; this owner forwards shutdown and reaps the
/// daemon before returning its status.
///
/// The traps come before any child, so no shutdown signal can arrive while
/// they are missing. As container PID 1 the kernel drops a signal with no
/// handler: a Stop during user setup or the daemon wait would otherwise sit
/// out the Pod's whole termination grace and kill the daemon. A trap that runs
/// between a fork and its `$!` assignment takes the child from `$!`.
pub(super) fn managed_workspace_supervisor_command(
    ensure_user: &str,
    wait_daemon: &str,
    daemon_command: &str,
) -> String {
    format!(
        "daemon_pid=; \
         shutdown() {{ \
           daemon_pid=\"${{daemon_pid:-$!}}\"; \
           kill -TERM \"$daemon_pid\" 2>/dev/null || true; \
           wait \"$daemon_pid\" 2>/dev/null || true; \
         }}; \
         trap 'shutdown; exit 143' TERM; \
         trap 'shutdown; exit 130' INT; \
         {ensure_user} {wait_daemon} \
         {daemon_command} & daemon_pid=$!; \
         wait \"$daemon_pid\"; status=$?; \
         trap - TERM INT; \
         exit \"$status\""
    )
}

pub(super) fn custom_workspace_supervisor_command(
    ensure_user: &str,
    wait_daemon: &str,
    daemon_command: &str,
    entrypoint: &str,
) -> String {
    // The container carries no environment token to remove from the workload.
    let workload = format!("(exec {entrypoint})");
    // Traps first, as for the managed supervisor; a restarted daemon clears
    // its old pid before the fork so a trap in between takes it from `$!`.
    format!(
        "daemon_pid=; workload_pid=; \
         shutdown() {{ \
           daemon_pid=\"${{daemon_pid:-$!}}\"; \
           workload_pid=\"${{workload_pid:-$!}}\"; \
           kill \"$workload_pid\" \"$daemon_pid\" 2>/dev/null || true; \
           wait \"$workload_pid\" 2>/dev/null || true; \
           wait \"$daemon_pid\" 2>/dev/null || true; \
         }}; \
         trap 'shutdown; exit 0' TERM INT; \
         {ensure_user} {wait_daemon} \
         {daemon_command} & daemon_pid=$!; \
         {workload} & workload_pid=$!; \
         while kill -0 \"$workload_pid\" 2>/dev/null; do \
           if ! kill -0 \"$daemon_pid\" 2>/dev/null; then \
             wait \"$daemon_pid\" 2>/dev/null || true; \
             sleep 1; \
             daemon_pid=; \
             {daemon_command} & daemon_pid=$!; \
           fi; \
           sleep 1; \
         done; \
         wait \"$workload_pid\"; status=$?; \
         kill \"$daemon_pid\" 2>/dev/null || true; \
         wait \"$daemon_pid\" 2>/dev/null || true; \
         exit \"$status\""
    )
}

fn build_template_spec(opts: &TemplateOpts, ws: &mut Value, support_image: &str) -> Value {
    let runtime_spec = opts.runtime_profile_spec();
    let mut annotations = Map::new();
    annotations.insert(WORKSPACE_ANNOTATION_KEY.into(), "true".into());
    if !opts.egress_bandwidth.is_empty() {
        annotations.insert(
            super::EGRESS_BANDWIDTH_ANNOTATION_KEY.into(),
            opts.egress_bandwidth.clone().into(),
        );
    }
    if opts.disk_gib > 0 {
        annotations.insert(
            WORKSPACE_DISK_GIB_ANNOTATION_KEY.into(),
            format!("{}", opts.disk_gib).into(),
        );
    }
    if uses_kata_policy_init_data(opts, &runtime_spec) {
        annotations.insert(
            KATA_COCO_INIT_DATA_ANNOTATION_KEY.into(),
            kata_policy_init_data_annotation(opts, true).into(),
        );
    }
    if let Some(kernel_params) = kata_coco_kernel_params_annotation(opts, &runtime_spec) {
        annotations.insert(
            KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY.into(),
            kernel_params.into(),
        );
    }
    if runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL
        && opts.disk_gib > 0
        && crate::confidential_storage::validate_manifest_uri(
            &opts.confidential_storage_manifest_uri,
        )
    {
        let mut mounts = Map::new();
        mounts.insert("workspace".into(), json!(["/home/codewire", "/workspace"]));
        if matches!(
            runtime_spec.docker_mode.as_str(),
            DOCKER_MODE_LOCAL_DIND_DIRECT | DOCKER_MODE_GUEST_DIND
        ) {
            mounts.insert("dind".into(), json!(["/workspace"]));
        }
        annotations.insert(
            KATA_CONFIDENTIAL_VOLUME_ANNOTATION.into(),
            serde_json::json!({
                "workspace": {
                    "devicePath": KATA_CONFIDENTIAL_WORKSPACE_DEVICE_PATH,
                    "manifestUri": opts.confidential_storage_manifest_uri,
                    "access": "readWrite",
                    "fsGroup": 1000,
                    "fsGroupChangePolicy": "OnRootMismatch",
                    "mounts": mounts,
                }
            })
            .to_string()
            .into(),
        );
    }

    let mut labels = workspace_template_labels();
    if runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL {
        labels
            .as_object_mut()
            .expect("workspace labels object")
            .insert("codewire.sh/isolation-tier".into(), "confidential".into());
    }
    let mut spec = Map::new();
    spec.insert(
        "podTemplate".into(),
        json!({
            "metadata": { "annotations": annotations, "labels": labels },
            "spec": build_pod_spec(opts, ws, support_image),
        }),
    );
    if !opts.network_policy_management.is_empty() && opts.network_policy_management != "Managed" {
        spec.insert(
            "networkPolicyManagement".into(),
            opts.network_policy_management.clone().into(),
        );
    }

    if opts.disk_gib > 0 {
        let storage_class = workspace_storage_class(opts);
        let confidential = runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL;
        let metadata = if confidential {
            json!({
                "name": "workspace",
                "labels": {
                    "codewire.sh/environment-id": opts.environment_id,
                },
            })
        } else {
            json!({ "name": "workspace" })
        };
        let access_mode = if confidential {
            "ReadWriteOncePod"
        } else {
            "ReadWriteOnce"
        };
        let mut claim_spec = json!({
            "accessModes": [access_mode],
            "storageClassName": storage_class,
            "resources": { "requests": { "storage": format!("{}Gi", opts.disk_gib) } },
        });
        // Confidential's device is opened by CoCo's storage handler; a
        // commodity one by the guest's `mount-workspace` (#3718).
        if confidential || block_workspace(opts, &runtime_spec) {
            claim_spec["volumeMode"] = "Block".into();
        }
        if let Some(snapshot) = &opts.workspace_source_snapshot {
            claim_spec["dataSource"] = json!({
                "apiGroup": "snapshot.storage.k8s.io",
                "kind": "VolumeSnapshot",
                "name": snapshot,
            });
        }
        spec.insert(
            "volumeClaimTemplates".into(),
            json!([{
                "metadata": metadata,
                "spec": claim_spec,
            }]),
        );
    }

    let mut network_policy = Map::new();
    let ingress = identity_free_workspace_ingress_rules(opts);
    if !ingress.is_empty() {
        network_policy.insert("ingress".into(), Value::Array(ingress));
    }
    network_policy.insert(
        "egress".into(),
        Value::Array(identity_free_workspace_egress_rules(opts)),
    );
    spec.insert("networkPolicy".into(), Value::Object(network_policy));

    Value::Object(spec)
}

fn build_pod_spec(opts: &TemplateOpts, ws: &mut Value, support_image: &str) -> Value {
    let runtime_spec = opts.runtime_profile_spec();
    let confidential_block = runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL
        && opts.disk_gib > 0
        && crate::confidential_storage::validate_manifest_uri(
            &opts.confidential_storage_manifest_uri,
        );
    if confidential_block {
        configure_confidential_workspace_device(ws);
    }
    let block = block_workspace(opts, &runtime_spec);
    let subfolder = block && opts.workspace_subfolder;
    if block {
        configure_block_workspace_mounts(ws, true, subfolder);
    }
    let daemon_image_volume = daemon_from_image_volume(&runtime_spec);
    let daemon_volume = if daemon_image_volume {
        json!({
            "name": DAEMON_VOLUME,
            "image": { "reference": support_image, "pullPolicy": "IfNotPresent" },
        })
    } else {
        json!({ "name": DAEMON_VOLUME, "emptyDir": {} })
    };
    // A confidential daemon keeps its credential and SSH host key here: guest
    // memory, whatever emptyDir backing the runtime would choose (B2c).
    let run_volume = if runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL {
        json!({ "name": "codewire-run", "emptyDir": { "medium": "Memory" } })
    } else {
        json!({ "name": "codewire-run", "emptyDir": {} })
    };
    let mut volumes = vec![daemon_volume, run_volume];
    if opts.disk_gib == 0 {
        volumes.insert(0, json!({ "name": "workspace", "emptyDir": {} }));
    }
    if block {
        volumes.extend(block_workspace_volumes(subfolder));
    }
    if opts.credential_runtime.is_some() {
        volumes.extend(credentials::workspace_volumes(opts));
        ws["volumeMounts"]
            .as_array_mut()
            .expect("workspace mounts")
            .extend(credentials::workspace_mounts());
        // The bound daemon expands its managed clients into child
        // environments from the bind response; nothing is rendered here.
    }
    // Workspace container only; never DinD or an init container.
    volumes.push(workspace_binding_token_volume());
    ws["volumeMounts"]
        .as_array_mut()
        .expect("workspace mounts")
        .push(json!({
            "name": WORKSPACE_BINDING_VOLUME,
            "mountPath": WORKSPACE_BINDING_TOKEN_MOUNT_PATH,
            "readOnly": true,
        }));
    // The public roots that verify the binding listener's TLS identity. A
    // confidential workspace mounts none: the host supplies every file there,
    // so its daemon trusts only its measured roots (B2c).
    let confidential = runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL;
    if !confidential {
        volumes.push(workspace_binding_roots_volume());
        ws["volumeMounts"]
            .as_array_mut()
            .expect("workspace mounts")
            .push(json!({
                "name": WORKSPACE_BINDING_ROOTS_VOLUME,
                "mountPath": WORKSPACE_BINDING_TLS_ROOTS_MOUNT_PATH,
                "readOnly": true,
            }));
    }
    // A local cluster's coordinator is not WebPKI-signed: only there does
    // orchestration mount the public bundle the daemon trusts beside the
    // WebPKI roots for its coordinator. Dev and Production never do, and a
    // confidential daemon never trusts one.
    if opts.coordinator_extra_roots && !confidential {
        volumes.push(coordinator_extra_roots_volume());
        ws["volumeMounts"]
            .as_array_mut()
            .expect("workspace mounts")
            .push(json!({
                "name": COORDINATOR_EXTRA_ROOTS_VOLUME,
                "mountPath": codewire_daemon_proto::COORDINATOR_EXTRA_ROOTS_MOUNT_PATH,
                "readOnly": true,
            }));
    }

    let mut spec = Map::new();
    spec.insert("restartPolicy".into(), "Never".into());
    spec.insert("serviceAccountName".into(), SANDBOX_SERVICE_ACCOUNT.into());
    spec.insert("automountServiceAccountToken".into(), false.into());
    // Every environment has a Service in this shared namespace. Without this,
    // Kubernetes injects each one's name and address into every workspace
    // process as `*_SERVICE_HOST` variables, across owners.
    spec.insert("enableServiceLinks".into(), false.into());
    spec.insert(
        "securityContext".into(),
        json!({
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "fsGroup": 1000,
            "fsGroupChangePolicy": "OnRootMismatch",
        }),
    );
    spec.insert("dnsPolicy".into(), "ClusterFirst".into());

    if !runtime_spec.runtime_class_name.is_empty() {
        spec.insert(
            "runtimeClassName".into(),
            runtime_spec.runtime_class_name.clone().into(),
        );
    }
    // Docker never decides workspace readiness: a DinD workspace renders the
    // same probes as one without Docker. Usable means the user can SSH in
    // (owner, 2026-10-06), so the Pod, its Sandbox and Claim turn Ready
    // without waiting for dockerd, which comes up beside the workspace; the
    // DinD container has no probe and still counts only while it runs, so a
    // bootstrap that exits keeps the Pod unready. A `docker` command run
    // before dockerd listens waits for its socket (owner, 2026-10-27; setup's
    // `DOCKER_SOCKET_WAIT`, the workspace image's `docker`). Program #2238.
    apply_daemon_ready_probes(ws, &runtime_spec);
    let mut containers: Vec<Value> = Vec::new();
    if runtime_spec.docker_mode == DOCKER_MODE_LOCAL_DIND_DIRECT
        || runtime_spec.docker_mode == DOCKER_MODE_GUEST_DIND
    {
        // Kata can only share a live Unix socket between pod containers when
        // the emptyDir is guest memory. A disk-backed emptyDir is projected
        // through the shared filesystem or a block device, which preserves a
        // pathname but not the listening socket endpoint.
        volumes.push(json!({
            "name": "docker-sock",
            "emptyDir": { "medium": "Memory" },
        }));
    }

    if runtime_spec.docker_mode == DOCKER_MODE_LOCAL_DIND_DIRECT {
        ws["env"]
            .as_array_mut()
            .expect("ws env array")
            .push(json!({ "name": "DOCKER_HOST", "value": "unix:///var/run/docker/docker.sock" }));
        ws["volumeMounts"]
            .as_array_mut()
            .expect("ws mounts array")
            .push(json!({ "name": "docker-sock", "mountPath": "/var/run/docker" }));

        containers.push(ws.clone());
        let mut dind = dind_container(opts, &runtime_spec, false);
        if confidential_block {
            configure_confidential_workspace_device(&mut dind);
        }
        if block {
            configure_block_workspace_mounts(&mut dind, true, subfolder);
            if subfolder {
                dind_mount_workspace_root(&mut dind);
            }
        }
        containers.push(dind);
    } else if runtime_spec.docker_mode == DOCKER_MODE_GUEST_DIND {
        ws["env"]
            .as_array_mut()
            .expect("ws env array")
            .push(json!({ "name": "DOCKER_HOST", "value": "unix:///var/run/docker/docker.sock" }));
        ws["volumeMounts"]
            .as_array_mut()
            .expect("ws mounts array")
            .push(json!({ "name": "docker-sock", "mountPath": "/var/run/docker" }));

        containers.push(ws.clone());
        let mut dind = dind_container(opts, &runtime_spec, true);
        if confidential_block {
            configure_confidential_workspace_device(&mut dind);
        }
        if block {
            configure_block_workspace_mounts(&mut dind, true, subfolder);
            if subfolder {
                dind_mount_workspace_root(&mut dind);
            }
        }
        containers.push(dind);
    } else {
        containers.push(ws.clone());
    }

    // The daemon in the workspace container writes Codex's `~/.codex` on the
    // persistent home itself, so no init container
    // copies client configuration. On confidential, no init container can
    // reach that protected disk at all. A guest DinD's data image is
    // prepared before DinD mounts it (#3208), last, as a Start re-renders it
    // into an older Sandbox.
    // A Block workspace is mounted first, by the only container that ever
    // holds its device (#3718).
    // On Block it also prepares the Docker data image, and a sidecar flushes
    // the workspace when the Pod stops.
    let mut init_containers = Vec::new();
    let data_env = docker_data_init_env(opts, &runtime_spec);
    if block {
        init_containers.push(mount_workspace_init_container(
            support_image,
            WorkspaceVolume::rendered(opts),
            data_env.clone().unwrap_or_default(),
            subfolder,
        ));
    }
    if !daemon_image_volume {
        init_containers.push(daemon_init_container(support_image, &runtime_spec.profile));
    }
    if block {
        init_containers.push(workspace_flush_container(support_image));
    } else if let Some(env) = data_env {
        init_containers.push(docker_data_init_container(support_image, env));
    }
    if !init_containers.is_empty() {
        spec.insert("initContainers".into(), Value::Array(init_containers));
    }
    if block {
        spec.insert(
            "terminationGracePeriodSeconds".into(),
            BLOCK_WORKSPACE_GRACE_SECONDS.into(),
        );
    }
    spec.insert("containers".into(), Value::Array(containers));
    spec.insert("volumes".into(), Value::Array(volumes));
    Value::Object(spec)
}

/// Whether the workspace is a commodity Block volume that the guest formats
/// and mounts itself, so writes reach the disk with no host page cache
/// (#3718, design §2). Kind and runc keep a Filesystem claim.
fn block_workspace(opts: &TemplateOpts, runtime_spec: &RuntimeProfileSpec) -> bool {
    runtime_spec.profile == RUNTIME_PROFILE_COMMODITY && opts.disk_gib > 0
}

/// The one-shot container that formats, checks, grows and mounts a Block
/// workspace (#3718, design §2).
pub(crate) const MOUNT_WORKSPACE_CONTAINER: &str = "mount-workspace";

/// Where `mount-workspace` sees the workspace device.
pub(crate) const MOUNT_WORKSPACE_DEVICE_PATH: &str = "/dev/cwws";

/// The guest-memory volume the workspace filesystem is mounted into: the
/// home, and with no workspace subfolder also `/workspace`.
pub(crate) const WORKSPACE_MOUNT_VOLUME: &str = "mnthome";
/// Its name in Pods rendered before #4026, which a start still recognizes.
pub(crate) const LEGACY_WORKSPACE_MOUNT_VOLUME: &str = "wsmnt";
/// The guest-memory volume the filesystem's `workspace/` folder is bound
/// into for `/workspace` when the workspace is a subfolder (#4026).
pub(crate) const WORKSPACE_DIR_VOLUME: &str = "mntws";
/// Chooses the commodity Block workspace layout (#4026).
pub const WORKSPACE_LAYOUT_ENV: &str = "SANDBOX_WORKSPACE_LAYOUT";

/// Validates [`WORKSPACE_LAYOUT_ENV`] at startup: empty mounts the whole volume
/// at `/workspace`, `subfolder` only its `workspace/` folder. Anything else is
/// refused, so a misspelling never silently keeps the old layout.
pub fn workspace_subfolder_layout(value: &str) -> Result<bool, String> {
    match value.trim() {
        "" => Ok(false),
        "subfolder" => Ok(true),
        other => Err(format!(
            "{WORKSPACE_LAYOUT_ENV} must be empty or subfolder, not '{other}'"
        )),
    }
}
/// Where DinD sees the filesystem's root, and so its data image, when its
/// `/workspace` is the subfolder (#4026).
pub(crate) const DIND_WORKSPACE_ROOT: &str = "/mnt/home";
const WORKSPACE_TMP_VOLUME: &str = "wstmp";

/// What the create operation knows of a Block workspace volume: `New` only
/// for a fresh claim, which `mount-workspace` may format if it is not
/// already ext4. Every other volume is `Existing` and never formatted.
/// Once a Pod's `mount-workspace` has exited 0, the next stop, suspension or
/// Pod replacement turns `New` into `Existing` (the client's
/// `workspace_volume_existing`); a first Pod that failed before or during
/// its format leaves `New`, so its replacement can still format. Until then
/// the formatted disk's own ext4 signature keeps a rebuilt Pod from
/// formatting it again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkspaceVolume {
    New,
    Existing,
}

impl WorkspaceVolume {
    /// A fork restores a snapshot, so its volume is never new.
    fn rendered(opts: &TemplateOpts) -> Self {
        if opts.workspace_source_snapshot.is_some() {
            Self::Existing
        } else {
            Self::New
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Existing => "existing",
        }
    }
}

/// The guest-memory emptyDirs a Block workspace is mounted into, with the
/// subfolder's when `/workspace` is one (#4026). They hold only mount
/// points, so they use no memory of their own.
fn block_workspace_volumes(subfolder: bool) -> Vec<Value> {
    let mut volumes = vec![
        json!({ "name": WORKSPACE_MOUNT_VOLUME, "emptyDir": { "medium": "Memory" } }),
        json!({ "name": WORKSPACE_TMP_VOLUME, "emptyDir": { "medium": "Memory" } }),
    ];
    if subfolder {
        volumes.push(json!({ "name": WORKSPACE_DIR_VOLUME, "emptyDir": { "medium": "Memory" } }));
    }
    volumes
}

/// Replaces a container's `workspace` mounts with the mounted filesystem,
/// seen through `HostToContainer` propagation, and, with `tmp`, mounts the
/// workspace's temporary directory at `/tmp` and `/var/tmp` (R1). With
/// `subfolder`, its `/workspace` is the filesystem's `workspace/` folder
/// instead of its root (#4026). No long-lived container ever holds the
/// device: a Kata container with a `volumeDevice` cannot restart (design §2).
pub(crate) fn configure_block_workspace_mounts(container: &mut Value, tmp: bool, subfolder: bool) {
    let mounts = container["volumeMounts"]
        .as_array_mut()
        .expect("container volumeMounts array");
    for mount in mounts.iter_mut() {
        if mount["name"].as_str() == Some("workspace") {
            mount["name"] = if subfolder && mount["mountPath"].as_str() == Some("/workspace") {
                WORKSPACE_DIR_VOLUME
            } else {
                WORKSPACE_MOUNT_VOLUME
            }
            .into();
            mount["mountPropagation"] = "HostToContainer".into();
        }
    }
    if tmp {
        for path in ["/tmp", "/var/tmp"] {
            mounts.push(json!({
                "name": WORKSPACE_TMP_VOLUME,
                "mountPath": path,
                "mountPropagation": "HostToContainer",
            }));
        }
    }
}

/// `mount-workspace`: privileged inside the guest only, the one container
/// with the workspace device, and done before any other container starts.
/// Beside a guest DinD it also prepares the Docker data image, with the data
/// init's variables (`data_env`), so a Block Pod has one init container that
/// must exit, as a Filesystem Pod does: each one delays the next container by
/// about a second (durability design §4).
pub(crate) fn mount_workspace_init_container(
    support_image: &str,
    volume: WorkspaceVolume,
    data_env: Vec<Value>,
    subfolder: bool,
) -> Value {
    // The layout rides in the one argument, so the admitted argv keeps its
    // shape (infra's Kyverno policy pins five elements).
    let state = if subfolder {
        format!("{}-subfolder", volume.as_str())
    } else {
        volume.as_str().to_owned()
    };
    let command = json!([
        "sh",
        "-c",
        MOUNT_WORKSPACE_SCRIPT,
        MOUNT_WORKSPACE_CONTAINER,
        state
    ]);
    let mut mounts = vec![
        json!({ "name": WORKSPACE_MOUNT_VOLUME, "mountPath": "/mnt/ws", "mountPropagation": "Bidirectional" }),
        json!({ "name": WORKSPACE_TMP_VOLUME, "mountPath": "/mnt/tmp", "mountPropagation": "Bidirectional" }),
    ];
    if subfolder {
        mounts.push(json!({ "name": WORKSPACE_DIR_VOLUME, "mountPath": "/mnt/wsdir", "mountPropagation": "Bidirectional" }));
    }
    let mut container = json!({
        "name": MOUNT_WORKSPACE_CONTAINER,
        "image": support_image,
        "securityContext": { "privileged": true, "runAsUser": 0, "runAsGroup": 0 },
        "command": command,
        "volumeDevices": [{ "name": "workspace", "devicePath": MOUNT_WORKSPACE_DEVICE_PATH }],
        "volumeMounts": mounts,
        "resources": docker_data_init_resources(),
    });
    if !data_env.is_empty() {
        container["env"] = Value::Array(data_env);
    }
    container
}

/// The native sidecar that flushes a Block workspace when its Pod stops
/// (#3718, durability design §1).
pub(crate) const WORKSPACE_FLUSH_CONTAINER: &str = "workspace-flush";

/// `workspace-flush`: a sidecar (an init container with `restartPolicy:
/// Always`), so the kubelet stops it only after the workspace and DinD have
/// exited, and the VM is destroyed only after it returns. Without it, writes
/// still in guest memory are lost when the VM goes. It is unprivileged and
/// sees only the mounted workspace, as the workspace does.
pub(crate) fn workspace_flush_container(support_image: &str) -> Value {
    json!({
        "name": WORKSPACE_FLUSH_CONTAINER,
        "image": support_image,
        "restartPolicy": "Always",
        "securityContext": {
            "runAsUser": 1000, "runAsGroup": 1000, "runAsNonRoot": true,
            "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
            "capabilities": { "drop": ["ALL"] },
        },
        "command": ["sh", "-c", WORKSPACE_FLUSH_SCRIPT],
        "volumeMounts": [
            { "name": WORKSPACE_MOUNT_VOLUME, "mountPath": "/mnt/ws", "mountPropagation": "HostToContainer" },
        ],
        "resources": {
            "requests": { "cpu": "5m", "memory": "8Mi" },
            "limits": { "cpu": "100m", "memory": "32Mi" },
        },
    })
}

/// A Block workspace Pod's termination grace period: `workspace-flush`'s bound plus
/// the workspace and DinD shutdowns before it (dockerd's own shutdown waits up
/// to 15 s), so the kubelet never kills a Pod mid-flush. Only a stop with that
/// much unwritten data ever waits this long; on Dev, a full dirty pool took
/// 4.2 s (8 GiB) and 8.0 s (32 GiB) from SIGTERM to the flush done.
pub(crate) const BLOCK_WORKSPACE_GRACE_SECONDS: u32 = 60;

/// `workspace-flush`'s shell. It waits for SIGTERM, then `syncfs` writes every
/// completed write of the workspace filesystem to the disk. ext4's journal
/// keeps the unmounted filesystem consistent, and `mount-workspace` checks it
/// at the next start. The guest keeps the kernel's writeback defaults (owner,
/// 2026-11-02: "If the sandbox crashes, the sandbox crashes"), so the flush
/// may have up to the default dirty limit to write: 6.22 GiB (6.68 GB) in the
/// largest, 32 GiB guest, measured on Dev (`nr_dirty_threshold`, #3718). At
/// the 327 MB/s the workspace disk was measured to write, that is 20.4 s;
/// with half again as margin, 30.6 s, so `syncfs` gets 35 s, inside the Pod's
/// [`BLOCK_WORKSPACE_GRACE_SECONDS`]. A failed or late flush is logged, and the
/// Pod still stops.
pub(crate) const WORKSPACE_FLUSH_SCRIPT: &str = r#"# The path is overridable only for the script's own test.
ws="${CODEWIRE_WORKSPACE_FLUSH_ROOT:-/mnt/ws}"
flush() {
  began="$(date +%s%N)"
  status=0
  timeout 35 sync -f "$ws" || status=$?
  took=$((($(date +%s%N) - began) / 1000000))
  if [ "$status" = 0 ]; then
    echo "codewire workspace-flush: flushed the workspace (flush_ms=$took)"
  else
    echo "codewire workspace-flush: flushing the workspace failed (status=$status flush_ms=$took)" >&2
  fi
  kill "$sleeper" 2>/dev/null
  exit 0
}
trap flush TERM
while :; do
  sleep 3600 &
  sleeper=$!
  wait "$sleeper"
done
"#;

/// The Docker data image preparation as a literal, so that
/// [`MOUNT_WORKSPACE_SCRIPT`] can carry it verbatim (see
/// [`docker_data_image_prepare_script`]).
macro_rules! docker_data_image_prepare_text {
    () => {
        r#"data_image="${CODEWIRE_DOCKER_DATA_IMAGE:-/workspace/.codewire/docker-data.ext4}"
data_size="${CODEWIRE_DOCKER_DATA_SIZE:-8G}"
mount_mode="${CODEWIRE_DOCKER_MOUNT_MODE:-loop}"
if [ "$mount_mode" = "loop" ]; then
  codewire_dir="$(dirname "$data_image")"
  mkdir -p "$codewire_dir"
  chown 1000:1000 "$codewire_dir"
  # Owner-writable only: the workspace daemon refuses a group- or
  # world-writable ancestor of its platform session store.
  chmod 0755 "$codewire_dir"
  if [ ! -s "$data_image" ]; then
    # A fresh sparse image reads as zeros, so mke2fs skips zeroing its
    # inode tables and journal: a few MiB of writes at any size.
    if ! { truncate -s "$data_size" "$data_image" &&
      mkfs.ext4 -q -F -E lazy_itable_init=1,lazy_journal_init=1 "$data_image"; }; then
      rm -f "$data_image"
      echo "the Docker data image $data_image was not created; Docker does not start" >&2
    fi
  fi
  if [ -s "$data_image" ]; then
    # A grown workspace disk renders a larger data size: extend the image to
    # it, never shrinking it, and grow its filesystem offline to fill the
    # image. Growth keeps every byte, and a failed grow still starts Docker
    # at its previous size (#3554).
    data_gib="${data_size%G}"
    case "$data_gib" in ''|*[!0-9]*) data_gib=0 ;; esac
    if [ "$(stat -c %s "$data_image")" -lt "$((data_gib * 1073741824))" ]; then
      truncate -s "$data_size" "$data_image" || true
    fi
    data_fs_bytes="$(dumpe2fs -h "$data_image" 2>/dev/null | awk -F: '$1 == "Block count" { count = $2 } $1 == "Block size" { size = $2 } END { printf "%.0f", count * size }')"
    if [ "$(stat -c %s "$data_image")" -gt "${data_fs_bytes:-0}" ]; then
      # resize2fs grows an unmounted filesystem only after a forced check;
      # e2fsck exits 1 when it corrected something.
      fsck_status=0
      e2fsck -fy "$data_image" >/dev/null || fsck_status=$?
      if [ "$fsck_status" -gt 1 ] || ! resize2fs "$data_image"; then
        echo "the Docker data filesystem did not grow to $data_size; Docker keeps its previous size" >&2
      fi
    fi
  fi
fi"#
    };
}

/// `mount-workspace`'s shell; its one argument is `new` or `existing`, with
/// `-subfolder` when `/workspace` is the filesystem's `workspace/` folder.
///
/// It fails closed and is never retried in place: a retried container
/// cannot re-add the locked disk, so recovery is a new Pod (#3786). Every
/// refusal prints one `codewire mount-workspace:` line and exits 1.
///
/// - The device must read; a volume that fails to read is never probed or
///   formatted.
/// - `blkid -p` probes at a low level, so a stale or partial signature also
///   counts as a signature. A linstor-local volume is LUKS-encrypted, so a
///   new one reads as random bytes, never zeros: whether it is new comes from
///   the create operation, never from its contents.
/// - A volume holds ext4 when `dumpe2fs -h` reads a valid ext4 superblock or
///   `blkid -p` finds ext4. Such a volume is never wiped or formatted, whatever
///   else the probe says: the random bytes around a real filesystem may also
///   match a foreign magic, which makes the probe ambiguous.
/// - A `new` volume that does not hold ext4 is formatted. Its random bytes
///   may match a short foreign magic by chance, so any signature is wiped
///   first.
/// - An `existing` volume must hold ext4: no signature, another one and a
///   failed probe are refused.
/// - `e2fsck -f -p` must exit 0 or 1 (corrected); its time and the whole
///   step's are in the last line, for the no-slower measurement. The filesystem is then
///   mounted and grown online to the device, which a grown claim makes
///   larger; a failed grow keeps the previous size.
/// - A fresh filesystem's root is the workspace user's: a guest-formatted
///   volume gets no kubelet `fsGroup`.
/// - `.codewire/tmp` is emptied at every boot and bound for `/tmp` and
///   `/var/tmp` (R1). A `.codewire` that is a symbolic link is refused, so
///   no path the workspace controls is followed as root.
/// - With `-subfolder`, `workspace/` is created if absent and bound for
///   `/workspace` (#4026); one that is a symbolic link or not a directory is
///   refused, for the same reason.
pub(crate) const MOUNT_WORKSPACE_SCRIPT: &str = concat!(
    r#"set -u
# The three paths are overridable only for the script's own test; nothing
# renders them, and the pool policy admits no other variable.
dev="${CODEWIRE_MOUNT_WORKSPACE_DEVICE:-/dev/cwws}"
ws="${CODEWIRE_MOUNT_WORKSPACE_ROOT:-/mnt/ws}"
tmp="${CODEWIRE_MOUNT_WORKSPACE_TMP:-/mnt/tmp}"
volume="${1:-}"
began="$(date +%s%N)"
refuse() {
  echo "codewire mount-workspace: $*" >&2
  exit 1
}
subfolder=0
case "$volume" in
  new|existing) ;;
  new-subfolder|existing-subfolder) subfolder=1; volume="${volume%-subfolder}" ;;
  *) refuse "the volume state must be new or existing, optionally with -subfolder, not '$volume'" ;;
esac
dd if="$dev" of=/dev/null bs=4096 count=1 2>/dev/null || refuse "the workspace device $dev cannot be read"
probe=0
blkid -p "$dev" >/dev/null 2>&1 || probe=$?
fstype=
[ "$probe" != 0 ] || fstype="$(blkid -p -s TYPE -o value "$dev" 2>/dev/null || true)"
ext4=0
if [ "$fstype" = ext4 ] || dumpe2fs -h "$dev" >/dev/null 2>&1; then ext4=1; fi
fresh=0
if [ "$ext4" = 0 ] && [ "$volume" = new ]; then
  case "$probe" in
    0|2|8) ;;
    *) refuse "probing the workspace device failed (blkid exit $probe)" ;;
  esac
  [ "$probe" = 2 ] || wipefs -a -q "$dev" || refuse "clearing the new workspace volume's chance signature failed"
  mkfs.ext4 -q -F -E lazy_itable_init=1,lazy_journal_init=1 "$dev" || refuse "formatting the new workspace volume failed"
  fresh=1
elif [ "$ext4" = 0 ]; then
  case "$probe" in
    0) refuse "the workspace volume holds '${fstype:-an unknown signature}', not ext4" ;;
    2) refuse "the existing workspace volume has no filesystem; it is not formatted" ;;
    *) refuse "probing the workspace device failed (blkid exit $probe)" ;;
  esac
fi
checked="$(date +%s%N)"
check=0
e2fsck -f -p "$dev" >/dev/null 2>&1 || check=$?
[ "$check" -le 1 ] || refuse "checking the workspace filesystem failed (e2fsck exit $check)"
check_ms=$((($(date +%s%N) - checked) / 1000000))
mount -t ext4 -o noatime "$dev" "$ws" || refuse "mounting the workspace filesystem failed"
resize2fs "$dev" >/dev/null 2>&1 || echo "codewire mount-workspace: the workspace filesystem did not grow; it keeps its previous size" >&2
[ "$fresh" = 0 ] || chown 1000:1000 "$ws" || refuse "the fresh workspace root could not be given to the workspace user"
[ ! -L "$ws/.codewire" ] || refuse "the workspace's .codewire is a symbolic link"
if [ ! -d "$ws/.codewire" ]; then
  mkdir "$ws/.codewire" && chown 1000:1000 "$ws/.codewire" && chmod 0755 "$ws/.codewire" ||
    refuse "the workspace's .codewire could not be created"
fi
rm -rf "$ws/.codewire/tmp" && mkdir "$ws/.codewire/tmp" && chmod 1777 "$ws/.codewire/tmp" ||
  refuse "the workspace temporary directory could not be emptied"
mount --bind "$ws/.codewire/tmp" "$tmp" || refuse "binding the workspace temporary directory failed"
if [ "$subfolder" = 1 ]; then
  # /workspace is the filesystem's workspace/ folder (#4026). No workspace
  # process runs yet, so a folder checked here is the one bound.
  dir="${CODEWIRE_MOUNT_WORKSPACE_DIR:-/mnt/wsdir}"
  [ ! -L "$ws/workspace" ] || refuse "the workspace's workspace folder is a symbolic link"
  if [ ! -d "$ws/workspace" ]; then
    [ ! -e "$ws/workspace" ] || refuse "the workspace's workspace folder is not a directory"
    mkdir "$ws/workspace" && chown 1000:1000 "$ws/workspace" && chmod 0755 "$ws/workspace" ||
      refuse "the workspace's workspace folder could not be created"
  fi
  mount --bind "$ws/workspace" "$dir" || refuse "binding the workspace folder failed"
fi
if [ -n "${CODEWIRE_DOCKER_DATA_SIZE:-}" ]; then
  (
    CODEWIRE_DOCKER_DATA_IMAGE="$ws/.codewire/docker-data.ext4"
"#,
    docker_data_image_prepare_text!(),
    r#"
  ) || echo "codewire mount-workspace: preparing the Docker data image failed; Docker reports it" >&2
fi
echo "codewire mount-workspace: mounted the $volume workspace volume (formatted=$fresh e2fsck_ms=$check_ms total_ms=$((($(date +%s%N) - began) / 1000000)))"
"#
);

/// Where a guest DinD finds its data image: under `/workspace` when that is
/// the filesystem's root, or under [`DIND_WORKSPACE_ROOT`] when `/workspace`
/// is the subfolder (#4026). The image stays at the filesystem root's
/// `.codewire/` either way.
fn docker_data_image_path(opts: &TemplateOpts, runtime_spec: &RuntimeProfileSpec) -> String {
    if opts.workspace_subfolder && block_workspace(opts, runtime_spec) {
        format!("{DIND_WORKSPACE_ROOT}/.codewire/docker-data.ext4")
    } else {
        "/workspace/.codewire/docker-data.ext4".to_owned()
    }
}

/// With `/workspace` the subfolder, DinD also sees the filesystem's root at
/// [`DIND_WORKSPACE_ROOT`] for its data image (#4026).
fn dind_mount_workspace_root(dind: &mut Value) {
    dind["volumeMounts"]
        .as_array_mut()
        .expect("dind volumeMounts array")
        .push(json!({
            "name": WORKSPACE_MOUNT_VOLUME,
            "mountPath": DIND_WORKSPACE_ROOT,
            "mountPropagation": "HostToContainer",
        }));
}

fn configure_confidential_workspace_device(container: &mut Value) {
    container["volumeMounts"]
        .as_array_mut()
        .expect("container volumeMounts array")
        .retain(|mount| mount["name"].as_str() != Some("workspace"));
    container["volumeDevices"] = json!([{
        "name": "workspace",
        "devicePath": KATA_CONFIDENTIAL_WORKSPACE_DEVICE_PATH,
    }]);
}

/// A workspace is Ready once its daemon process is up, signalled by the
/// marker it writes before it binds; Pod readiness never depends on the
/// binding (design §8, §10) or on Docker. The kubelet runs readiness only
/// after the startup probe succeeds, and then at once, so the 1-second startup
/// probe bounds how late a start notices the marker while the steady-state
/// readiness probe keeps its 2-second period. The startup budget is the tier's
/// ready timeout: create or start has already failed before the kubelet would
/// stop a slow start.
fn apply_daemon_ready_probes(ws: &mut Value, runtime_spec: &RuntimeProfileSpec) {
    let ready_timeout = ready_timeout(runtime_spec);
    ws["startupProbe"] = exec_probe(DAEMON_READY_PROBE, 1, ready_timeout.as_secs());
    ws["readinessProbe"] = exec_probe(DAEMON_READY_PROBE, 2, 3);
}

fn ready_timeout(runtime_spec: &RuntimeProfileSpec) -> std::time::Duration {
    if runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL {
        CONFIDENTIAL_WORKSPACE_READY_TIMEOUT
    } else {
        WORKSPACE_READY_TIMEOUT
    }
}

const DAEMON_READY_PROBE: &str = "test -f /codewire/run/daemon/ready";

fn exec_probe(command: &str, period_seconds: u64, failure_threshold: u64) -> Value {
    json!({
        "exec": {
            "command": [
                "sh",
                "-ec",
                command,
            ],
        },
        "periodSeconds": period_seconds,
        "timeoutSeconds": 2,
        "failureThreshold": failure_threshold,
        "successThreshold": 1,
    })
}

/// The Pod-bound projected token the daemon presents to `BindWorkspace`
/// (design §3.4). Same mode and lifetime as the gateway's binding token.
fn workspace_binding_token_volume() -> Value {
    json!({
        "name": WORKSPACE_BINDING_VOLUME,
        "projected": {
            "defaultMode": 0o440,
            "sources": [{
                "serviceAccountToken": {
                    "audience": WORKSPACE_BINDING_TOKEN_AUDIENCE,
                    "expirationSeconds": WORKSPACE_BINDING_TOKEN_EXPIRATION_SECONDS,
                    "path": "token",
                },
            }],
        },
    })
}

/// The volume of the binding listener's public roots.
pub(crate) const WORKSPACE_BINDING_ROOTS_VOLUME: &str = "orchestration-internal-roots";

/// Only the `ca.crt` key of orchestration's published internal roots: public
/// trust material, never a credential (daemon-hosted access §6).
fn workspace_binding_roots_volume() -> Value {
    json!({
        "name": WORKSPACE_BINDING_ROOTS_VOLUME,
        "configMap": {
            "name": ORCHESTRATION_INTERNAL_ROOTS_CONFIGMAP,
            "items": [{ "key": "ca.crt", "path": "ca.crt" }],
            "defaultMode": 0o444,
        },
    })
}

/// The volume of the coordinator's extra public roots (local clusters only).
pub(crate) const COORDINATOR_EXTRA_ROOTS_VOLUME: &str = "coordinator-extra-roots";

/// Only the `ca.crt` key of the coordinator's extra public roots: public trust
/// material, never a credential.
fn coordinator_extra_roots_volume() -> Value {
    json!({
        "name": COORDINATOR_EXTRA_ROOTS_VOLUME,
        "configMap": {
            "name": codewire_daemon_proto::COORDINATOR_EXTRA_ROOTS_CONFIGMAP,
            "items": [{ "key": "ca.crt", "path": "ca.crt" }],
            "defaultMode": 0o444,
        },
    })
}

/// The workspace container's `/codewire/bin`. An image volume exposes only the
/// support image's `usr/local/bin`, read-only; the copy is a private emptyDir.
fn daemon_mount(runtime_spec: &RuntimeProfileSpec) -> Value {
    if daemon_from_image_volume(runtime_spec) {
        json!({
            "name": DAEMON_VOLUME,
            "mountPath": "/codewire/bin",
            "subPath": SUPPORT_IMAGE_DAEMON_SUBPATH,
            "readOnly": true,
        })
    } else {
        json!({ "name": DAEMON_VOLUME, "mountPath": "/codewire/bin" })
    }
}

/// The daemon-copy init writes the whole `cw` (about 160 MB) through the page
/// cache, which its memory limit is charged for: under 128Mi a busy node could
/// kill the copy before writeback caught up. The request is unchanged, so
/// scheduling is unchanged.
fn bootstrap_resources() -> Value {
    json!({
        "requests": { "cpu": "25m", "memory": "32Mi" },
        "limits": { "cpu": "100m", "memory": "512Mi" },
    })
}

fn daemon_init_container(support_image: &str, profile: &str) -> Value {
    let mounts = json!([
        { "name": DAEMON_VOLUME, "mountPath": "/codewire/bin" },
        { "name": "codewire-run", "mountPath": "/codewire/run" },
    ]);
    if profile == RUNTIME_PROFILE_CONFIDENTIAL {
        // A confidential guest keeps the workspace-user copy its policy
        // admits; managed agents, which pin a root-owned daemon, are not
        // offered there.
        return json!({
            "name": DAEMON_INIT_CONTAINER,
            "image": support_image,
            "command": [
                "sh", "-c",
                "umask 077; mkdir -p /codewire/run/processes && chmod 0700 /codewire/run/processes && cp /usr/local/bin/cw /codewire/bin/.cw.tmp && chmod 0755 /codewire/bin/.cw.tmp && mv /codewire/bin/.cw.tmp /codewire/bin/cw",
            ],
            "volumeMounts": mounts,
            "resources": bootstrap_resources(),
        });
    }
    // Root installs the daemon as an image volume presents it: a root-owned
    // 0755 directory holding a root-owned 0555 executable, which the
    // daemon's own image pin requires. Only the process directory belongs to
    // the workspace user.
    json!({
        "name": DAEMON_INIT_CONTAINER,
        "image": support_image,
        "securityContext": { "runAsUser": 0, "runAsGroup": 0 },
        "command": [
            "sh", "-c",
            "umask 022; chown 0:0 /codewire/bin && chmod 0755 /codewire/bin && chmod g-s /codewire/bin && cp /usr/local/bin/cw /codewire/bin/.cw.tmp && chmod 0555 /codewire/bin/.cw.tmp && mv /codewire/bin/.cw.tmp /codewire/bin/cw && mkdir -p /codewire/run/processes && chown 1000:1000 /codewire/run/processes && chmod 0700 /codewire/run/processes",
        ],
        "volumeMounts": mounts,
        "resources": bootstrap_resources(),
    })
}

/// Prepares the loop-mounted Docker data image before DinD starts, from the
/// support image's e2fsprogs: the DinD image ships none since Docker 29.9.2
/// (#3208). It renders beside a guest DinD on every profile but confidential,
/// whose DinD keeps a plain directory on the protected disk. A commodity Pod
/// takes its daemon from an image volume and has no other init container, so
/// this one is its only serial step before the workspace starts; the
/// `codewire-daemon-init` name stays the daemon copy's alone
/// (`plan_daemon_image` reads it as the daemon's source).
pub(crate) const DOCKER_DATA_INIT_CONTAINER: &str = "codewire-docker-data-init";

/// The Docker data image variables DinD renders that the data init reads too.
pub(crate) const DOCKER_DATA_INIT_ENV: [&str; 3] = [
    "CODEWIRE_DOCKER_DATA_IMAGE",
    "CODEWIRE_DOCKER_DATA_SIZE",
    "CODEWIRE_DOCKER_MOUNT_MODE",
];

/// The data init's own limits. It formats a fresh image and checks and grows
/// a grown one before the workspace starts, so its CPU is not capped at the
/// daemon copy's 100m. The request, and so scheduling, matches the copy's.
fn docker_data_init_resources() -> Value {
    json!({
        "requests": { "cpu": "25m", "memory": "32Mi" },
        "limits": { "cpu": "1", "memory": "512Mi" },
    })
}

/// The data init for a guest DinD's environment: the same data image, size
/// and mount mode DinD renders, as root, with only the workspace volume.
pub(crate) fn docker_data_init_container(support_image: &str, env: Vec<Value>) -> Value {
    json!({
        "name": DOCKER_DATA_INIT_CONTAINER,
        "image": support_image,
        "securityContext": { "runAsUser": 0, "runAsGroup": 0 },
        "command": ["sh", "-c", docker_data_image_prepare_script()],
        "env": env,
        "volumeMounts": [{ "name": "workspace", "mountPath": "/workspace" }],
        "resources": docker_data_init_resources(),
    })
}

/// The data init's shell: it prepares the Docker data image offline, before
/// DinD mounts it, so DinD needs only busybox. It never fails the init
/// container: Docker never decides whether the workspace starts (owner,
/// 2026-10-06), so a failure is logged and DinD then reports a missing image
/// or starts at its previous size.
///
/// - The image's directory, the workspace home's `.codewire`, is the
///   workspace user's and owner-writable only.
/// - A missing or empty image is created at the rendered size and formatted
///   lazily; a failed create removes it, so the next start tries again.
/// - A grown workspace disk renders a larger size: the image is extended to
///   it, never shrunk, and a malformed size is ignored. Whenever the image is
///   larger than its filesystem, including after an interrupted grow, the
///   filesystem is checked and grown offline to fill it.
pub(crate) fn docker_data_image_prepare_script() -> &'static str {
    DOCKER_DATA_IMAGE_PREPARE_SCRIPT
}

const DOCKER_DATA_IMAGE_PREPARE_SCRIPT: &str = docker_data_image_prepare_text!();

/// The DinD bootstrap Sandboxes were rendered with before 531fc0f7e, exactly
/// as their stored Pod specs carry it. It made the workspace home's
/// `.codewire` group-writable (0775) at every Pod start, so a workspace daemon
/// with the hosted credential bridge refused its platform session store. A
/// Start or Pod replacement re-renders it (#2639); nothing renders it now.
pub(crate) const LEGACY_DIND_BOOTSTRAP_SCRIPT: &str = r#"data_image="${CODEWIRE_DOCKER_DATA_IMAGE:-/workspace/.codewire/docker-data.ext4}"
data_root="${CODEWIRE_DOCKER_DATA_ROOT:-/var/lib/docker}"
data_size="${CODEWIRE_DOCKER_DATA_SIZE:-8G}"
mount_mode="${CODEWIRE_DOCKER_MOUNT_MODE:-loop}"
codewire_dir="$(dirname "$data_image")"
mkdir -p "$codewire_dir" "$data_root"
chown 1000:1000 "$codewire_dir"
chmod 0775 "$codewire_dir"
if [ "$mount_mode" = "loop" ]; then
  if [ ! -s "$data_image" ]; then
    truncate -s "$data_size" "$data_image"
    mkfs.ext4 -q -F "$data_image"
  fi
  if ! awk -v target="$data_root" '$2 == target && $3 == "ext4" { found = 1 } END { exit found ? 0 : 1 }' /proc/mounts; then
    mount -o loop "$data_image" "$data_root"
  fi
elif [ "$mount_mode" != "none" ]; then
  echo "unsupported CODEWIRE_DOCKER_MOUNT_MODE=$mount_mode" >&2
  exit 1
fi
exec dockerd --host "unix:///var/run/docker/docker.sock" --group 1000 --data-root "$data_root" --storage-driver vfs"#;

/// The DinD bootstrap rendered from 531fc0f7e until Program #2238 made its
/// `mkfs.ext4` lazy. It differs from [`pre_growth_dind_bootstrap_script`]
/// only there; a Sandbox that carries it formatted its image on its first
/// start. It never grew the image either, so Start and Pod replacement
/// re-render it (#3554).
pub(crate) fn eager_mkfs_dind_bootstrap_script() -> String {
    pre_growth_dind_bootstrap_script().replace(LAZY_MKFS, r#"    mkfs.ext4 -q -F "$data_image""#)
}

/// The DinD bootstrap rendered from Program #2238's lazy `mkfs.ext4` until
/// #3554. It differs from [`growth_in_dind_bootstrap_script`] only in growing
/// the Docker data image: it created the image once and never grew it, so a
/// grown workspace disk left Docker at its first size. Start and Pod
/// replacement re-render it.
pub(crate) fn pre_growth_dind_bootstrap_script() -> String {
    growth_in_dind_bootstrap_script().replace(&format!("\n{DATA_IMAGE_GROWTH}"), "")
}

/// The DinD bootstrap rendered from #3554 until #3208, which formats and
/// grows the Docker data image inside DinD with e2fsprogs. The Docker
/// 29.9.2 DinD image ships none, so a commodity or runc Sandbox that carries
/// it fails to start Docker on that image (`mkfs.ext4: not found`, exit
/// 127). Start and Pod replacement re-render it to [`dind_bootstrap_script`]
/// beside the [`DOCKER_DATA_INIT_CONTAINER`] that prepares the image.
///
/// A confidential DinD still renders it: there it keeps a plain directory
/// (`CODEWIRE_DOCKER_MOUNT_MODE=none`), so it runs only busybox `mkdir`,
/// `chown` and `chmod`, and no init container can reach the protected disk
/// to own `.codewire` in its place.
pub(crate) fn growth_in_dind_bootstrap_script() -> String {
    format!(
        r#"data_image="${{CODEWIRE_DOCKER_DATA_IMAGE:-/workspace/.codewire/docker-data.ext4}}"
data_root="${{CODEWIRE_DOCKER_DATA_ROOT:-/var/lib/docker}}"
data_size="${{CODEWIRE_DOCKER_DATA_SIZE:-8G}}"
mount_mode="${{CODEWIRE_DOCKER_MOUNT_MODE:-loop}}"
codewire_dir="$(dirname "$data_image")"
mkdir -p "$codewire_dir" "$data_root"
chown 1000:1000 "$codewire_dir"
# Owner-writable only: the workspace daemon refuses a group- or
# world-writable ancestor of its platform session store.
chmod 0755 "$codewire_dir"
if [ "$mount_mode" = "loop" ]; then
  if [ ! -s "$data_image" ]; then
    truncate -s "$data_size" "$data_image"
{LAZY_MKFS}
  fi
  if ! awk -v target="$data_root" '$2 == target && $3 == "ext4" {{ found = 1 }} END {{ exit found ? 0 : 1 }}' /proc/mounts; then
    mount -o loop "$data_image" "$data_root"
  fi
{DATA_IMAGE_GROWTH}
elif [ "$mount_mode" != "none" ]; then
  echo "unsupported CODEWIRE_DOCKER_MOUNT_MODE=$mount_mode" >&2
  exit 1
fi
exec dockerd --host "unix://{DIND_SOCKET_PATH}" --group 1000 --data-root "$data_root" --storage-driver vfs"#
    )
}

/// After the mount, a grown workspace disk renders a larger data size:
/// extend the image to it (never shrinking it) and grow its mounted
/// filesystem online to fill the image. An interrupted grow finishes at the
/// next start.
const DATA_IMAGE_GROWTH: &str = r#"  # A grown workspace disk renders a larger data size: extend the image to
  # it, never shrinking it, and grow its mounted filesystem online to fill
  # the image. Growth keeps every byte, and a failed grow still starts
  # Docker at its previous size (#3554).
  data_gib="${data_size%G}"
  case "$data_gib" in ''|*[!0-9]*) data_gib=0 ;; esac
  if [ "$(stat -c %s "$data_image")" -lt "$((data_gib * 1073741824))" ]; then
    truncate -s "$data_size" "$data_image" || true
  fi
  data_device="$(awk -v target="$data_root" '$2 == target && $3 == "ext4" { print $1; exit }' /proc/mounts)"
  data_fs_bytes="$(dumpe2fs -h "$data_device" 2>/dev/null | awk -F: '$1 == "Block count" { count = $2 } $1 == "Block size" { size = $2 } END { printf "%.0f", count * size }')"
  if [ "$(stat -c %s "$data_image")" -gt "${data_fs_bytes:-0}" ]; then
    { losetup -c "$data_device" && resize2fs "$data_device"; } ||
      echo "the Docker data filesystem did not grow to $data_size; Docker keeps its previous size" >&2
  fi"#;

const LAZY_MKFS: &str = r#"    # A fresh sparse image reads as zeros, so mke2fs skips zeroing its
    # inode tables and journal: a few MiB of writes at any size.
    mkfs.ext4 -q -F -E lazy_itable_init=1,lazy_journal_init=1 "$data_image""#;

/// The guest DinD bootstrap of every profile but confidential: it mounts the
/// data image [`DOCKER_DATA_INIT_CONTAINER`] prepared and starts Docker on
/// it, with only busybox, which the DinD image keeps (#3208). A missing image
/// stops Docker with a reason, never the workspace.
fn dind_mount_script() -> String {
    format!(
        r#"data_image="${{CODEWIRE_DOCKER_DATA_IMAGE:-/workspace/.codewire/docker-data.ext4}}"
data_root="${{CODEWIRE_DOCKER_DATA_ROOT:-/var/lib/docker}}"
mount_mode="${{CODEWIRE_DOCKER_MOUNT_MODE:-loop}}"
mkdir -p "$data_root"
if [ "$mount_mode" = "loop" ]; then
  if [ ! -s "$data_image" ]; then
    echo "the Docker data image $data_image is missing; the {DOCKER_DATA_INIT_CONTAINER} init container prepares it before Docker starts" >&2
    exit 1
  fi
  if ! awk -v target="$data_root" '$2 == target && $3 == "ext4" {{ found = 1 }} END {{ exit found ? 0 : 1 }}' /proc/mounts; then
    mount -o loop "$data_image" "$data_root"
  fi
elif [ "$mount_mode" != "none" ]; then
  echo "unsupported CODEWIRE_DOCKER_MOUNT_MODE=$mount_mode" >&2
  exit 1
fi"#
    )
}

/// Frozen VFS bootstrap retained for local profiles and recognized old Sandboxes.
pub(crate) fn dind_bootstrap_script() -> String {
    format!(
        "{}\nexec dockerd --host \"unix://{DIND_SOCKET_PATH}\" --group 1000 --data-root \"$data_root\" --storage-driver vfs",
        dind_mount_script()
    )
}

/// Commodity Docker delegates its cgroup before starting daemon subprocesses.
/// Its persistent ext4 store uses the containerd image store and OverlayFS.
pub(crate) fn commodity_dind_bootstrap_script() -> String {
    use super::dind::{BOOTSTRAP_FAILURE, CGROUP_INIT, PREPARE_STORE, VERIFY_STORE_MOUNT};
    format!(
        "{BOOTSTRAP_FAILURE}\n{CGROUP_INIT}\n{}\n\
{VERIFY_STORE_MOUNT}\n\
{PREPARE_STORE}\n\
exec dockerd --host \"unix://{DIND_SOCKET_PATH}\" --group 1000 --data-root \"$data_root\" --feature containerd-snapshotter=true --storage-driver overlayfs",
        dind_mount_script()
    )
    // Kubernetes consumes each `$$` in command/args before invoking the shell.
    // Preserve the shell PID in the self-only cgroup move and marker nonce.
    .replace("$$", "$$$$")
}

/// The Docker data variables a guest DinD renders: a loop-mounted image at
/// `/var/lib/docker`, or on confidential a plain directory on the protected
/// disk.
fn guest_dind_data_env(opts: &TemplateOpts, runtime_spec: &RuntimeProfileSpec) -> Vec<Value> {
    let (data_root, mount_mode) = if runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL {
        ("/workspace/.codewire/docker-root", "none")
    } else {
        ("/var/lib/docker", "loop")
    };
    vec![
        json!({ "name": "CODEWIRE_DOCKER_DATA_IMAGE", "value": docker_data_image_path(opts, runtime_spec) }),
        json!({ "name": "CODEWIRE_DOCKER_DATA_ROOT", "value": data_root }),
        json!({ "name": "CODEWIRE_DOCKER_DATA_SIZE", "value": format!("{}G", docker_data_size_gib(opts.disk_gib)) }),
        json!({ "name": "CODEWIRE_DOCKER_MOUNT_MODE", "value": mount_mode }),
    ]
}

/// The data init's variables when a Pod prepares a Docker data image: beside
/// a guest DinD with a loop-mounted image, never on confidential. A Block Pod
/// gives them to `mount-workspace`, every other Pod to the data init.
fn docker_data_init_env(
    opts: &TemplateOpts,
    runtime_spec: &RuntimeProfileSpec,
) -> Option<Vec<Value>> {
    if runtime_spec.docker_mode != DOCKER_MODE_GUEST_DIND
        || runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL
    {
        return None;
    }
    Some(
        guest_dind_data_env(opts, runtime_spec)
            .into_iter()
            .filter(|entry| {
                entry["name"]
                    .as_str()
                    .is_some_and(|name| DOCKER_DATA_INIT_ENV.contains(&name))
            })
            .collect(),
    )
}

fn dind_container(
    opts: &TemplateOpts,
    runtime_spec: &RuntimeProfileSpec,
    ext4_data_root: bool,
) -> Value {
    let command = if ext4_data_root && runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL {
        json!(["sh", "-ec", growth_in_dind_bootstrap_script()])
    } else if ext4_data_root && runtime_spec.profile == RUNTIME_PROFILE_COMMODITY {
        json!(["sh", "-ec", commodity_dind_bootstrap_script()])
    } else if ext4_data_root {
        json!(["sh", "-ec", dind_bootstrap_script()])
    } else {
        json!([
            "dockerd",
            "--host",
            format!("unix://{DIND_SOCKET_PATH}"),
            "--group",
            "1000",
            "--storage-driver",
            "vfs"
        ])
    };
    let env = if ext4_data_root {
        let mut env = vec![json!({ "name": "DOCKER_TLS_CERTDIR", "value": "" })];
        env.extend(guest_dind_data_env(opts, runtime_spec));
        Value::Array(env)
    } else {
        json!([ { "name": "DOCKER_TLS_CERTDIR", "value": "" } ])
    };

    json!({
        "name": "dind",
        "image": dind_image(opts),
        "command": command,
        "securityContext": { "privileged": true, "runAsUser": 0, "runAsGroup": 0 },
        "env": env,
        "volumeMounts": [
            { "name": "docker-sock", "mountPath": "/var/run/docker" },
            { "name": "workspace", "mountPath": "/workspace" },
        ],
        "resources": {
            "requests": { "cpu": "500m", "memory": "1Gi" },
            "limits": { "cpu": "2", "memory": format!("{}Gi", dind_memory_limit_gib(opts.memory_mib)) },
        },
    })
}

fn build_workspace_env(opts: &TemplateOpts) -> Vec<Value> {
    // Design §13: no daemon token, environment ID, generation, projection
    // digest, managed clients or derived client variables. The daemon gets all
    // of them from its binding.
    let mut environment = vec![
        json!({ "name": "CODEWIRE_WORKSPACE_SHIM_ADDR", "value": WORKSPACE_DAEMON_LISTEN_ADDR }),
        json!({ "name": "HOME", "value": HOME_ROOT }),
        json!({ "name": "USER", "value": "codewire" }),
        json!({ "name": WORKSPACE_BINDING_URL_ENV, "value": opts.workspace_binding_url }),
        json!({
            "name": WORKSPACE_POD_UID_ENV,
            "valueFrom": { "fieldRef": { "fieldPath": "metadata.uid" } },
        }),
    ];
    // A confidential workspace's measured anchors (B2c), pinned exactly by
    // its measured Kata policy. The binding URL above is one of them.
    if opts.runtime_profile_spec().profile == RUNTIME_PROFILE_CONFIDENTIAL {
        let measured = opts
            .measured_workspace_environment()
            .expect("a confidential workspace renders only with measured binding roots");
        environment.extend(
            measured
                .into_iter()
                .filter(|(name, _)| *name != WORKSPACE_BINDING_URL_ENV)
                .map(|(name, value)| json!({ "name": name, "value": value })),
        );
    }
    // Kind's test deployment only; production renders no such variable.
    if let Some(seconds) = opts.codex_login_check_period_seconds {
        environment.push(json!({
            "name": codewire_daemon::CODEX_LOGIN_CHECK_PERIOD_ENV,
            "value": seconds.to_string(),
        }));
    }
    environment
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// The gateway and orchestration reach the workspace daemon through this
/// Service. A commodity Service publishes the Pod before it is Ready, so the
/// gateway connects as soon as the daemon listens instead of after the
/// kubelet's next readiness probe. Create and start still wait for the Pod to
/// be Ready through the SandboxClaim. Confidential keeps Ready-only endpoints;
/// its start path is not part of this change.
pub fn render_workspace_daemon_service(namespace: &str, opts: &TemplateOpts) -> Value {
    let publish_not_ready = opts.runtime_profile_spec().profile != RUNTIME_PROFILE_CONFIDENTIAL;
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": workspace_daemon_service_name(&opts.environment_id),
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "codewire-workspace-daemon",
                "app.kubernetes.io/component": "workspace-daemon",
                "app.kubernetes.io/managed-by": "codewire",
                "codewire.sh/environment-id": opts.environment_id,
                "codewire.sh/type": "workspace-daemon",
            },
        },
        "spec": {
            "type": "ClusterIP",
            "selector": workspace_selector(opts),
            "publishNotReadyAddresses": publish_not_ready,
            "ports": [
                { "name": "daemon", "protocol": "TCP", "port": WORKSPACE_DAEMON_PORT, "targetPort": WORKSPACE_DAEMON_PORT },
            ],
        },
    })
}

/// The sandbox-namespace ConfigMap with the public roots of orchestration's
/// internal TLS listeners. The infrastructure owner provisions it; workspaces
/// mount it and orchestration checks its own leaf against it at startup.
pub const ORCHESTRATION_INTERNAL_ROOTS_CONFIGMAP: &str = "codewire-orchestration-internal-roots";

/// The DNS name of orchestration's internal TLS listener in `server_namespace`:
/// the name Mesh calls and its leaf Certificate names.
pub fn orchestration_internal_tls_host(server_namespace: &str) -> String {
    format!("codewire-orchestration.{server_namespace}.svc.cluster.local")
}
