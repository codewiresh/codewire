//! Workspace SandboxTemplate, pod, storage, and daemon-service rendering.

use serde_json::{Map, Value, json};

use super::credentials;
use super::encoding::kata_policy_init_data_annotation;
use super::naming::{workspace_daemon_service_name, workspace_selector, workspace_template_labels};
use super::network::{identity_free_workspace_egress_rules, workspace_egress_rules};
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
    CONFIDENTIAL_WORKSPACE_READY_TIMEOUT, DAEMON_AUTH_TOKEN_ENV, DIND_SOCKET_PATH,
    EXTENSIONS_API_VERSION, HOME_ROOT, KATA_COCO_INIT_DATA_ANNOTATION_KEY,
    KATA_CONFIDENTIAL_VOLUME_ANNOTATION, KATA_CONFIDENTIAL_WORKSPACE_DEVICE_PATH,
    KATA_HYPERVISOR_KERNEL_PARAMS_ANNOTATION_KEY, SANDBOX_SERVICE_ACCOUNT, TemplateOpts,
    WORKSPACE_ANNOTATION_KEY, WORKSPACE_DAEMON_LISTEN_ADDR, WORKSPACE_DAEMON_PORT,
    WORKSPACE_DISK_GIB_ANNOTATION_KEY, WORKSPACE_EPHEMERAL_STORAGE_GI, WORKSPACE_READY_TIMEOUT,
};

/// Copies the daemon from the support image into `codewire-bin` where the
/// daemon cannot be mounted from the image itself.
pub(crate) const DAEMON_INIT_CONTAINER: &str = "codewire-daemon-init";
/// The init container that once copied Codex's ConfigMap into a memory home
/// for an image-volume Pod. It is no longer rendered: the daemon writes
/// `~/.codex` itself. The name stays so a start removes it from older objects.
pub(crate) const CLIENT_BOOTSTRAP_CONTAINER: &str = "codewire-client-bootstrap";
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
    // An identity-free template carries no environment label (design §13);
    // its environment-owned shadow pool names it.
    let labels = if opts.identity_free() {
        json!({})
    } else {
        json!({ super::LABEL_ENV_ID: opts.environment_id })
    };
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
                !opts.identity_free(),
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
                "cpu": format!("{}m", opts.cpu_millicores),
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
pub(super) fn managed_workspace_supervisor_command(
    ensure_user: &str,
    wait_daemon: &str,
    daemon_command: &str,
) -> String {
    format!(
        "{ensure_user} {wait_daemon} \
         {daemon_command} & daemon_pid=$!; \
         shutdown() {{ \
           kill -TERM \"$daemon_pid\" 2>/dev/null || true; \
           wait \"$daemon_pid\" 2>/dev/null || true; \
         }}; \
         trap 'shutdown; exit 143' TERM; \
         trap 'shutdown; exit 130' INT; \
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
    unset_environment_token: bool,
) -> String {
    // A legacy workload starts without the rendered environment token; an
    // identity-free container has none to remove.
    let workload = if unset_environment_token {
        format!("(unset {DAEMON_AUTH_TOKEN_ENV}; exec {entrypoint})")
    } else {
        format!("(exec {entrypoint})")
    };
    format!(
        "{ensure_user} {wait_daemon} \
         {daemon_command} & daemon_pid=$!; \
         {workload} & workload_pid=$!; \
         shutdown() {{ \
           kill \"$workload_pid\" \"$daemon_pid\" 2>/dev/null || true; \
           wait \"$workload_pid\" 2>/dev/null || true; \
           wait \"$daemon_pid\" 2>/dev/null || true; \
         }}; \
         trap 'shutdown; exit 0' TERM INT; \
         while kill -0 \"$workload_pid\" 2>/dev/null; do \
           if ! kill -0 \"$daemon_pid\" 2>/dev/null; then \
             wait \"$daemon_pid\" 2>/dev/null || true; \
             sleep 1; \
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
        if confidential {
            claim_spec["volumeMode"] = "Block".into();
        }
        spec.insert(
            "volumeClaimTemplates".into(),
            json!([{
                "metadata": metadata,
                "spec": claim_spec,
            }]),
        );
    }

    let egress = if opts.identity_free() {
        identity_free_workspace_egress_rules(opts)
    } else {
        workspace_egress_rules(opts)
    };
    spec.insert("networkPolicy".into(), json!({ "egress": egress }));

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
    let daemon_image_volume = daemon_from_image_volume(&runtime_spec);
    let daemon_volume = if daemon_image_volume {
        json!({
            "name": DAEMON_VOLUME,
            "image": { "reference": support_image, "pullPolicy": "IfNotPresent" },
        })
    } else {
        json!({ "name": DAEMON_VOLUME, "emptyDir": {} })
    };
    let mut volumes = vec![
        daemon_volume,
        json!({ "name": "codewire-run", "emptyDir": {} }),
    ];
    if opts.disk_gib == 0 {
        volumes.insert(0, json!({ "name": "workspace", "emptyDir": {} }));
    }
    if opts.credential_runtime.is_some() {
        volumes.extend(credentials::workspace_volumes(opts));
        ws["volumeMounts"]
            .as_array_mut()
            .expect("workspace mounts")
            .extend(credentials::workspace_mounts());
        // An identity-free daemon expands its managed clients into child
        // environments from the bind response; nothing is rendered here.
        if !opts.identity_free() {
            ws["env"]
                .as_array_mut()
                .expect("workspace env")
                .extend(credentials::workspace_environment(opts));
        }
    }
    if opts.identity_free() {
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
        // The public roots that verify the binding listener's TLS identity.
        volumes.push(workspace_binding_roots_volume());
        ws["volumeMounts"]
            .as_array_mut()
            .expect("workspace mounts")
            .push(json!({
                "name": WORKSPACE_BINDING_ROOTS_VOLUME,
                "mountPath": WORKSPACE_BINDING_TLS_ROOTS_MOUNT_PATH,
                "readOnly": true,
            }));
        // A local cluster's coordinator is not WebPKI-signed: only there does
        // orchestration mount the public bundle the daemon trusts beside the
        // WebPKI roots for its coordinator. Dev and Production never do.
        if opts.coordinator_extra_roots {
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
    }

    let mut spec = Map::new();
    spec.insert("restartPolicy".into(), "Never".into());
    spec.insert("serviceAccountName".into(), SANDBOX_SERVICE_ACCOUNT.into());
    spec.insert("automountServiceAccountToken".into(), false.into());
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
        apply_docker_socket_probes(ws, opts, &runtime_spec);

        containers.push(ws.clone());
        let mut dind = dind_container(opts, &runtime_spec, false);
        if confidential_block {
            configure_confidential_workspace_device(&mut dind);
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
        apply_docker_socket_probes(ws, opts, &runtime_spec);

        containers.push(ws.clone());
        let mut dind = dind_container(opts, &runtime_spec, true);
        if confidential_block {
            configure_confidential_workspace_device(&mut dind);
        }
        containers.push(dind);
    } else {
        if opts.identity_free() {
            apply_daemon_ready_probes(ws, &runtime_spec);
        }
        containers.push(ws.clone());
    }

    // The daemon in the workspace container writes Codex's `~/.codex` on the
    // persistent home itself, in both identity modes, so no init container
    // copies client configuration. On confidential, no init container can
    // reach that protected disk at all.
    if !daemon_image_volume {
        spec.insert(
            "initContainers".into(),
            json!([daemon_init_container(support_image, &runtime_spec.profile)]),
        );
    }
    spec.insert("containers".into(), Value::Array(containers));
    spec.insert("volumes".into(), Value::Array(volumes));
    Value::Object(spec)
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

/// Workspace readiness proves the cross-container Docker socket, and create
/// and start wait for that readiness. The kubelet runs readiness only after
/// the startup probe succeeds, and then at once, so the 1-second startup probe
/// bounds how late a start notices Docker while the steady-state readiness
/// probe keeps its 2-second period. The startup budget is the tier's ready
/// timeout: create or start has already failed before the kubelet would stop
/// a slow Docker start.
fn apply_docker_socket_probes(
    ws: &mut Value,
    opts: &TemplateOpts,
    runtime_spec: &RuntimeProfileSpec,
) {
    let ready_timeout = ready_timeout(runtime_spec);
    // An identity-free daemon writes its local readiness marker before it
    // binds; Pod readiness never depends on the binding, because
    // orchestration binds only after the Pod is Ready (design §8, §10).
    let command = if opts.identity_free() {
        DAEMON_READY_AND_DOCKER_PROBE
    } else {
        DOCKER_PROBE
    };
    ws["startupProbe"] = exec_probe(command, 1, ready_timeout.as_secs());
    ws["readinessProbe"] = exec_probe(command, 2, 3);
}

/// Without DinD an identity-free workspace is Ready once its daemon process
/// is up, signalled by the marker; before B2 it had no readiness probe.
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

const DOCKER_PROBE: &str = "docker version --format '{{.Server.Version}}' >/dev/null";
const DAEMON_READY_PROBE: &str = "test -f /codewire/run/daemon/ready";
const DAEMON_READY_AND_DOCKER_PROBE: &str = "test -f /codewire/run/daemon/ready && docker version --format '{{.Server.Version}}' >/dev/null";

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

fn bootstrap_resources() -> Value {
    json!({
        "requests": { "cpu": "25m", "memory": "32Mi" },
        "limits": { "cpu": "100m", "memory": "128Mi" },
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

/// Only machine-owned stock-client fields, without rendering confidential
/// init-data or resolving public trust. Used by suspended recipe refresh and
/// exact immutable Pod verification; it contains no provider material.
///
/// `init` is the daemon-copy init of a Pod whose `codewire-bin` is an
/// emptyDir. `clientInit` is the client bootstrap of an image-volume Pod. No
/// client volume, mount or init copy is rendered any more: the daemon writes
/// Codex's `~/.codex` itself. Reconciling against this removes the ones an
/// older object still carries.
pub(crate) fn render_workspace_client_bootstrap(opts: &TemplateOpts) -> Value {
    json!({
        "environment": credentials::workspace_environment(opts),
        "volumes": [],
        "volumeMounts": [],
        "init": daemon_init_container("", &opts.runtime_profile_spec().profile),
        "clientInit": null,
    })
}

pub(super) fn dind_bootstrap_script() -> String {
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
    mkfs.ext4 -q -F "$data_image"
  fi
  if ! awk -v target="$data_root" '$2 == target && $3 == "ext4" {{ found = 1 }} END {{ exit found ? 0 : 1 }}' /proc/mounts; then
    mount -o loop "$data_image" "$data_root"
  fi
elif [ "$mount_mode" != "none" ]; then
  echo "unsupported CODEWIRE_DOCKER_MOUNT_MODE=$mount_mode" >&2
  exit 1
fi
exec dockerd --host "unix://{DIND_SOCKET_PATH}" --group 1000 --data-root "$data_root" --storage-driver vfs"#
    )
}

fn dind_container(
    opts: &TemplateOpts,
    runtime_spec: &RuntimeProfileSpec,
    ext4_data_root: bool,
) -> Value {
    let command = if ext4_data_root {
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
        let (data_root, mount_mode) = if runtime_spec.profile == RUNTIME_PROFILE_CONFIDENTIAL {
            ("/workspace/.codewire/docker-root", "none")
        } else {
            ("/var/lib/docker", "loop")
        };
        json!([
            { "name": "DOCKER_TLS_CERTDIR", "value": "" },
            { "name": "CODEWIRE_DOCKER_DATA_IMAGE", "value": "/workspace/.codewire/docker-data.ext4" },
            { "name": "CODEWIRE_DOCKER_DATA_ROOT", "value": data_root },
            { "name": "CODEWIRE_DOCKER_DATA_SIZE", "value": format!("{}G", docker_data_size_gib(opts.disk_gib)) },
            { "name": "CODEWIRE_DOCKER_MOUNT_MODE", "value": mount_mode },
        ])
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
    if let Some(binding_url) = opts.workspace_binding_url() {
        // Design §13: no daemon token, environment ID, generation, projection
        // digest, managed clients or derived client variables. The daemon
        // gets all of them from its binding.
        return vec![
            json!({ "name": "CODEWIRE_WORKSPACE_SHIM_ADDR", "value": WORKSPACE_DAEMON_LISTEN_ADDR }),
            json!({ "name": "HOME", "value": HOME_ROOT }),
            json!({ "name": "USER", "value": "codewire" }),
            json!({ "name": WORKSPACE_BINDING_URL_ENV, "value": binding_url }),
            json!({
                "name": WORKSPACE_POD_UID_ENV,
                "valueFrom": { "fieldRef": { "fieldPath": "metadata.uid" } },
            }),
        ];
    }
    codewire_daemon_proto::DaemonAuthToken::new(opts.daemon_auth_token.clone())
        .expect("hosted workspace requires a canonical daemon auth token");
    let mut environment = vec![
        json!({ "name": "CODEWIRE_WORKSPACE_SHIM_ADDR", "value": WORKSPACE_DAEMON_LISTEN_ADDR }),
        json!({ "name": "HOME", "value": HOME_ROOT }),
        json!({ "name": "USER", "value": "codewire" }),
        json!({ "name": DAEMON_AUTH_TOKEN_ENV, "value": opts.daemon_auth_token }),
    ];
    if let Some(projection) = credentials::projection_environment(opts) {
        assert!(
            opts.operation_generation > 0,
            "projection requires operation identity"
        );
        environment.extend([
            json!({"name":"CODEWIRE_ENVIRONMENT_ID","value":opts.environment_id}),
            json!({"name":"CODEWIRE_ENVIRONMENT_OPERATION_GENERATION","value":opts.operation_generation.to_string()}),
            json!({"name":credentials::MANAGED_CREDENTIAL_CLIENTS_ENV,"value":opts.managed_credential_clients.encode()}),
            projection,
        ]);
    }
    environment
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// The gateway and orchestration reach the workspace daemon through this
/// Service. The daemon listens as soon as the workspace container starts, but
/// the Pod turns Ready only after its Docker socket probe. A commodity Service
/// therefore publishes the Pod before it is Ready, so the gateway connects
/// while Docker starts instead of after it. Create and start still wait for
/// the Pod to be Ready through the SandboxClaim. Confidential keeps Ready-only
/// endpoints; its start path is not part of this change.
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
