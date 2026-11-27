//! The `standard` workspace Pod (#5602): one container of Codewire's runtime
//! image, whose entrypoint boots the workspace's VM over the workspace image's
//! published disk. `SPEC.md` section 4 states what the Pod holds, and "The
//! `standard` profile" in `docs/dev/CODEWIRE-GUARD-RUNTIME-PROFILES.md` what
//! admission requires of it.

use std::net::SocketAddrV4;

use serde_json::{Map, Value, json};

use codewire_daemon_proto::{
    POD_RUNTIME_DOCKER_DISK_MIB_ENV, POD_RUNTIME_EGRESS_MODE_BROKER, POD_RUNTIME_EGRESS_MODE_ENV,
    POD_RUNTIME_IMAGE_DIGEST_ENV, POD_RUNTIME_IMAGE_DISK_BUILD_ID_ENV,
    POD_RUNTIME_IMAGE_DISK_ID_ENV, POD_RUNTIME_IMAGE_DISK_MOUNT_PATH, POD_RUNTIME_MEMORY_MIB_ENV,
    POD_RUNTIME_PLATFORM_PEERS_ENV, POD_RUNTIME_RESTORE_GENERATION_ENV,
    POD_RUNTIME_STATE_DISK_MIB_ENV, POD_RUNTIME_STATE_MOUNT_PATH, POD_RUNTIME_UDP_PEERS_ENV,
    POD_RUNTIME_VCPUS_ENV, POD_RUNTIME_VM_STATE_ENV, POD_RUNTIME_VM_STATE_EXISTING,
    POD_RUNTIME_VM_STATE_NEW, POD_RUNTIME_WORKSPACE_IMAGE_ENV, POD_RUNTIME_WORKSPACE_INIT_ENV,
    POD_RUNTIME_WORKSPACE_INIT_IMAGE, POD_RUNTIME_WORKSPACE_INIT_SYSTEMD,
};

use crate::sandbox::runtime_images::{RuntimeImages, SystemdWorkspaceImage};

use super::runtime_policy::{
    RUNTIME_CLASS_STANDARD, STANDARD_VMM_CPU_MILLICORES, STANDARD_VMM_MEMORY_MIB,
};
use super::workspace::{apply_daemon_ready_probes, build_workspace_env, run_volume};
use super::{
    HostedEgressTemplate, SANDBOX_SERVICE_ACCOUNT, TemplateOpts, WORKSPACE_DAEMON_PORT,
    WORKSPACE_EPHEMERAL_STORAGE_GI, hosted_egress, identity,
};

/// The runtime image every `standard` workspace runs, by digest.
pub const STANDARD_RUNTIME_IMAGE_ENV: &str = "SANDBOX_STANDARD_RUNTIME_IMAGE";
/// The workspace image's published disk, as the line its publish step
/// prints: `<disk reference>@sha256:<digest> <image disk id> <build id>
/// <workspace image>@sha256:<manifest digest>`. The runtime refuses a
/// workspace image other than the one the disk was built from, so both come
/// from this one value.
pub const STANDARD_IMAGE_DISK_ENV: &str = "SANDBOX_STANDARD_IMAGE_DISK";
/// The one device a `standard` Pod is given, by the node's device plugin.
pub(crate) const KVM_DEVICE_RESOURCE: &str = "codewire.sh/kvm";
/// The runtime bounds the guest's power-off at 45 s, inside this.
const TERMINATION_GRACE_SECONDS: i64 = 60;
const IMAGE_DISK_VOLUME: &str = "image-disk";
/// The share of the Sandbox's volume its filesystem keeps for itself, which
/// the VM process cannot use: it is not root, so ext4's reserved blocks are
/// not its. The disks are sparse files of the rest, so the guest can never
/// fill the volume under them.
const STATE_DISK_RESERVE_PERCENT: i64 = 7;
const STATE_DISK_RESERVE_MIB: i64 = 256;
/// The VM's root disk, its changes over the image, which `cw __pod-runtime`
/// also keeps on the Sandbox's volume. It costs the user this much of their
/// disk against `commodity` until it moves to the Pod's own storage (#5602).
const STANDARD_ROOT_DISK_MIB: i64 = 4_096;
/// The Docker data disk's share of the room the VM's disks have on the
/// volume; the state disk has the rest. The disks are never larger together
/// than that room, so the guest can never fill the volume under them.
const DOCKER_DISK_SHARE_PERCENT: i64 = 50;
/// The smallest Docker data disk `cw __pod-runtime` takes.
pub(super) const MIN_DOCKER_DISK_MIB: i64 = 1_024;
/// The smallest disk a `standard` workspace takes: its state and Docker disks
/// are then about 1.6 GiB each.
pub(super) const MIN_DISK_GIB: i64 = 8;
/// What `cw __pod-runtime` accepts (`crates/codewire-local-vmm`).
const MAX_VCPUS: i64 = 32;
const MEMORY_MIB_RANGE: std::ops::RangeInclusive<i64> = 128..=65_536;

/// The runtime image and the published workspace image disk a deployment's
/// `standard` workspaces run, parsed once at startup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandardRuntime {
    runtime_image: String,
    image_disk: String,
    image_disk_id: String,
    build_id: String,
    workspace_image: String,
    /// Whether the disk's workspace image boots systemd as its container's
    /// first process ([`Self::with_systemd_repository`]).
    boots_systemd: bool,
}

impl StandardRuntime {
    /// [`STANDARD_RUNTIME_IMAGE_ENV`] and [`STANDARD_IMAGE_DISK_ENV`]: both,
    /// or neither for a deployment with no `standard` workspace. Anything
    /// else is refused, so a typo stops orchestration instead of rendering a
    /// Pod the node cannot start.
    pub fn parse(runtime_image: &str, image_disk: &str) -> Result<Option<Self>, String> {
        let runtime_image = runtime_image.trim();
        let image_disk = image_disk.trim();
        if runtime_image.is_empty() && image_disk.is_empty() {
            return Ok(None);
        }
        if !crate::sandbox::warm_pool::digest_pinned(runtime_image) {
            return Err(format!(
                "{STANDARD_RUNTIME_IMAGE_ENV} must name the runtime image by digest, such as \
                 registry.example.com/codewire/pod-runtime@sha256:<digest>; see docs/CONFIGURATION.md"
            ));
        }
        let fields: Vec<&str> = image_disk.split_whitespace().collect();
        let [reference, image_disk_id, build_id, workspace_image] = fields[..] else {
            return Err(image_disk_error());
        };
        if !crate::sandbox::warm_pool::digest_pinned(reference)
            || !lowercase_hex(image_disk_id, 64)
            || !lowercase_hex(build_id, 32)
            || !crate::sandbox::warm_pool::digest_pinned(workspace_image)
        {
            return Err(image_disk_error());
        }
        Ok(Some(Self {
            runtime_image: runtime_image.to_owned(),
            image_disk: reference.to_owned(),
            image_disk_id: image_disk_id.to_owned(),
            build_id: build_id.to_owned(),
            workspace_image: workspace_image.to_owned(),
            boots_systemd: false,
        }))
    }

    /// This runtime, booting systemd when its disk was built from a
    /// digest-pinned image of the systemd workspace repository: a disk is the
    /// kind of the image it holds, by the rule a `commodity` create follows
    /// (docs/dev/SYSTEMD-WORKSPACE.md, "On the `standard` profile").
    pub fn with_systemd_repository(mut self, images: &RuntimeImages) -> Self {
        self.boots_systemd =
            images.systemd_workspace(&self.workspace_image) == SystemdWorkspaceImage::Pinned;
        self
    }

    /// [`POD_RUNTIME_WORKSPACE_INIT_ENV`] for this runtime's disk.
    pub fn workspace_init(&self) -> &'static str {
        if self.boots_systemd {
            POD_RUNTIME_WORKSPACE_INIT_SYSTEMD
        } else {
            POD_RUNTIME_WORKSPACE_INIT_IMAGE
        }
    }

    /// The runtime image the Pod's one container runs, by digest.
    pub fn runtime_image(&self) -> &str {
        &self.runtime_image
    }

    /// The `sha256:<64 hex>` digest suffix of [`Self::runtime_image`].
    pub fn runtime_image_digest(&self) -> Option<&str> {
        self.runtime_image
            .rsplit_once('@')
            .map(|(_, digest)| digest)
            .filter(|digest| {
                digest
                    .strip_prefix("sha256:")
                    .is_some_and(|hex| lowercase_hex(hex, 64))
            })
    }

    /// The published workspace disk the Pod mounts read-only, by digest.
    pub fn image_disk(&self) -> &str {
        &self.image_disk
    }

    /// The Pod's one image volume, its workspace disk, exactly as rendered.
    /// A warm member's first bind admits this volume and no other image
    /// volume (#5602).
    pub fn image_disk_volume(&self) -> Value {
        json!({
            "name": IMAGE_DISK_VOLUME,
            "image": { "reference": self.image_disk, "pullPolicy": "IfNotPresent" },
        })
    }

    /// Whether the VM boots `image`: it has the manifest digest of the
    /// workspace image the disk was built from, whatever registry it names.
    pub fn boots(&self, image: &str) -> bool {
        manifest_digest(image)
            .is_some_and(|digest| Some(digest) == manifest_digest(&self.workspace_image))
    }

    /// [`Self::parse`] of this process's environment, with its configured
    /// systemd workspace repository.
    pub fn from_env() -> Result<Option<Self>, String> {
        let read = |name: &str| std::env::var(name).unwrap_or_default();
        let images = crate::sandbox::runtime_images::configured();
        Ok(Self::parse(
            &read(STANDARD_RUNTIME_IMAGE_ENV),
            &read(STANDARD_IMAGE_DISK_ENV),
        )?
        .map(|runtime| runtime.with_systemd_repository(images)))
    }
}

/// The runtime profile a Pod of `image` renders on, on a deployment of
/// `deployment_profile`. A `standard` VM boots only the image its disk was
/// built from, so an environment that names any other image, a user's own or
/// a workspace image the disk was not republished for, renders on
/// `commodity` (`SPEC.md` section 4), which is a VM too.
pub fn runtime_profile_of<'a>(
    deployment_profile: &'a str,
    runtime: Option<&StandardRuntime>,
    image: &str,
) -> &'a str {
    if deployment_profile.trim() == super::RUNTIME_PROFILE_STANDARD
        && !runtime.is_some_and(|runtime| runtime.boots(image))
    {
        return super::RUNTIME_PROFILE_COMMODITY;
    }
    deployment_profile
}

fn image_disk_error() -> String {
    format!(
        "{STANDARD_IMAGE_DISK_ENV} must be the published disk's line: \
         <reference>@sha256:<digest>, its 64-hex image disk id, its 32-hex build id and \
         the workspace image it was built from by digest, separated by spaces; see \
         docs/CONFIGURATION.md"
    )
}

fn manifest_digest(image: &str) -> Option<&str> {
    image
        .rsplit_once("@sha256:")
        .map(|(_, digest)| digest)
        .filter(|digest| lowercase_hex(digest, 64))
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Unbilled PVC headroom (in GiB) reserved on a `standard` Sandbox's thin-LVM
/// volume for the hibernate memory image and device state (#6647,
/// `docs/dev/SANDBOX-SLEEP.md`, "Volume space"). Never counted in `disk_gib`
/// billing and never given to the guest's state/Docker sparse disks.
pub(crate) fn hibernate_memory_headroom_gib(memory_mib: i64) -> i64 {
    memory_mib.max(0).saturating_add(512).saturating_add(1_023) / 1_024
}

/// Total PVC storage request (in GiB) for a `standard` Sandbox: the user's
/// billed `disk_gib` plus unbilled [`hibernate_memory_headroom_gib`].
pub(crate) fn standard_pvc_gib(disk_gib: i64, memory_mib: i64) -> i64 {
    disk_gib.saturating_add(hibernate_memory_headroom_gib(memory_mib))
}

/// Physical PVC storage request (in GiB) for a Sandbox of `runtime_profile`:
/// `standard` reserves unbilled hibernate memory headroom on top of `disk_gb`;
/// other profiles (`commodity`, `confidential`) request `disk_gb` directly (#6647).
pub(crate) fn workspace_pvc_target_gib(runtime_profile: &str, disk_gb: i32, memory_mb: i32) -> i32 {
    if runtime_profile == super::RUNTIME_PROFILE_STANDARD {
        i32::try_from(standard_pvc_gib(i64::from(disk_gb), i64::from(memory_mb))).unwrap_or(disk_gb)
    } else {
        disk_gb
    }
}

/// The room in MiB the VM's state and Docker disks share on a volume of
/// `disk_gib`, which also holds its root disk.
pub(super) fn disks_mib(disk_gib: i64) -> i64 {
    let volume = disk_gib.saturating_mul(1_024);
    volume.saturating_mul(100 - STATE_DISK_RESERVE_PERCENT) / 100
        - STATE_DISK_RESERVE_MIB
        - STANDARD_ROOT_DISK_MIB
}

/// The VM's Docker data disk, in MiB, on a volume of `disk_gib`.
pub(super) fn docker_disk_mib(disk_gib: i64) -> i64 {
    (disks_mib(disk_gib) * DOCKER_DISK_SHARE_PERCENT / 100).max(MIN_DOCKER_DISK_MIB)
}

/// The VM's home and workspace disk, in MiB, on a volume of `disk_gib`: the
/// room its Docker disk leaves.
pub(super) fn state_disk_mib(disk_gib: i64) -> i64 {
    disks_mib(disk_gib) - docker_disk_mib(disk_gib)
}

/// The VM's whole vCPUs for a CPU size in millicores.
fn vcpus(cpu_millicores: i64) -> i64 {
    cpu_millicores.saturating_add(999) / 1_000
}

/// The platform peers the guest's daemon may reach: cw-egress, the binding
/// Service, the public gateway and DERP. DERP's TLS name stays in
/// `CODEWIRE_DERP_ADDR`, which the daemon reads as on `commodity`.
fn platform_peers(egress: &HostedEgressTemplate) -> [&str; 4] {
    let derp = egress
        .derp_addr
        .split_once('=')
        .map_or(egress.derp_addr.as_str(), |(_, address)| address);
    [
        &egress.stream_addr,
        &egress.binding_addr,
        &egress.gateway_addr,
        derp,
    ]
}

/// A `standard` workspace renders only with its runtime, with hosted egress,
/// which is its VM's only network, and at a size its VM can take.
pub(super) fn validate(opts: &TemplateOpts) -> anyhow::Result<()> {
    let Some(egress) = &opts.hosted_egress else {
        anyhow::bail!(
            "the standard runtime profile needs hosted egress on: its VM has no other network"
        );
    };
    anyhow::ensure!(
        opts.standard_runtime.is_some(),
        "the standard runtime profile needs {STANDARD_RUNTIME_IMAGE_ENV} and {STANDARD_IMAGE_DISK_ENV}; see docs/CONFIGURATION.md"
    );
    anyhow::ensure!(
        opts.disk_gib >= MIN_DISK_GIB,
        "a standard workspace keeps its VM's disks on its own volume, so it needs a disk of at least {MIN_DISK_GIB} GiB"
    );
    anyhow::ensure!(
        opts.cpu_millicores > 0 && vcpus(opts.cpu_millicores) <= MAX_VCPUS,
        "a standard workspace takes from 1 to {MAX_VCPUS} vCPUs"
    );
    anyhow::ensure!(
        MEMORY_MIB_RANGE.contains(&opts.memory_mib),
        "a standard workspace takes from {} to {} MiB of memory",
        MEMORY_MIB_RANGE.start(),
        MEMORY_MIB_RANGE.end()
    );
    for peer in platform_peers(egress) {
        let literal = peer.parse::<SocketAddrV4>().ok().filter(|address| {
            let ip = address.ip();
            address.port() != 0
                && !(ip.is_unspecified()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_broadcast())
        });
        anyhow::ensure!(
            literal.is_some(),
            "a standard workspace reaches its platform peers by literal IPv4 address and port; {peer:?} is not one"
        );
    }
    const MAX_UDP_PEERS: usize = 8;
    anyhow::ensure!(
        egress.udp_relay_peers.len() <= MAX_UDP_PEERS,
        "a standard workspace takes at most {MAX_UDP_PEERS} UDP relay peers"
    );
    for peer in &egress.udp_relay_peers {
        anyhow::ensure!(
            codewire_egress_policy::platform_peer(peer).is_ok(),
            "a standard workspace reaches its UDP relay peers by literal IPv4 address and port; {peer:?} is not one"
        );
    }
    Ok(())
}

/// The one container and its Pod. The container's requests are the user's
/// size, as on the other profiles, because billing reads them; its limits add
/// the VM process and the runtime beside the guest.
pub(super) fn pod_spec(
    opts: &TemplateOpts,
    runtime: &StandardRuntime,
    egress: &HostedEgressTemplate,
) -> Value {
    let mut ws = json!({
        "name": "workspace",
        "image": runtime.runtime_image,
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
                "cpu": format!("{}m", opts.cpu_millicores + i64::from(STANDARD_VMM_CPU_MILLICORES)),
                "memory": format!("{}Mi", opts.memory_mib + i64::from(STANDARD_VMM_MEMORY_MIB)),
                "ephemeral-storage": format!("{WORKSPACE_EPHEMERAL_STORAGE_GI}Gi"),
                KVM_DEVICE_RESOURCE: "1",
            },
        },
        "securityContext": {
            "allowPrivilegeEscalation": false,
            "capabilities": { "drop": ["ALL"] },
        },
        "volumeMounts": [
            { "name": "workspace", "mountPath": POD_RUNTIME_STATE_MOUNT_PATH },
            {
                "name": IMAGE_DISK_VOLUME,
                "mountPath": POD_RUNTIME_IMAGE_DISK_MOUNT_PATH,
                "readOnly": true,
            },
            { "name": "codewire-run", "mountPath": "/codewire/run" },
        ],
    });
    let mut volumes = vec![runtime.image_disk_volume(), run_volume()];
    identity::mount_identity(opts, &mut ws, &mut volumes, hosted_egress::mount_identity);
    ws["env"]
        .as_array_mut()
        .expect("workspace env")
        .extend(settings(opts, runtime, egress));
    apply_daemon_ready_probes(&mut ws, &opts.runtime_profile_spec());

    let mut spec = Map::new();
    spec.insert("restartPolicy".into(), "Never".into());
    spec.insert("serviceAccountName".into(), SANDBOX_SERVICE_ACCOUNT.into());
    spec.insert("automountServiceAccountToken".into(), false.into());
    spec.insert("enableServiceLinks".into(), false.into());
    spec.insert(
        "securityContext".into(),
        json!({
            "runAsUser": 1000,
            "runAsGroup": 1000,
            "runAsNonRoot": true,
            "fsGroup": 1000,
            "fsGroupChangePolicy": "OnRootMismatch",
            "seccompProfile": { "type": "RuntimeDefault" },
        }),
    );
    // The Pod resolves nothing: the runtime dials literal addresses only.
    hosted_egress::resolver(&mut spec);
    spec.insert("runtimeClassName".into(), RUNTIME_CLASS_STANDARD.into());
    spec.insert(
        "terminationGracePeriodSeconds".into(),
        TERMINATION_GRACE_SECONDS.into(),
    );
    spec.insert("containers".into(), json!([ws]));
    spec.insert("volumes".into(), Value::Array(volumes));
    Value::Object(spec)
}

/// How the guest's workload reaches the network (#5602): every `standard`
/// template (both per-environment and shared warm pool) runs hosted broker
/// mode inside the VM so its daemon carries the workload over `cwegress0` to
/// `cw-egress`. While unbound, `cw-egress` holds a warm member at
/// `Assignment::Unbound` (zero workload egress) and records its interception
/// trust (#6200), so an adopted member matches an environment's rendering
/// one-for-one.
fn egress_mode(_opts: &TemplateOpts) -> &'static str {
    POD_RUNTIME_EGRESS_MODE_BROKER
}

/// What `cw __pod-runtime` reads, by its fixed names.
fn settings(
    opts: &TemplateOpts,
    runtime: &StandardRuntime,
    egress: &HostedEgressTemplate,
) -> Vec<Value> {
    let mut entries = vec![
        (
            POD_RUNTIME_VCPUS_ENV,
            vcpus(opts.cpu_millicores).to_string(),
        ),
        (POD_RUNTIME_MEMORY_MIB_ENV, opts.memory_mib.to_string()),
        (
            POD_RUNTIME_STATE_DISK_MIB_ENV,
            state_disk_mib(opts.disk_gib).to_string(),
        ),
        (
            POD_RUNTIME_DOCKER_DISK_MIB_ENV,
            docker_disk_mib(opts.disk_gib).to_string(),
        ),
        (
            POD_RUNTIME_VM_STATE_ENV,
            if opts.workspace_source_snapshot.is_some() {
                POD_RUNTIME_VM_STATE_EXISTING
            } else {
                POD_RUNTIME_VM_STATE_NEW
            }
            .to_owned(),
        ),
        (POD_RUNTIME_EGRESS_MODE_ENV, egress_mode(opts).to_owned()),
        (
            POD_RUNTIME_WORKSPACE_IMAGE_ENV,
            runtime.workspace_image.clone(),
        ),
        (
            POD_RUNTIME_WORKSPACE_INIT_ENV,
            runtime.workspace_init().to_owned(),
        ),
        (POD_RUNTIME_IMAGE_DISK_ID_ENV, runtime.image_disk_id.clone()),
        (
            POD_RUNTIME_IMAGE_DISK_BUILD_ID_ENV,
            runtime.build_id.clone(),
        ),
        (
            POD_RUNTIME_PLATFORM_PEERS_ENV,
            platform_peers(egress).join(","),
        ),
    ];
    if !egress.udp_relay_peers.is_empty() {
        entries.push((POD_RUNTIME_UDP_PEERS_ENV, egress.udp_relay_peers.join(",")));
    }
    if let Some(digest) = runtime.runtime_image_digest() {
        entries.push((POD_RUNTIME_IMAGE_DIGEST_ENV, digest.to_owned()));
    }
    entries
        .into_iter()
        .map(|(name, value)| json!({ "name": name, "value": value }))
        .collect()
}

/// JSON Patch operations that set or clear [`POD_RUNTIME_RESTORE_GENERATION_ENV`]
/// on a `standard` Sandbox's `workspace` container env (#6647), fenced by
/// `test`s of the Sandbox's UID and any replaced/removed entry. Returns an
/// empty list for non-`standard` Sandboxes or when the env already matches.
pub(crate) fn vm_restore_generation(
    sandbox: &Value,
    generation: Option<u64>,
) -> anyhow::Result<Vec<Value>> {
    let spec = "/spec/podTemplate/spec";
    if sandbox
        .pointer(&format!("{spec}/runtimeClassName"))
        .and_then(Value::as_str)
        != Some(RUNTIME_CLASS_STANDARD)
    {
        return Ok(Vec::new());
    }
    let uid = sandbox
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| anyhow::anyhow!("the standard Sandbox has no UID"))?;
    let containers = sandbox
        .pointer(&format!("{spec}/containers"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let (index, workspace) = containers
        .iter()
        .enumerate()
        .find(|(_, container)| container["name"] == "workspace")
        .ok_or_else(|| anyhow::anyhow!("the standard Sandbox has no workspace container"))?;
    let env_list = workspace["env"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("the standard Sandbox's workspace has no env array"))?;
    let existing = env_list
        .iter()
        .enumerate()
        .find(|(_, variable)| variable["name"] == POD_RUNTIME_RESTORE_GENERATION_ENV)
        .map(|(entry, variable)| (entry, variable.get("value").and_then(Value::as_str)));

    match (generation, existing) {
        (None, None) => Ok(Vec::new()),
        (None, Some((entry, _))) => {
            let path = format!("{spec}/containers/{index}/env/{entry}");
            Ok(vec![
                json!({"op": "test", "path": "/metadata/uid", "value": uid}),
                json!({"op": "test", "path": format!("{path}/name"), "value": POD_RUNTIME_RESTORE_GENERATION_ENV}),
                json!({"op": "remove", "path": path}),
            ])
        }
        (Some(gen_value), Some((entry, current))) => {
            let desired = gen_value.to_string();
            if current == Some(desired.as_str()) {
                return Ok(Vec::new());
            }
            let path = format!("{spec}/containers/{index}/env/{entry}");
            Ok(vec![
                json!({"op": "test", "path": "/metadata/uid", "value": uid}),
                json!({"op": "test", "path": format!("{path}/name"), "value": POD_RUNTIME_RESTORE_GENERATION_ENV}),
                json!({"op": "replace", "path": format!("{path}/value"), "value": desired}),
            ])
        }
        (Some(gen_value), None) => Ok(vec![
            json!({"op": "test", "path": "/metadata/uid", "value": uid}),
            json!({
                "op": "add",
                "path": format!("{spec}/containers/{index}/env/-"),
                "value": {
                    "name": POD_RUNTIME_RESTORE_GENERATION_ENV,
                    "value": gen_value.to_string(),
                },
            }),
        ]),
    }
}

/// The JSON Patch operations that turn a `standard` Sandbox's rendered
/// [`POD_RUNTIME_VM_STATE_ENV`] from `new` into `existing` (#5602), fenced by
/// `test`s of the Sandbox's UID and of the entry's name and value, so no
/// later Pod of it creates its state disk. Empty for a Sandbox of another
/// class, or once it is `existing`. Only the next Pod reads it: the
/// controller never rewrites a running one.
pub(crate) fn vm_state_existing(sandbox: &Value) -> anyhow::Result<Vec<Value>> {
    let spec = "/spec/podTemplate/spec";
    if sandbox
        .pointer(&format!("{spec}/runtimeClassName"))
        .and_then(Value::as_str)
        != Some(RUNTIME_CLASS_STANDARD)
    {
        return Ok(Vec::new());
    }
    let uid = sandbox
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .filter(|uid| !uid.is_empty())
        .ok_or_else(|| anyhow::anyhow!("the standard Sandbox has no UID"))?;
    let containers = sandbox
        .pointer(&format!("{spec}/containers"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let (index, workspace) = containers
        .iter()
        .enumerate()
        .find(|(_, container)| container["name"] == "workspace")
        .ok_or_else(|| anyhow::anyhow!("the standard Sandbox has no workspace container"))?;
    let (entry, value) = workspace["env"]
        .as_array()
        .and_then(|env| {
            env.iter()
                .enumerate()
                .find(|(_, variable)| variable["name"] == POD_RUNTIME_VM_STATE_ENV)
        })
        .map(|(entry, variable)| (entry, variable.get("value").and_then(Value::as_str)))
        .ok_or_else(|| {
            anyhow::anyhow!("the standard Sandbox's workspace has no {POD_RUNTIME_VM_STATE_ENV}")
        })?;
    let path = format!("{spec}/containers/{index}/env/{entry}");
    match value {
        Some(POD_RUNTIME_VM_STATE_EXISTING) => Ok(Vec::new()),
        Some(POD_RUNTIME_VM_STATE_NEW) => Ok(vec![
            json!({"op": "test", "path": "/metadata/uid", "value": uid}),
            json!({"op": "test", "path": format!("{path}/name"), "value": POD_RUNTIME_VM_STATE_ENV}),
            json!({"op": "test", "path": format!("{path}/value"), "value": POD_RUNTIME_VM_STATE_NEW}),
            json!({
                "op": "replace",
                "path": format!("{path}/value"),
                "value": POD_RUNTIME_VM_STATE_EXISTING,
            }),
        ]),
        _ => anyhow::bail!(
            "the standard Sandbox's {POD_RUNTIME_VM_STATE_ENV} is neither {POD_RUNTIME_VM_STATE_NEW} nor {POD_RUNTIME_VM_STATE_EXISTING}"
        ),
    }
}
