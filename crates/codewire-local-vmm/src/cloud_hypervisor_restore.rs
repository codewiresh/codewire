//! Admission and rewrite of a VM checkpoint's Cloud Hypervisor
//! configuration, and the restore command (#3046 R4).
//!
//! A VM checkpoint's `config.json` is written by the VMM, which runs the
//! guest, so it is input, never trusted. Before a restore the runner admits
//! it against exactly what [`crate::cloud_hypervisor::CloudHypervisorConfig`]
//! produces for a local VM: the Codewire disks by id with their read-only
//! flags, one hybrid vsock device, no network, filesystem or passthrough
//! device, private memory without hugepages or zones, a discarded serial
//! console, Landlock with exactly one rule. It then rewrites every host path
//! to the restoring VM's own, and refuses the result if any absolute path in
//! it is not one of those.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use codewire_vmm_guest_probe::cw_runtime::CW_RUNTIME_DISK_SERIAL;
use codewire_vmm_guest_probe::{
    DOCKER_DISK_SERIAL, ROOT_DISK_SERIAL, SEED_DISK_SERIAL, SETUP_DISK_SERIAL, STATE_DISK_SERIAL,
};
use serde_json::Value;

/// The largest `config.json` admitted.
pub(crate) const MAXIMUM_CONFIG_BYTES: usize = 1024 * 1024;
const MIB: u64 = 1024 * 1024;

/// Devices the local VM command never creates. Each must be absent, null or
/// empty in an admitted configuration.
const ABSENT_DEVICES: [&str; 10] = [
    "net",
    "pmem",
    "devices",
    "user_devices",
    "vdpa",
    "balloon",
    "tpm",
    "sgx_epc",
    "numa",
    "preserved_fds",
];

/// One Codewire disk: its device id, serial and whether it is read-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestoreDisk {
    State,
    Docker,
    Root,
    Seed,
    Setup,
    CwRuntime,
}

impl RestoreDisk {
    fn id(self) -> &'static str {
        match self {
            Self::State => "cw-state",
            Self::Docker => "cw-docker",
            Self::Root => "cw-root",
            Self::Seed => "cw-seed",
            Self::Setup => "cw-setup",
            Self::CwRuntime => "cw-runtime",
        }
    }

    fn serial(self) -> &'static str {
        match self {
            Self::State => STATE_DISK_SERIAL,
            Self::Docker => DOCKER_DISK_SERIAL,
            Self::Root => ROOT_DISK_SERIAL,
            Self::Seed => SEED_DISK_SERIAL,
            Self::Setup => SETUP_DISK_SERIAL,
            Self::CwRuntime => CW_RUNTIME_DISK_SERIAL,
        }
    }

    fn readonly(self) -> bool {
        matches!(self, Self::Seed | Self::Setup | Self::CwRuntime)
    }

    fn from_id(id: &str) -> Option<Self> {
        [
            Self::State,
            Self::Docker,
            Self::Root,
            Self::Seed,
            Self::Setup,
            Self::CwRuntime,
        ]
        .into_iter()
        .find(|disk| disk.id() == id)
    }
}

/// What the captured VM must have been, and the restoring VM's own paths.
#[derive(Debug, Clone)]
pub(crate) struct RestoreTarget {
    pub(crate) vcpus: u8,
    pub(crate) memory_mib: u32,
    pub(crate) vsock_cid: u32,
    /// Every disk the captured VM had, and where the restoring VM's is.
    pub(crate) disks: BTreeMap<&'static str, (RestoreDisk, PathBuf)>,
    pub(crate) vsock_socket: PathBuf,
    pub(crate) checkpoint_dir: PathBuf,
    pub(crate) kernel: PathBuf,
    pub(crate) initramfs: PathBuf,
    /// Each direct share's tag and the restoring VM's virtiofsd socket for
    /// it, in the order the VM was made with.
    pub(crate) virtiofs: Vec<(String, PathBuf)>,
}

impl RestoreTarget {
    pub(crate) fn with_disk(mut self, disk: RestoreDisk, path: PathBuf) -> Self {
        self.disks.insert(disk.id(), (disk, path));
        self
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum RestoreConfigError {
    #[error("the VM checkpoint's VMM configuration is not admitted: {0}")]
    Refused(&'static str),
}

fn refuse<T>(reason: &'static str) -> Result<T, RestoreConfigError> {
    Err(RestoreConfigError::Refused(reason))
}

/// Admit `config` against `target` and return it with every host path the
/// restoring VM's own.
pub(crate) fn admit_and_rewrite(
    config: &[u8],
    target: &RestoreTarget,
) -> Result<Vec<u8>, RestoreConfigError> {
    if config.len() > MAXIMUM_CONFIG_BYTES {
        return refuse("it is too large");
    }
    let mut value: Value =
        serde_json::from_slice(config).map_err(|_| RestoreConfigError::Refused("not JSON"))?;
    let root = value
        .as_object_mut()
        .ok_or(RestoreConfigError::Refused("not an object"))?;
    for device in ABSENT_DEVICES {
        match root.get(device) {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) if items.is_empty() => {}
            Some(_) => return refuse("it has a device the local VM never has"),
        }
    }
    // Memory: no hugepages or zones, exactly the recorded size; shared
    // exactly when direct shares need it, as the local VM command makes it.
    let memory = root
        .get("memory")
        .and_then(Value::as_object)
        .ok_or(RestoreConfigError::Refused("no memory"))?;
    if memory.get("size").and_then(Value::as_u64) != Some(u64::from(target.memory_mib) * MIB)
        || memory.get("shared").and_then(Value::as_bool) != Some(!target.virtiofs.is_empty())
        || memory.get("hugepages").and_then(Value::as_bool) != Some(false)
        || !matches!(memory.get("zones"), None | Some(Value::Null))
    {
        return refuse("its memory is not the local VM's memory of the recorded size");
    }
    // Direct shares: exactly the recorded virtio-fs devices, by tag, each
    // rewritten to the restoring VM's own virtiofsd socket.
    match root.get_mut("fs") {
        None | Some(Value::Null) if target.virtiofs.is_empty() => {}
        Some(Value::Array(devices)) if devices.is_empty() && target.virtiofs.is_empty() => {}
        Some(Value::Array(devices)) if devices.len() == target.virtiofs.len() => {
            for (device, (tag, socket)) in devices.iter_mut().zip(&target.virtiofs) {
                let device = device.as_object_mut().ok_or(RestoreConfigError::Refused(
                    "a filesystem device is not an object",
                ))?;
                if device.get("tag").and_then(Value::as_str) != Some(tag.as_str())
                    || !device.get("socket").is_some_and(Value::is_string)
                {
                    return refuse("a filesystem device is not a recorded direct share");
                }
                device.insert("socket".to_owned(), path_value(socket)?);
            }
        }
        _ => return refuse("its filesystem devices are not the recorded direct shares"),
    }
    if root
        .get("cpus")
        .and_then(|cpus| cpus.get("boot_vcpus"))
        .and_then(Value::as_u64)
        != Some(u64::from(target.vcpus))
    {
        return refuse("its vCPU count is not the recorded one");
    }
    if root.get("landlock_enable").and_then(Value::as_bool) != Some(true) {
        return refuse("Landlock is off");
    }
    let mode = |name: &str| {
        root.get(name)
            .and_then(|device| device.get("mode"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    if mode("serial").as_deref() != Some("Null") || mode("console").as_deref() != Some("Off") {
        return refuse("its serial console is not discarded");
    }
    if root
        .get("rng")
        .and_then(|rng| rng.get("src"))
        .and_then(Value::as_str)
        != Some("/dev/urandom")
    {
        return refuse("its RNG is not the host's /dev/urandom");
    }

    // Disks: exactly the recorded set, by id, each with its serial and
    // read-only flag, rewritten to the restoring VM's paths.
    let disks = root
        .get_mut("disks")
        .and_then(Value::as_array_mut)
        .ok_or(RestoreConfigError::Refused("no disks"))?;
    let mut seen = BTreeSet::new();
    for disk in disks.iter_mut() {
        let object = disk
            .as_object_mut()
            .ok_or(RestoreConfigError::Refused("a disk is not an object"))?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .ok_or(RestoreConfigError::Refused("a disk has no id"))?
            .to_owned();
        let kind = RestoreDisk::from_id(&id)
            .ok_or(RestoreConfigError::Refused("a disk is not a Codewire disk"))?;
        let (_, path) = target
            .disks
            .get(kind.id())
            .ok_or(RestoreConfigError::Refused("a disk was not recorded"))?;
        if !seen.insert(kind.id())
            || object.get("serial").and_then(Value::as_str) != Some(kind.serial())
            || object.get("readonly").and_then(Value::as_bool) != Some(kind.readonly())
            || object.get("vhost_user").and_then(Value::as_bool) == Some(true)
            || !object.get("path").is_some_and(Value::is_string)
        {
            return refuse("a disk is not the one the local VM command makes");
        }
        object.insert("path".to_owned(), path_value(path)?);
    }
    if seen.len() != target.disks.len() {
        return refuse("a recorded disk is missing");
    }

    // One hybrid vsock device, its CID kept: the guest cached it at probe.
    let vsock = root
        .get_mut("vsock")
        .and_then(Value::as_object_mut)
        .ok_or(RestoreConfigError::Refused("no vsock device"))?;
    if vsock.get("id").and_then(Value::as_str) != Some("cw-vsock")
        || vsock.get("cid").and_then(Value::as_u64) != Some(u64::from(target.vsock_cid))
        || !vsock.get("socket").is_some_and(Value::is_string)
    {
        return refuse("its vsock device is not the local VM's");
    }
    vsock.insert("socket".to_owned(), path_value(&target.vsock_socket)?);

    // Exactly one Landlock rule: the restoring VM's own checkpoint directory.
    let rules = root
        .get_mut("landlock_rules")
        .and_then(Value::as_array_mut)
        .ok_or(RestoreConfigError::Refused("no Landlock rule"))?;
    let [rule] = rules.as_mut_slice() else {
        return refuse("it has other Landlock rules");
    };
    let rule = rule.as_object_mut().ok_or(RestoreConfigError::Refused(
        "a Landlock rule is not an object",
    ))?;
    if rule.get("access").and_then(Value::as_str) != Some("rw") || rule.len() != 2 {
        return refuse("its Landlock rule is not the checkpoint directory's");
    }
    rule.insert("path".to_owned(), path_value(&target.checkpoint_dir)?);

    // The pinned kernel and initramfs; no firmware.
    let payload = root
        .get_mut("payload")
        .and_then(Value::as_object_mut)
        .ok_or(RestoreConfigError::Refused("no payload"))?;
    if !matches!(payload.get("firmware"), None | Some(Value::Null))
        || !payload.get("kernel").is_some_and(Value::is_string)
        || !payload.get("initramfs").is_some_and(Value::is_string)
    {
        return refuse("its payload is not a direct kernel boot");
    }
    payload.insert("kernel".to_owned(), path_value(&target.kernel)?);
    payload.insert("initramfs".to_owned(), path_value(&target.initramfs)?);

    // Closed: every absolute path left is one of the restoring VM's own.
    let mut allowed = BTreeSet::from([
        "/dev/urandom".to_owned(),
        path_text(&target.vsock_socket)?,
        path_text(&target.checkpoint_dir)?,
        path_text(&target.kernel)?,
        path_text(&target.initramfs)?,
    ]);
    for (_, path) in target.disks.values() {
        allowed.insert(path_text(path)?);
    }
    for (_, socket) in &target.virtiofs {
        allowed.insert(path_text(socket)?);
    }
    if !only_allowed_paths(&value, &allowed) {
        return refuse("it names a host path the restoring VM does not own");
    }
    serde_json::to_vec(&value).map_err(|_| RestoreConfigError::Refused("not re-encodable"))
}

fn path_text(path: &Path) -> Result<String, RestoreConfigError> {
    path.to_str()
        .filter(|text| text.starts_with('/'))
        .map(str::to_owned)
        .ok_or(RestoreConfigError::Refused(
            "a target path is not absolute UTF-8",
        ))
}

fn path_value(path: &Path) -> Result<Value, RestoreConfigError> {
    path_text(path).map(Value::String)
}

fn only_allowed_paths(value: &Value, allowed: &BTreeSet<String>) -> bool {
    match value {
        Value::String(text) => !text.starts_with('/') || allowed.contains(text),
        Value::Array(items) => items.iter().all(|item| only_allowed_paths(item, allowed)),
        Value::Object(fields) => fields
            .values()
            .all(|field| only_allowed_paths(field, allowed)),
        _ => true,
    }
}

/// `cloud-hypervisor --api-socket path=API --restore
/// source_url=file://IN,memory_restore_mode=copyonwrite,resume=true
/// --seccomp true`, and nothing else.
pub(crate) fn restore_arguments(
    api_socket: &Path,
    source: &Path,
) -> Result<Vec<OsString>, RestoreConfigError> {
    let api = path_text(api_socket)?;
    let source = path_text(source)?;
    if api.contains(',') || source.contains(',') {
        return refuse("a path holds a comma");
    }
    Ok(vec![
        "--api-socket".into(),
        format!("path={api}").into(),
        "--restore".into(),
        format!("source_url=file://{source},memory_restore_mode=copyonwrite,resume=true").into(),
        "--seccomp".into(),
        "true".into(),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> RestoreTarget {
        RestoreTarget {
            vcpus: 2,
            memory_mib: 512,
            vsock_cid: 9,
            disks: BTreeMap::new(),
            vsock_socket: "/sock/new/vsock/vsock.sock".into(),
            checkpoint_dir: "/state/vms/new/checkpoints".into(),
            kernel: "/artifacts/kernel".into(),
            initramfs: "/artifacts/initramfs".into(),
            virtiofs: Vec::new(),
        }
        .with_disk(RestoreDisk::State, "/state/vms/new/disks/state.raw".into())
        .with_disk(
            RestoreDisk::Root,
            "/state/vms/new/generations/g/root.raw".into(),
        )
        .with_disk(RestoreDisk::Seed, "/state/vms/new/seed/seed.raw".into())
    }

    fn disk(id: &str, serial: &str, readonly: bool, path: &str) -> Value {
        serde_json::json!({
            "path": path, "readonly": readonly, "direct": false, "iommu": false,
            "num_queues": 1, "queue_size": 128, "vhost_user": false, "vhost_socket": null,
            "id": id, "serial": serial, "image_type": "Raw", "sparse": true,
            "lock_granularity": "Full", "backing_files": false, "pci_segment": 0
        })
    }

    fn captured() -> Value {
        serde_json::json!({
            "cpus": {"boot_vcpus": 2, "max_vcpus": 2},
            "memory": {"size": 512 * MIB, "mergeable": false, "shared": false,
                       "hugepages": false, "zones": null, "thp": true},
            "payload": {"firmware": null, "kernel": "/artifacts/old/kernel",
                        "cmdline": "console=ttyS0 rdinit=/init panic=-1",
                        "initramfs": "/artifacts/old/initramfs"},
            "disks": [
                disk("cw-state", "CWSTATE1", false, "/state/vms/old/disks/state.raw"),
                disk("cw-root", "CWROOT1", false, "/state/vms/old/generations/g/root.raw"),
                disk("cw-seed", "CWSEED1", true, "/state/vms/old/seed/seed.raw"),
            ],
            "net": null, "rng": {"src": "/dev/urandom", "iommu": false},
            "balloon": null, "fs": null, "pmem": null,
            "serial": {"file": null, "mode": "Null", "iommu": false, "socket": null},
            "console": {"file": null, "mode": "Off", "iommu": false, "socket": null},
            "devices": null, "user_devices": null, "vdpa": null,
            "vsock": {"cid": 9, "socket": "/sock/old/vsock/vsock.sock", "iommu": false,
                      "id": "cw-vsock", "pci_segment": 0},
            "iommu": false, "sgx_epc": null, "numa": null, "watchdog": false,
            "platform": null, "tpm": null, "preserved_fds": null,
            "landlock_enable": true,
            "landlock_rules": [{"path": "/state/vms/old/checkpoints", "access": "rw"}]
        })
    }

    fn admit(config: &Value) -> Result<Value, RestoreConfigError> {
        admit_and_rewrite(&serde_json::to_vec(config).unwrap(), &target())
            .map(|bytes| serde_json::from_slice(&bytes).unwrap())
    }

    #[test]
    fn a_local_vm_configuration_is_rewritten_to_the_restoring_vms_paths() {
        let rewritten = admit(&captured()).unwrap();
        assert_eq!(
            rewritten["disks"][0]["path"],
            "/state/vms/new/disks/state.raw"
        );
        assert_eq!(
            rewritten["disks"][2]["path"],
            "/state/vms/new/seed/seed.raw"
        );
        assert_eq!(rewritten["vsock"]["socket"], "/sock/new/vsock/vsock.sock");
        assert_eq!(rewritten["vsock"]["cid"], 9);
        assert_eq!(
            rewritten["landlock_rules"][0]["path"],
            "/state/vms/new/checkpoints"
        );
        assert_eq!(rewritten["payload"]["kernel"], "/artifacts/kernel");
        assert_eq!(rewritten["memory"]["thp"], true);
    }

    #[test]
    fn anything_the_local_vm_command_never_makes_is_refused() {
        type Case = Box<dyn Fn(&mut Value)>;
        let cases: Vec<Case> = vec![
            Box::new(|config| config["net"] = serde_json::json!([{"tap": "tap0"}])),
            Box::new(|config| config["fs"] = serde_json::json!([{"tag": "x"}])),
            Box::new(|config| config["memory"]["shared"] = true.into()),
            Box::new(|config| config["memory"]["hugepages"] = true.into()),
            Box::new(|config| config["memory"]["size"] = (1024 * MIB).into()),
            Box::new(|config| config["memory"]["zones"] = serde_json::json!([])),
            Box::new(|config| config["cpus"]["boot_vcpus"] = 4.into()),
            Box::new(|config| config["landlock_enable"] = false.into()),
            Box::new(|config| {
                config["landlock_rules"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({"path": "/", "access": "rw"}))
            }),
            Box::new(|config| config["serial"]["mode"] = "File".into()),
            Box::new(|config| config["rng"]["src"] = "/dev/random".into()),
            Box::new(|config| config["vsock"]["cid"] = 10.into()),
            Box::new(|config| config["disks"][2]["readonly"] = false.into()),
            Box::new(|config| config["disks"][0]["serial"] = "OTHER".into()),
            Box::new(|config| config["disks"][0]["id"] = "cw-docker".into()),
            Box::new(|config| {
                config["disks"].as_array_mut().unwrap().pop();
            }),
            Box::new(|config| {
                let extra = config["disks"][0].clone();
                config["disks"].as_array_mut().unwrap().push(extra);
            }),
            Box::new(|config| config["payload"]["firmware"] = "/fw".into()),
            Box::new(|config| config["platform"] = serde_json::json!({"oem": "/etc/passwd"})),
            Box::new(|config| config["devices"] = serde_json::json!([{"path": "/sys/x"}])),
        ];
        for (index, case) in cases.iter().enumerate() {
            let mut config = captured();
            case(&mut config);
            assert!(admit(&config).is_err(), "case {index} was admitted");
        }
        assert!(admit_and_rewrite(b"[]", &target()).is_err());
        assert!(admit_and_rewrite(&vec![b' '; MAXIMUM_CONFIG_BYTES + 1], &target()).is_err());
    }

    #[test]
    fn direct_shares_are_rewritten_to_the_restoring_vms_virtiofsd() {
        let mut target = target();
        target.virtiofs = vec![("cw-direct-00".to_owned(), "/sock/new/fs/00.sock".into())];
        let mut config = captured();
        config["memory"]["shared"] = true.into();
        config["fs"] = serde_json::json!([{
            "tag": "cw-direct-00", "socket": "/sock/old/fs/00.sock",
            "num_queues": 1, "queue_size": 1024, "id": "cw-fs-00", "pci_segment": 0
        }]);
        let admitted: Value = serde_json::from_slice(
            &admit_and_rewrite(&serde_json::to_vec(&config).unwrap(), &target).unwrap(),
        )
        .unwrap();
        assert_eq!(admitted["fs"][0]["socket"], "/sock/new/fs/00.sock");
        // Private memory with a share, another tag, or a missing share are refused.
        let mut private = config.clone();
        private["memory"]["shared"] = false.into();
        assert!(admit_and_rewrite(&serde_json::to_vec(&private).unwrap(), &target).is_err());
        let mut tagged = config.clone();
        tagged["fs"][0]["tag"] = "other".into();
        assert!(admit_and_rewrite(&serde_json::to_vec(&tagged).unwrap(), &target).is_err());
        assert!(admit_and_rewrite(&serde_json::to_vec(&captured()).unwrap(), &target).is_err());
    }

    #[test]
    fn the_restore_command_is_exact() {
        let arguments = restore_arguments(
            Path::new("/sock/new/api/api.sock"),
            Path::new("/state/vms/new/checkpoints/in"),
        )
        .unwrap();
        assert_eq!(
            arguments,
            [
                "--api-socket",
                "path=/sock/new/api/api.sock",
                "--restore",
                "source_url=file:///state/vms/new/checkpoints/in,memory_restore_mode=copyonwrite,resume=true",
                "--seccomp",
                "true",
            ]
            .map(OsString::from)
        );
        assert!(restore_arguments(Path::new("/a,b"), Path::new("/in")).is_err());
        assert!(restore_arguments(Path::new("relative"), Path::new("/in")).is_err());
    }
}
