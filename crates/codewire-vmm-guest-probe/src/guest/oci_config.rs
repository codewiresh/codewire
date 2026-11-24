//! The workspace container's OCI runtime configuration, written once per boot
//! before the container starts.

use super::*;

#[cfg(test)]
pub(super) fn workspace_oci_config(plan: &WorkspacePlan) -> Result<Vec<u8>> {
    workspace_oci_config_with_cw(plan, false, false)
}

/// With `workload_may_become_root` (Docker on), the container runs without
/// no-new-privileges and keeps the OCI default bounding set, so a setuid
/// `sudo` from the image works; every process it starts inherits that. Its
/// own init still holds only `CAP_SETUID` and `CAP_SETGID`. Without it, the
/// container and everything in it keep no-new-privileges
/// (`docs/dev/LINUX-LOCAL-VMS.md`, "Root and sudo in a VM", #5464).
/// The workspace container's standard character devices, and the cgroup
/// rules that allow exactly those.
fn standard_devices() -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let standard_devices = [
        ("/dev/null", 1, 3, 0o666),
        ("/dev/zero", 1, 5, 0o666),
        ("/dev/full", 1, 7, 0o666),
        ("/dev/tty", 5, 0, 0o666),
        ("/dev/random", 1, 8, 0o666),
        ("/dev/urandom", 1, 9, 0o666),
    ];
    let devices = standard_devices
        .iter()
        .map(|(path, major, minor, mode)| {
            serde_json::json!({
                "path": path,
                "type": "c",
                "major": major,
                "minor": minor,
                "fileMode": mode,
                "uid": 0,
                "gid": 0
            })
        })
        .collect::<Vec<_>>();
    let allowed_devices = standard_devices
        .iter()
        .map(|(_, major, minor, _)| {
            serde_json::json!({
                "allow": true,
                "type": "c",
                "major": major,
                "minor": minor,
                "access": "rwm"
            })
        })
        .collect::<Vec<_>>();
    (devices, allowed_devices)
}

pub(super) fn workspace_oci_config_with_cw(
    plan: &WorkspacePlan,
    cw_asset: bool,
    workload_may_become_root: bool,
) -> Result<Vec<u8>> {
    let bounding: Vec<&str> = if workload_may_become_root {
        codewire_daemon::execution::WORKLOAD_ROOT_CAPABILITIES.to_vec()
    } else {
        vec!["CAP_SETGID", "CAP_SETUID"]
    };
    let (mut devices, mut allowed_devices) = standard_devices();
    // A hosted boot's own (broker mode's TUN device), none otherwise.
    let (hosted_devices, hosted_allowed) = super::hosted::container_devices();
    devices.extend(hosted_devices);
    allowed_devices.extend(hosted_allowed);
    let mut configuration = serde_json::json!({
        "ociVersion": "1.2.0",
        "process": {
            "terminal": false,
            "user": { "uid": 0, "gid": 0 },
            "args": [CONTAINER_INIT_PATH, "workspace-init"],
            "env": [
                "HOME=/root",
                "USER=root",
                "SHELL=/bin/sh",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG=C.UTF-8"
            ],
            "cwd": "/",
            "capabilities": {
                "bounding": bounding,
                "effective": ["CAP_SETGID", "CAP_SETUID"],
                "inheritable": [],
                "permitted": ["CAP_SETGID", "CAP_SETUID"],
                "ambient": []
            },
            "rlimits": [
                { "type": "RLIMIT_NOFILE", "hard": 1048576, "soft": 1048576 }
            ],
            "noNewPrivileges": !workload_may_become_root
        },
        "root": { "path": "../merged", "readonly": false },
        "hostname": CONTAINER_HOSTNAME,
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"] },
            { "destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] },
            { "destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"] },
            { "destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"] },
            { "destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"] },
            { "destination": "/run", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "noexec", "nodev", "mode=0755", "size=16m"] },
            { "destination": CONTAINER_INIT_PATH, "type": "none", "source": INIT_PATH, "options": ["bind", "ro", "nosuid", "nodev", "exec"] },
            { "destination": CONTAINER_PLAN_PATH, "type": "none", "source": ACTIVE_WORKSPACE_PLAN_PATH, "options": ["bind", "ro", "nosuid", "nodev", "noexec"] },
            { "destination": CONTAINER_INSTALL_STATE_PATH, "type": "none", "source": INSTALL_STATE_PATH, "options": ["bind", "ro", "nosuid", "nodev", "noexec"] },
            { "destination": CONTAINER_MACHINE_ID_DESTINATION, "type": "none", "source": CONTAINER_MACHINE_ID_PATH, "options": ["bind", "ro", "nosuid", "nodev", "noexec"] },
            { "destination": CONTAINER_HOSTS_DESTINATION, "type": "none", "source": CONTAINER_HOSTS_PATH, "options": ["bind", "ro", "nosuid", "nodev", "noexec"] },
            { "destination": CONTAINER_RESOLV_CONF_DESTINATION, "type": "none", "source": CONTAINER_RESOLV_CONF_PATH, "options": ["bind", "ro", "nosuid", "nodev", "noexec"] },
            { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777", "size=256m"] },
            { "destination": WORKSPACE_PATH, "type": "none", "source": PERSISTENT_WORKSPACE_PATH, "options": ["rbind", "rw", "nosuid", "nodev"] },
            { "destination": plan.identity.home, "type": "none", "source": HOME_MERGED_PATH, "options": ["rbind", "rw", "nosuid", "nodev"] },
            { "destination": crate::CODEX_GUEST_HOME_PATH, "type": "none", "source": PERSISTENT_CODEX_HOME_PATH, "options": ["rbind", "rw", "nosuid", "nodev"] },
            { "destination": CONTAINER_CONTROL_DESTINATION, "type": "none", "source": CONTAINER_CONTROL_PATH, "options": ["rbind", "ro", "nosuid", "nodev", "noexec"] },
            { "destination": CONTAINER_PROBE_DESTINATION, "type": "none", "source": PERSISTENT_PROBE_PATH, "options": ["rbind", "rw", "nosuid", "nodev", "noexec"] },
            { "destination": CONTAINER_DOCKER_RUNTIME_PATH, "type": "none", "source": DOCKER_RUNTIME_PATH, "options": ["rbind", "rw", "nosuid", "nodev", "noexec"] }
        ],
        "linux": {
            "rootfsPropagation": "rslave",
            "cgroupsPath": crate::workload_cgroup::WORKSPACE_CGROUPS_PATH,
            "resources": {
                "devices": std::iter::once(serde_json::json!({ "allow": false, "access": "rwm" }))
                    .chain(allowed_devices)
                    .collect::<Vec<_>>()
            },
            "namespaces": [
                { "type": "pid" },
                { "type": "network", "path": NETWORK_NAMESPACE_PATH },
                { "type": "ipc" },
                { "type": "uts" },
                { "type": "mount" }
            ],
            "devices": devices,
            "maskedPaths": [
                "/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
                "/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
                "/proc/sched_debug", "/sys/firmware", "/sys/devices/virtual/powercap"
            ],
            "readonlyPaths": [
                "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"
            ]
        }
    });
    if cw_asset {
        configuration["process"]["env"] = serde_json::to_value(runtime_path_environment(
            &configuration["process"]["env"]
                .as_array()
                .context("workspace environment")?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .context("workspace environment value")
                        .map(str::to_owned)
                })
                .collect::<Result<Vec<_>>>()?,
            true,
        ))?;
        configuration["mounts"]
            .as_array_mut()
            .context("workspace mounts")?
            .extend([
                serde_json::json!({
                    "destination": CW_RUNTIME_ROOT, "type": "none", "source": crate::cw_runtime_live::LIVE_RUNTIME_VIEW,
                    "options": ["bind", "ro", "nosuid", "nodev", "exec"]
                }),
                serde_json::json!({
                    "destination": crate::cw_runtime_live::LIVE_RUNTIME_LAUNCHER, "type": "none",
                    "source": format!("{}/cw", crate::cw_runtime_live::LIVE_RUNTIME_VIEW),
                    "options": ["bind", "ro", "nosuid", "nodev", "exec"]
                }),
            ]);
    }
    if super::hosted::active() {
        configuration["mounts"]
            .as_array_mut()
            .context("workspace mounts")?
            .extend(super::hosted::container_mounts());
    }
    serde_json::to_vec(&configuration).context("encode workspace OCI configuration")
}
