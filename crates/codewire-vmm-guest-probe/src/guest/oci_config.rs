//! The workspace container's OCI runtime configuration, written once per boot
//! before the container starts.

use super::*;

#[cfg(test)]
pub(super) fn workspace_oci_config(plan: &WorkspacePlan) -> Result<Vec<u8>> {
    workspace_oci_config_with_options(plan, false, false, false, false)
}

/// Defense-in-depth seccomp policy for `standard` hosted workspace containers
/// (`docs/dev/SYSTEMD-WORKSPACE.md`, "The container is defense in depth"):
/// denies `AF_VSOCK` sockets (`socket` and `socketpair`) and 32-bit
/// `socketcall` on `x86_64` as lightweight accident defense in depth.
/// `io_uring` stays allowed here because the VM is the boundary and
/// `docker run --privileged` inside the VM already reaches vsock.
fn hosted_seccomp_policy() -> serde_json::Value {
    #[cfg(target_arch = "x86_64")]
    let architectures = ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"];
    #[cfg(target_arch = "aarch64")]
    let architectures = ["SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM"];
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let architectures: [&str; 0] = [];

    let mut syscalls = vec![serde_json::json!({
        "names": ["socket", "socketpair"],
        "action": "SCMP_ACT_ERRNO",
        "errnoRet": libc::EAFNOSUPPORT,
        "args": [
            {
                "index": 0,
                "value": u64::try_from(libc::AF_VSOCK).unwrap_or(40),
                "op": "SCMP_CMP_EQ"
            }
        ]
    })];
    #[cfg(target_arch = "x86_64")]
    syscalls.push(serde_json::json!({
        "names": ["socketcall"],
        "action": "SCMP_ACT_ERRNO",
        "errnoRet": libc::EPERM
    }));

    serde_json::json!({
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": architectures,
        "syscalls": syscalls
    })
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
    workspace_oci_config_with_options(
        plan,
        cw_asset,
        workload_may_become_root,
        super::hosted::active(),
        super::hosted::systemd_workspace(),
    )
}

fn workspace_oci_config_with_options(
    plan: &WorkspacePlan,
    cw_asset: bool,
    workload_may_become_root: bool,
    hosted_active: bool,
    systemd_workspace: bool,
) -> Result<Vec<u8>> {
    let allow_root = workload_may_become_root || systemd_workspace;
    let mut bounding: Vec<&str> = if allow_root {
        codewire_daemon::execution::WORKLOAD_ROOT_CAPABILITIES.to_vec()
    } else {
        vec!["CAP_SETGID", "CAP_SETUID"]
    };
    let (effective, permitted): (Vec<&str>, Vec<&str>) = if systemd_workspace {
        // Held only by sealed `workspace-init --systemd` long enough to
        // unshare the cgroup namespace and mount the delegated cgroup2
        // subtree; permanently dropped from CapBnd before any workspace code
        // or `/sbin/init` runs.
        bounding.push("CAP_SYS_ADMIN");
        (bounding.clone(), bounding.clone())
    } else {
        (
            vec!["CAP_SETGID", "CAP_SETUID"],
            vec!["CAP_SETGID", "CAP_SETUID"],
        )
    };
    let args: Vec<&str> = if systemd_workspace {
        vec![CONTAINER_INIT_PATH, "workspace-init", "--systemd"]
    } else {
        vec![CONTAINER_INIT_PATH, "workspace-init"]
    };
    let mut env = vec![
        "HOME=/root",
        "USER=root",
        "SHELL=/bin/sh",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C.UTF-8",
    ];
    if systemd_workspace {
        env.push("container=oci");
    }
    let run_mount_size = if systemd_workspace {
        "size=64m"
    } else {
        "size=16m"
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
            "args": args,
            "env": env,
            "cwd": "/",
            "capabilities": {
                "bounding": bounding,
                "effective": effective,
                "inheritable": [],
                "permitted": permitted,
                "ambient": []
            },
            "rlimits": [
                { "type": "RLIMIT_NOFILE", "hard": 1048576, "soft": 1048576 }
            ],
            "noNewPrivileges": !allow_root
        },
        "root": { "path": "../merged", "readonly": false },
        "hostname": CONTAINER_HOSTNAME,
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"] },
            { "destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] },
            { "destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"] },
            { "destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=65536k"] },
            { "destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"] },
            { "destination": "/run", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "noexec", "nodev", "mode=0755", run_mount_size] },
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
    if hosted_active {
        configuration["mounts"]
            .as_array_mut()
            .context("workspace mounts")?
            .extend(super::hosted::container_mounts());
        configuration["linux"]["seccomp"] = hosted_seccomp_policy();
    }
    if systemd_workspace {
        // `/run/lock` must be its own tmpfs mountpoint: without `CAP_SYS_ADMIN`,
        // systemd cannot mount it itself and fails API filesystem setup
        // (`docs/dev/SYSTEMD-WORKSPACE.md`).
        configuration["mounts"]
            .as_array_mut()
            .context("workspace mounts")?
            .push(serde_json::json!({
                "destination": "/run/lock",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "noexec", "nodev", "mode=1777", "size=8m"]
            }));
        // systemd mounts/reads `/proc` and `/sys` inside its own VM; per
        // `docs/dev/SYSTEMD-WORKSPACE.md`, the VM is the boundary and the
        // container masks are not re-applied on systemd's side.
        configuration["linux"]["maskedPaths"] = serde_json::json!([]);
        configuration["linux"]["readonlyPaths"] = serde_json::json!([]);
    }
    serde_json::to_vec(&configuration).context("encode workspace OCI configuration")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_container_gets_vsock_seccomp_filter_and_allows_io_uring() {
        let plan = super::super::tests::test_workspace_plan();
        let hosted: serde_json::Value = serde_json::from_slice(
            &workspace_oci_config_with_options(&plan, true, true, true, false).unwrap(),
        )
        .unwrap();
        let syscalls = hosted["linux"]["seccomp"]["syscalls"].as_array().unwrap();
        assert_eq!(
            hosted["linux"]["seccomp"]["defaultAction"],
            "SCMP_ACT_ALLOW"
        );
        assert!(syscalls.iter().any(|rule| {
            rule["names"] == serde_json::json!(["socket", "socketpair"])
                && rule["args"][0]["value"] == serde_json::json!(40)
        }));
        #[cfg(target_arch = "x86_64")]
        assert!(syscalls.iter().any(|rule| {
            rule["names"] == serde_json::json!(["socketcall"])
                && rule["errnoRet"] == serde_json::json!(libc::EPERM)
        }));
        for name in ["io_uring_setup", "io_uring_enter", "io_uring_register"] {
            assert!(
                !syscalls.iter().any(|rule| {
                    rule["names"]
                        .as_array()
                        .is_some_and(|names| names.contains(&serde_json::json!(name)))
                }),
                "{name} must not be denied in the workspace container seccomp policy"
            );
        }
        let local: serde_json::Value = serde_json::from_slice(
            &workspace_oci_config_with_options(&plan, true, false, false, false).unwrap(),
        )
        .unwrap();
        assert!(local["linux"].get("seccomp").is_none());
    }

    #[test]
    fn systemd_workspace_container_config_passes_flag_and_container_env() {
        let plan = super::super::tests::test_workspace_plan();
        let config: serde_json::Value = serde_json::from_slice(
            &workspace_oci_config_with_options(&plan, true, true, true, true).unwrap(),
        )
        .unwrap();
        assert_eq!(
            config["process"]["args"],
            serde_json::json!([CONTAINER_INIT_PATH, "workspace-init", "--systemd"])
        );
        assert!(
            config["process"]["env"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("container=oci"))
        );
        assert_eq!(config["process"]["noNewPrivileges"], false);
        assert!(config["linux"].get("seccomp").is_some());
    }
}
