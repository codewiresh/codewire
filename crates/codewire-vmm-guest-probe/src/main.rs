#[cfg(target_os = "linux")]
use std::ffi::{OsStr, OsString};
#[cfg(target_os = "linux")]
use std::path::Path;

fn main() {
    #[cfg(target_os = "linux")]
    let fatal_vm_init_failure =
        is_fatal_vm_init_failure(std::env::args_os().nth(1).as_deref(), unsafe {
            libc::getpid()
        });
    if let Err(error) = entrypoint() {
        eprintln!("codewire guest probe failed: {error:#}");
        #[cfg(target_os = "linux")]
        if fatal_vm_init_failure {
            codewire_vmm_guest_probe::guest::halt_after_init_failure();
        }
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn is_fatal_vm_init_failure(command: Option<&OsStr>, pid: libc::pid_t) -> bool {
    pid == 1 && command.is_none()
}

#[cfg(target_os = "linux")]
fn entrypoint() -> anyhow::Result<()> {
    use anyhow::{Context, bail, ensure};
    use codewire_vmm_guest_probe::guest;

    let mut arguments = std::env::args_os();
    let executable = arguments.next();
    if executable
        .as_deref()
        .and_then(|path| Path::new(path).file_name())
        == Some(OsStr::new("cw"))
    {
        return codewire_vmm_guest_probe::cw_runtime_publisher::launch_default(arguments.collect());
    }
    let command = arguments.next();
    match command.as_deref().and_then(|value| value.to_str()) {
        None => {
            ensure!(
                arguments.next().is_none(),
                "guest init accepts no arguments"
            );
            guest::run_init()
        }
        Some("daemon") => {
            ensure!(
                arguments.next().is_none(),
                "guest daemon accepts no arguments"
            );
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("create guest daemon Tokio runtime")?;
            runtime.block_on(guest::run_daemon())
        }
        Some("network-agent") => {
            ensure!(
                arguments.next().is_none(),
                "network agent accepts no arguments"
            );
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .context("create guest network-agent Tokio runtime")?;
            runtime.block_on(guest::run_network_agent())
        }
        Some("identity") => {
            ensure!(arguments.next().is_none(), "identity accepts no arguments");
            guest::run_identity()
        }
        Some("write-nonce") => {
            let nonce = arguments
                .next()
                .ok_or_else(|| anyhow::anyhow!("write-nonce requires one nonce"))?;
            ensure!(arguments.next().is_none(), "write-nonce accepts one nonce");
            guest::run_write_nonce(&nonce)
        }
        Some("read-nonce") => {
            ensure!(
                arguments.next().is_none(),
                "read-nonce accepts no arguments"
            );
            guest::run_read_nonce()
        }
        Some("network-check") => {
            ensure!(
                arguments.next().is_none(),
                "network-check accepts no arguments"
            );
            guest::run_network_check()
        }
        Some("poweroff") => {
            ensure!(arguments.next().is_none(), "poweroff accepts no arguments");
            guest::run_poweroff()
        }
        Some("runc-exec") => {
            let container_id = arguments
                .next()
                .ok_or_else(|| anyhow::anyhow!("runc-exec requires a container ID"))?;
            let process_spec = arguments
                .next()
                .ok_or_else(|| anyhow::anyhow!("runc-exec requires a process spec"))?;
            ensure!(
                arguments.next().is_none(),
                "runc-exec accepts exactly two arguments"
            );
            guest::run_runc_exec(&container_id, Path::new(&process_spec))
        }
        Some("workspace-init") => {
            ensure!(
                arguments.next().is_none(),
                "workspace-init accepts no arguments"
            );
            guest::run_workspace_init()
        }
        Some("credential-forwarder") => {
            ensure!(
                arguments.next().is_none(),
                "credential-forwarder accepts no arguments"
            );
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("create credential forwarder Tokio runtime")?;
            runtime.block_on(guest::run_credential_forwarder())
        }
        Some("workspace-exec") => guest::run_workspace_exec(arguments.collect()),
        Some("docker-fixture") => guest::run_docker_fixture(arguments.collect()),
        Some("newc") => build_newc(arguments),
        Some("newc-root") => build_guest_root_newc(arguments),
        Some("newc-root-cw") => bail!(
            "embedded cw boot assets are unsupported; supply the separate read-only cw runtime disk"
        ),
        Some(_) => {
            let _ = executable;
            bail!("unknown guest probe command")
        }
    }
}

#[cfg(target_os = "linux")]
fn build_guest_root_newc(mut arguments: impl Iterator<Item = OsString>) -> anyhow::Result<()> {
    use anyhow::ensure;

    let probe = arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("newc-root requires a probe path"))?;
    let busybox = arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("newc-root requires a BusyBox path"))?;
    let runc = arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("newc-root requires a runc path"))?;
    let output = arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("newc-root requires an output path"))?;
    ensure!(
        arguments.next().is_none(),
        "newc-root accepts exactly four paths"
    );
    for (label, value) in [
        ("probe", &probe),
        ("BusyBox", &busybox),
        ("runc", &runc),
        ("output", &output),
    ] {
        ensure!(
            Path::new(value).is_absolute(),
            "newc-root {label} path must be absolute"
        );
    }
    codewire_vmm_guest_probe::write_canonical_guest_root_initramfs(probe, busybox, runc, output)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_newc(mut arguments: impl Iterator<Item = OsString>) -> anyhow::Result<()> {
    use anyhow::ensure;

    let probe = arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("newc requires a probe path"))?;
    let output = arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("newc requires an output path"))?;
    ensure!(arguments.next().is_none(), "newc accepts exactly two paths");
    ensure!(
        Path::new(&probe).is_absolute(),
        "newc probe path must be absolute"
    );
    ensure!(
        Path::new(&output).is_absolute(),
        "newc output path must be absolute"
    );
    codewire_vmm_guest_probe::write_canonical_initramfs(probe, output)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn entrypoint() -> Result<(), Box<dyn std::error::Error>> {
    Err("codewire-vmm-guest-probe is supported only on Linux".into())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn only_initial_vm_modes_halt_after_pid_one_failure() {
        assert!(is_fatal_vm_init_failure(None, 1));
        for command in ["workspace-init", "daemon", "network-agent", "identity"] {
            assert!(!is_fatal_vm_init_failure(Some(OsStr::new(command)), 1));
        }
        assert!(!is_fatal_vm_init_failure(None, 2));
    }
}
