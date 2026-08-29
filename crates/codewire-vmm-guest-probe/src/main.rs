#[cfg(target_os = "linux")]
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::path::Path;

fn main() {
    if let Err(error) = entrypoint() {
        eprintln!("codewire guest probe failed: {error:#}");
        #[cfg(target_os = "linux")]
        if unsafe { libc::getpid() } == 1 {
            codewire_vmm_guest_probe::guest::halt_after_init_failure();
        }
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn entrypoint() -> anyhow::Result<()> {
    use anyhow::{Context, bail, ensure};
    use codewire_vmm_guest_probe::guest;

    let mut arguments = std::env::args_os();
    let executable = arguments.next();
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
        Some("newc") => build_newc(arguments),
        Some("newc-root") => build_guest_root_newc(arguments),
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
    let output = arguments
        .next()
        .ok_or_else(|| anyhow::anyhow!("newc-root requires an output path"))?;
    ensure!(
        arguments.next().is_none(),
        "newc-root accepts exactly three paths"
    );
    for (label, value) in [
        ("probe", &probe),
        ("BusyBox", &busybox),
        ("output", &output),
    ] {
        ensure!(
            Path::new(value).is_absolute(),
            "newc-root {label} path must be absolute"
        );
    }
    codewire_vmm_guest_probe::write_canonical_guest_root_initramfs(probe, busybox, output)?;
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
