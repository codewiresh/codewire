//! Local VMs on a Mac need Apple silicon and macOS 26 or later, the bound the
//! Virtualization.framework helper itself enforces. cw refuses before any
//! effect and names the reason; the helper's own guard stays a second line.

/// The oldest macOS major version that runs local VMs.
#[cfg(any(target_os = "macos", test))]
const MINIMUM_MACOS_MAJOR: u32 = 26;

/// Refuse to create, start or install local VMs on a Mac that cannot run them.
/// Listing and inspecting environments stay available everywhere.
#[cfg(target_os = "macos")]
pub(crate) fn require_local_vm_host() -> anyhow::Result<()> {
    let version = sysctl_string(c"kern.osproductversion").unwrap_or_default();
    let translated = sysctl_i32(c"sysctl.proc_translated") == Some(1);
    match local_vm_host_refusal(std::env::consts::ARCH, translated, &version) {
        Some(reason) => Err(anyhow::anyhow!(reason)),
        None => Ok(()),
    }
}

/// Refuse to create, start or install local VMs on a Linux host that cannot
/// run them, naming every unmet prerequisite and its fix (#2733); the
/// supervisor's own preflight stays a second line. Advice that does not
/// block, such as a missing git, is printed once to stderr.
#[cfg(target_os = "linux")]
pub(crate) fn require_local_vm_host() -> anyhow::Result<()> {
    let problems = codewire_local_vmm::linux::host_prerequisites();
    if let Some(report) = codewire_local_vmm::linux::host_problem_report(&problems) {
        anyhow::bail!(report);
    }
    for problem in problems.iter().filter(|problem| !problem.required) {
        eprintln!("Note: {}. {}.", problem.problem, problem.fix);
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn require_local_vm_host() -> anyhow::Result<()> {
    Ok(())
}

/// Why this Mac cannot run local VMs, or `None` when it can.
#[cfg(any(target_os = "macos", test))]
fn local_vm_host_refusal(arch: &str, translated: bool, product_version: &str) -> Option<String> {
    if arch != "aarch64" {
        return Some(if translated {
            "local VMs need the Apple silicon build of cw; this is the Intel build running under Rosetta. Reinstall with `curl -fsSL https://codewire.sh/install.sh | sh` from a native terminal".to_owned()
        } else {
            "local VMs need a Mac with Apple silicon".to_owned()
        });
    }
    let major = product_version
        .split('.')
        .next()
        .and_then(|major| major.parse::<u32>().ok());
    match major {
        Some(major) if major >= MINIMUM_MACOS_MAJOR => None,
        Some(_) => Some(format!(
            "local VMs need macOS {MINIMUM_MACOS_MAJOR} or later; this Mac runs macOS {product_version}"
        )),
        None => Some("could not read the macOS version, so local VMs are not started".to_owned()),
    }
}

#[cfg(target_os = "macos")]
fn sysctl_string(name: &std::ffi::CStr) -> Option<String> {
    let mut buffer = [0_u8; 64];
    let mut length = buffer.len();
    // SAFETY: the buffer and its length describe writable memory owned here.
    let status = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 || length == 0 || length > buffer.len() {
        return None;
    }
    let text = buffer[..length].split(|byte| *byte == 0).next()?;
    std::str::from_utf8(text).ok().map(str::to_owned)
}

#[cfg(target_os = "macos")]
fn sysctl_i32(name: &std::ffi::CStr) -> Option<i32> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>();
    // SAFETY: `value` is a writable c_int and `length` is its size.
    let status = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    (status == 0 && length == std::mem::size_of::<libc::c_int>()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_vms_need_apple_silicon_and_macos_26() {
        assert_eq!(local_vm_host_refusal("aarch64", false, "26.0"), None);
        assert_eq!(local_vm_host_refusal("aarch64", false, "26.6.2"), None);
        assert_eq!(local_vm_host_refusal("aarch64", false, "27.1"), None);

        let old = local_vm_host_refusal("aarch64", false, "15.7.1").unwrap();
        assert!(old.contains("macOS 26 or later"), "{old}");
        assert!(old.contains("macOS 15.7.1"), "{old}");

        let intel = local_vm_host_refusal("x86_64", false, "26.6.2").unwrap();
        assert!(intel.contains("Apple silicon"), "{intel}");
        let rosetta = local_vm_host_refusal("x86_64", true, "26.6.2").unwrap();
        assert!(rosetta.contains("Rosetta"), "{rosetta}");
        assert!(rosetta.contains("install.sh"), "{rosetta}");

        for unreadable in ["", "macOS", ".1"] {
            let refusal = local_vm_host_refusal("aarch64", false, unreadable).unwrap();
            assert!(refusal.contains("could not read"), "{refusal}");
        }
    }
}
