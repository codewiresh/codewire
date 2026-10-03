#![cfg(target_os = "linux")]

//! Actual kernel mounts and the source-built trusted launcher. The tiny A/B
//! ELFs are closed synthetic workload fixtures, not production cw/image proof.

use std::ffi::CString;
use std::fs;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::{Command, Stdio};

use codewire_vmm_guest_probe::cw_runtime::{
    CW_RUNTIME_ROOT, CwImageDescriptor, CwImagePayload, CwRuntimeCatalog, CwRuntimeProvenance,
};
use codewire_vmm_guest_probe::cw_runtime_live::{
    LIVE_RUNTIME_LAUNCHER, LIVE_RUNTIME_PROTOCOL, LIVE_RUNTIME_VIEW, RuntimeAction, RuntimeBinding,
    RuntimeRequest,
};
use codewire_vmm_guest_probe::cw_runtime_publisher::RuntimeCache;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn directory(path: &Path, mode: u32) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn sealed(path: &Path, bytes: &[u8], mode: u32) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    file.set_permissions(fs::Permissions::from_mode(mode))
        .unwrap();
}

fn synthetic_payload(version: u8) -> Vec<u8> {
    assert!(matches!(version, b'A' | b'B'));
    let message = format!("cw fixture {}\n", char::from(version));
    // Fixed x86_64 syscalls: refuse execution unless euid=65534, write the
    // fixed version line, exit. No input, interpreter, library or root code.
    let mut code = vec![
        0xb8, 107, 0, 0, 0, 0x0f, 0x05, // geteuid
        0x3d, 0xfe, 0xff, 0, 0, // cmp eax,65534
        0x0f, 0x85, 33, 0, 0, 0, // jne failure
        0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, // write(1,...)
        0x48, 0x8d, 0x35, 28, 0, 0, 0, // fixed message address
        0xba, 0, 0, 0, 0, 0x0f, 0x05, // message length, syscall
        0x31, 0xff, 0xb8, 60, 0, 0, 0, 0x0f, 0x05, // exit(0)
        0xbf, 99, 0, 0, 0, 0xb8, 60, 0, 0, 0, 0x0f, 0x05, // failure
    ];
    assert_eq!(code.len(), 63);
    code[36..40].copy_from_slice(&(message.len() as u32).to_le_bytes());
    code.extend_from_slice(message.as_bytes());
    let mut elf = vec![0_u8; 120];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x400078_u64.to_le_bytes());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
    elf[68..72].copy_from_slice(&5_u32.to_le_bytes()); // RX
    elf[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[88..96].copy_from_slice(&0x400000_u64.to_le_bytes());
    let size = (elf.len() + code.len()) as u64;
    elf[96..104].copy_from_slice(&size.to_le_bytes());
    elf[104..112].copy_from_slice(&size.to_le_bytes());
    elf[112..120].copy_from_slice(&4096_u64.to_le_bytes());
    elf.extend(code);
    elf
}

fn provenance(bytes: &[u8], version: &str) -> CwRuntimeProvenance {
    // Synthetic closed identity, explicitly not an admitted production image.
    CwRuntimeProvenance {
        schema_version: 1,
        image_index_sha256: "1".repeat(64),
        image_manifest: CwImageDescriptor {
            sha256: "2".repeat(64),
            size: 512,
        },
        image_config: CwImageDescriptor {
            sha256: "3".repeat(64),
            size: 512,
        },
        image_layer: CwImageDescriptor {
            sha256: "4".repeat(64),
            size: 1024,
        },
        layer_diff_id: "4".repeat(64),
        payload: CwImagePayload {
            schema_version: 2,
            protocol_version: 1,
            record_version: 1,
            package_version: version.into(),
            target: "x86_64-unknown-linux-musl".into(),
            source_revision: "a".repeat(40),
            source_tree_sha256: "b".repeat(64),
            rustc: "rustc 1.93.0 (254b59607 2026-01-19)".into(),
            sha256: digest(bytes),
            size: bytes.len() as u64,
        },
    }
}

struct OwnedMount(CString);
impl OwnedMount {
    fn bind(source: &Path, target: &Path, readonly: bool) -> Self {
        let source = CString::new(source.as_os_str().as_encoded_bytes()).unwrap();
        let target = CString::new(target.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(
            unsafe {
                libc::mount(
                    source.as_ptr(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                )
            },
            0,
            "private bind failed: {}",
            std::io::Error::last_os_error()
        );
        let mount = Self(target);
        if readonly {
            assert_eq!(
                unsafe {
                    libc::mount(
                        std::ptr::null(),
                        mount.0.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND
                            | libc::MS_REMOUNT
                            | libc::MS_RDONLY
                            | libc::MS_NOSUID
                            | libc::MS_NODEV,
                        std::ptr::null(),
                    )
                },
                0,
                "private readonly remount failed: {}",
                std::io::Error::last_os_error()
            );
        }
        mount
    }
}
impl Drop for OwnedMount {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) },
            0
        );
    }
}

struct OwnedRoot(fs::File);
impl OwnedRoot {
    fn enter(root: &Path) -> Self {
        let original = fs::File::open("/").unwrap();
        let root = CString::new(root.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::chroot(root.as_ptr()) }, 0);
        std::env::set_current_dir("/").unwrap();
        Self(original)
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::fchdir(self.0.as_raw_fd()) }, 0);
        let dot = CString::new(".").unwrap();
        assert_eq!(unsafe { libc::chroot(dot.as_ptr()) }, 0);
        std::env::set_current_dir("/").unwrap();
    }
}

fn kernel_login_shell() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
    let slash = CString::new("/").unwrap();
    assert_eq!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                slash.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        },
        0
    );
    let executable = std::env::current_exe().unwrap();
    let scratch = tempfile::Builder::new()
        .prefix("cw-runtime-login-kernel-")
        .tempdir_in(executable.parent().unwrap())
        .unwrap();
    fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let private_root = scratch.path().join("root");
    let private_bin = scratch.path().join("bin");
    for path in [&private_root, &private_bin] {
        directory(path, 0o755);
    }
    for name in ["usr", "run", "state", "etc"] {
        directory(&private_root.join(name), 0o755);
    }
    for (name, target) in [
        ("bin", "usr/bin"),
        ("lib", "usr/lib"),
        ("lib64", "usr/lib64"),
    ] {
        std::os::unix::fs::symlink(target, private_root.join(name)).unwrap();
    }
    // A private root avoids creating even a mountpoint in the host's /state
    // or /run. Only the system tool/library tree is exposed, readonly.
    let _usr = OwnedMount::bind(Path::new("/usr"), &private_root.join("usr"), true);
    let _bin = OwnedMount::bind(&private_bin, &private_root.join("usr/local/bin"), false);
    sealed(
        &private_root.join("etc/profile"),
        b"PATH=/usr/local/bin:/usr/bin:/bin\nexport PATH\n",
        0o444,
    );

    let a_bytes = synthetic_payload(b'A');
    let b_bytes = synthetic_payload(b'B');
    let a = provenance(&a_bytes, "fixture-A");
    let b = provenance(&b_bytes, "fixture-B");
    a.validate_payload(&a_bytes).unwrap();
    b.validate_payload(&b_bytes).unwrap();
    let bootstrap = CwRuntimeCatalog {
        schema_version: 1,
        active_sha256: a.payload.sha256.clone(),
        runtimes: vec![a.clone()],
    };
    let binding = RuntimeBinding {
        environment_id: Uuid::new_v4(),
        generation: 1,
        bootstrap_catalog_sha256: digest(&bootstrap.encode().unwrap()),
    };
    let bootstrap_source = private_root.join("bootstrap");
    directory(&bootstrap_source, 0o700);
    let member = bootstrap_source.join(&a.payload.sha256);
    directory(&member, 0o700);
    sealed(&member.join("cw"), &a_bytes, 0o555);
    sealed(
        &member.join("provenance.json"),
        &serde_json::to_vec(&a).unwrap(),
        0o444,
    );
    fs::set_permissions(&member, fs::Permissions::from_mode(0o555)).unwrap();
    let launcher_source = private_root.join("trusted-source-built-init");
    // Cargo binds this actual executable to this test's source build. It is
    // the trusted launcher, never the incoming synthetic A/B payload.
    sealed(
        &launcher_source,
        &fs::read(env!("CARGO_BIN_EXE_codewire-vmm-guest-probe")).unwrap(),
        0o755,
    );
    let _root = OwnedRoot::enter(&private_root);
    directory(Path::new("/state/codewire"), 0o700);
    directory(Path::new("/run/codewire-runtime"), 0o755);
    directory(Path::new(CW_RUNTIME_ROOT), 0o555);
    let home = Path::new("/run/cw-runtime-fixture-home");
    directory(home, 0o700);
    std::os::unix::fs::chown(home, Some(65534), Some(65534)).unwrap();
    let bootstrap_root = Path::new("/bootstrap");
    let launcher = Path::new("/trusted-source-built-init");
    let cache =
        RuntimeCache::initialize(binding.clone(), &bootstrap, bootstrap_root, launcher).unwrap();
    let _view = OwnedMount::bind(
        Path::new(LIVE_RUNTIME_VIEW),
        Path::new(CW_RUNTIME_ROOT),
        true,
    );
    sealed(Path::new(LIVE_RUNTIME_LAUNCHER), b"", 0o555);
    let _launcher = OwnedMount::bind(
        &Path::new(LIVE_RUNTIME_VIEW).join("cw"),
        Path::new(LIVE_RUNTIME_LAUNCHER),
        true,
    );
    let original_launcher = fs::symlink_metadata(LIVE_RUNTIME_LAUNCHER).unwrap();
    let original_a = fs::symlink_metadata(a.executable()).unwrap();
    for path in [LIVE_RUNTIME_LAUNCHER.to_owned(), a.executable()] {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (0, 0));
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.mode() & 0o7777, 0o555);
    }
    assert_eq!(
        fs::write(LIVE_RUNTIME_LAUNCHER, b"refuse")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EROFS)
    );
    let login = |expected: &str| {
        let output = Command::new("/bin/bash")
            .env_clear()
            .env("HOME", home)
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .args(["-lc", "command -v cw; cw --version"])
            .current_dir("/")
            .uid(65534)
            .gid(65534)
            // output() closes this pipe immediately. The private root does
            // not need a host /dev/null or any caller-controlled input.
            .stdin(Stdio::piped())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "workload login shell failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{LIVE_RUNTIME_LAUNCHER}\ncw fixture {expected}\n")
        );
    };
    login("A");
    let request = |action| RuntimeRequest {
        protocol_version: LIVE_RUNTIME_PROTOCOL,
        binding: binding.clone(),
        action,
    };
    let operation = Uuid::new_v4();
    let provenance = serde_json::to_vec(&b).unwrap();
    let mut pack = b"CWRPACK1".to_vec();
    pack.extend_from_slice(&(provenance.len() as u64).to_le_bytes());
    pack.extend_from_slice(&(b_bytes.len() as u64).to_le_bytes());
    pack.extend(provenance);
    pack.extend(&b_bytes);
    cache
        .publish(
            &request(RuntimeAction::Publish {
                operation_id: operation,
                pack_size: pack.len() as u64,
                pack_sha256: digest(&pack),
                provenance: Box::new(b.clone()),
            }),
            &pack,
        )
        .unwrap();
    cache
        .control(&request(RuntimeAction::Select {
            operation_id: operation,
            expected_revision: 1,
            target_sha256: b.payload.sha256.clone(),
        }))
        .unwrap();
    login("B");
    cache
        .control(&request(RuntimeAction::RetainedSelect {
            operation_id: Uuid::new_v4(),
            expected_revision: 2,
            target_sha256: a.payload.sha256.clone(),
        }))
        .unwrap();
    login("A");
    assert_eq!(cache.selection().unwrap().revision, 3);
    assert_eq!(fs::read(a.executable()).unwrap(), a_bytes);
    assert_eq!(fs::read(b.executable()).unwrap(), b_bytes);
    let retained_launcher = fs::symlink_metadata(LIVE_RUNTIME_LAUNCHER).unwrap();
    let retained_a = fs::symlink_metadata(a.executable()).unwrap();
    assert_eq!(
        (original_launcher.dev(), original_launcher.ino()),
        (retained_launcher.dev(), retained_launcher.ino())
    );
    assert_eq!(
        (original_a.dev(), original_a.ino()),
        (retained_a.dev(), retained_a.ino())
    );
}

#[test]
fn source_launcher_login_shell_selects_a_b_a_on_readonly_mounts() {
    let executable = std::env::current_exe().unwrap();
    let mut child = if unsafe { libc::geteuid() } == 0 {
        let mut child = Command::new(&executable);
        child
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("CW_RUNTIME_LOGIN_KERNEL", "1");
        child
    } else {
        let mut child = Command::new("/usr/bin/sudo");
        child
            .args([
                "-n",
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
                "LC_ALL=C",
                "CW_RUNTIME_LOGIN_KERNEL=1",
            ])
            .arg(&executable);
        child
    };
    let output = child
        .args([
            "--ignored",
            "--exact",
            "source_bound_root_login_child",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "actual isolated login-shell proof failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed; 0 ignored"));
}

#[test]
#[ignore = "invoked exactly by the source-bound kernel wrapper; not optional proof"]
fn source_bound_root_login_child() {
    assert_eq!(std::env::var("CW_RUNTIME_LOGIN_KERNEL").unwrap(), "1");
    kernel_login_shell();
}
