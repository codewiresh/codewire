//! Prepare private copies of Cargo's actual CW for native integration tests.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::{Child, Command, Stdio};
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

#[cfg(target_os = "linux")]
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

#[cfg(target_os = "linux")]
struct StripChild(Child);

#[cfg(target_os = "linux")]
impl Drop for StripChild {
    fn drop(&mut self) {
        // This handle owns an unreaped child, never a persisted numeric PID.
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        let _ = self.0.kill();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.0.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                _ => {
                    eprintln!("strip child closure unknown; retain the CW fixture");
                    return;
                }
            }
        }
    }
}

pub fn prepare(path: &Path) {
    let parent = fs::symlink_metadata(path.parent().unwrap()).unwrap();
    assert!(parent.is_dir() && !parent.file_type().is_symlink());
    assert_eq!(parent.uid(), unsafe { libc::geteuid() });
    assert_eq!(parent.mode() & 0o7777, 0o700);

    let mut source = File::open(env!("CARGO_BIN_EXE_cw")).unwrap();
    let mut copy = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    io::copy(&mut source, &mut copy).unwrap();
    drop(copy);

    #[cfg(target_os = "linux")]
    strip_linux_copy(path);
    #[cfg(target_os = "macos")]
    check_macos_copy(path);
    fs::set_permissions(path, fs::Permissions::from_mode(0o500)).unwrap();
    assert_eq!(fs::symlink_metadata(path).unwrap().mode() & 0o7777, 0o500);
}

/// Spawn an executable a test process just wrote or copied. A concurrent
/// test's fork child holds the write descriptor until its own exec, so the
/// kernel briefly refuses this exec with ETXTBSY; retry only that, bounded.
pub fn spawn_written<T>(mut spawn: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    for _ in 1..50 {
        match spawn() {
            Err(error) if error.kind() == io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(Duration::from_millis(20));
            }
            result => return result,
        }
    }
    spawn()
}

/// Cargo's debug CW can exceed the member helper's executable cap. Strip only
/// this disposable copy. Since Rust 1.97 its v0-mangled symbol names alone
/// exceed that cap, so remove the symbol table with the debug information.
/// --strip-all preserves allocated code/data, including the #[used] build
/// record backing CLI_VERSION.
#[cfg(target_os = "linux")]
fn strip_linux_copy(path: &Path) {
    let mut strip = StripChild(
        Command::new("/usr/bin/strip")
            .args(["--strip-all", "--"])
            .arg(path)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("strip debugging information from the owned CW copy"),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = strip.0.try_wait().unwrap() {
            assert!(status.success(), "strip owned CW copy: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "bounded CW fixture preparation");
        std::thread::sleep(Duration::from_millis(20));
    }

    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.nlink(), 1);
    assert!((20..=MAX_EXECUTABLE_BYTES).contains(&metadata.len()));
    let mut header = [0; 20];
    File::open(path).unwrap().read_exact(&mut header).unwrap();
    assert_eq!(&header[..7], b"\x7fELF\x02\x01\x01");
    #[cfg(target_arch = "x86_64")]
    assert_eq!(u16::from_le_bytes([header[18], header[19]]), 62);
    #[cfg(target_arch = "aarch64")]
    assert_eq!(u16::from_le_bytes([header[18], header[19]]), 183);
}

/// A macOS copy keeps its ad hoc signature only unstripped; nothing on macOS
/// caps the executable's size.
#[cfg(target_os = "macos")]
fn check_macos_copy(path: &Path) {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
    assert_eq!(metadata.nlink(), 1);
    let mut header = [0; 8];
    File::open(path).unwrap().read_exact(&mut header).unwrap();
    // MH_MAGIC_64, then CPU_TYPE_ARM64.
    assert_eq!(&header, &[0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01]);
}
