//! `mount-workspace` fails closed (#3718, design §2): it formats only a new
//! volume that is not already ext4, an existing one must be ext4, and every
//! refusal is one clear line, a non-zero exit, and no format or mount. The
//! real script runs under `sh` with stand-ins for the tools that need root
//! or a block device; each stand-in records its call, and a scratch file is
//! the device.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::MOUNT_WORKSPACE_SCRIPT;
use super::workspace::WORKSPACE_FLUSH_SCRIPT;

/// The stand-ins. `blkid -p` answers from `$FAKE/signature` (`none`, `ext4`,
/// `xfs`, `error` or `ambiguous`); `mkfs.ext4` writes `ext4` there unless
/// `$FAKE/mkfs` says `fail`; `wipefs` clears it; `dumpe2fs -h` reads a
/// superblock when the signature is `ext4` or `$FAKE/superblock` says `yes`;
/// `e2fsck`, `mount` and `resize2fs` exit with the status in `$FAKE/<tool>`
/// (0 by default).
const STANDINS: &[(&str, &str)] = &[
    (
        "blkid",
        r#"echo "blkid $*" >>"$FAKE/calls"
signature="$(cat "$FAKE/signature")"
case "$signature" in
  none) exit 2 ;;
  error) exit 4 ;;
  ambiguous) exit 8 ;;
esac
case " $* " in *" -s TYPE "*) echo "$signature" ;; esac"#,
    ),
    (
        "mkfs.ext4",
        r#"echo "mkfs.ext4 $*" >>"$FAKE/calls"
[ "$(cat "$FAKE/mkfs" 2>/dev/null)" != fail ] || exit 1
echo ext4 >"$FAKE/signature""#,
    ),
    (
        "dumpe2fs",
        r#"echo "dumpe2fs $*" >>"$FAKE/calls"
[ "$(cat "$FAKE/signature")" = ext4 ] || [ "$(cat "$FAKE/superblock" 2>/dev/null)" = yes ]"#,
    ),
    (
        "wipefs",
        r#"echo "wipefs $*" >>"$FAKE/calls"; echo none >"$FAKE/signature""#,
    ),
    (
        "e2fsck",
        r#"echo "e2fsck $*" >>"$FAKE/calls"; exit "$(cat "$FAKE/e2fsck" 2>/dev/null || echo 0)""#,
    ),
    (
        "mount",
        r#"echo "mount $*" >>"$FAKE/calls"; exit "$(cat "$FAKE/mount" 2>/dev/null || echo 0)""#,
    ),
    (
        "resize2fs",
        r#"echo "resize2fs $*" >>"$FAKE/calls"; exit "$(cat "$FAKE/resize2fs" 2>/dev/null || echo 0)""#,
    ),
    ("chown", r#"echo "chown $*" >>"$FAKE/calls""#),
];

struct Scene {
    _dir: tempfile::TempDir,
    root: PathBuf,
    fake: PathBuf,
    bin: PathBuf,
    device: PathBuf,
}

impl Scene {
    fn new(signature: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let fake = dir.path().join("fake");
        let bin = dir.path().join("bin");
        for path in [&root, &fake, &bin] {
            std::fs::create_dir(path).unwrap();
        }
        for (name, body) in STANDINS {
            let path = bin.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            let mut permissions = std::fs::metadata(&path).unwrap().permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
            std::fs::set_permissions(&path, permissions).unwrap();
        }
        std::fs::write(fake.join("signature"), signature).unwrap();
        let device = dir.path().join("device");
        std::fs::write(&device, vec![0u8; 8192]).unwrap();
        Self {
            root,
            fake,
            bin,
            device,
            _dir: dir,
        }
    }

    fn set(&self, tool: &str, value: &str) {
        std::fs::write(self.fake.join(tool), value).unwrap();
    }

    fn run(&self, volume: &str) -> Outcome {
        self.run_on(&self.device, volume)
    }

    fn run_on(&self, device: &Path, volume: &str) -> Outcome {
        self.run_with(device, volume, &[])
    }

    fn run_with(&self, device: &Path, volume: &str, env: &[(&str, &str)]) -> Outcome {
        let output = Command::new("sh")
            .args(["-c", MOUNT_WORKSPACE_SCRIPT, "mount-workspace", volume])
            .env_clear()
            .envs(env.iter().copied())
            .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
            .env("FAKE", &self.fake)
            .env("CODEWIRE_MOUNT_WORKSPACE_DEVICE", device)
            .env("CODEWIRE_MOUNT_WORKSPACE_ROOT", &self.root)
            .env("CODEWIRE_MOUNT_WORKSPACE_TMP", self.fake.join("tmp-target"))
            .output()
            .unwrap();
        Outcome {
            status: output.status.code().unwrap(),
            stdout: String::from_utf8(output.stdout).unwrap(),
            stderr: String::from_utf8(output.stderr).unwrap(),
            calls: std::fs::read_to_string(self.fake.join("calls")).unwrap_or_default(),
        }
    }
}

struct Outcome {
    status: i32,
    stdout: String,
    stderr: String,
    calls: String,
}

impl Outcome {
    /// A refusal: exit 1, exactly one line naming why, and no format, wipe
    /// or mount of any kind.
    fn refused(&self, why: &str) {
        self.refused_after_trying(why);
        assert!(!self.calls.contains("mkfs.ext4"), "{}", self.calls);
        assert!(!self.calls.contains("wipefs"), "{}", self.calls);
    }

    /// A refusal that may have tried to format, but mounted nothing.
    fn refused_after_trying(&self, why: &str) {
        assert_eq!(self.status, 1, "{}", self.stderr);
        let lines: Vec<_> = self.stderr.lines().collect();
        assert_eq!(
            lines,
            [format!("codewire mount-workspace: {why}")],
            "{}",
            self.stderr
        );
        assert!(!self.calls.contains("mount "), "{}", self.calls);
    }

    fn mounted(&self) {
        assert_eq!(self.status, 0, "{}", self.stderr);
        assert!(
            self.calls.contains("mount -t ext4 -o noatime "),
            "{}",
            self.calls
        );
        assert!(self.calls.contains("mount --bind"), "{}", self.calls);
    }

    /// The last line names the volume, whether it was formatted, and the
    /// time `e2fsck` and the whole step took, in milliseconds.
    fn mounted_line(&self, volume: &str, formatted: u8) {
        let line = self.stdout.trim_end();
        let prefix = format!(
            "codewire mount-workspace: mounted the {volume} workspace volume (formatted={formatted} e2fsck_ms="
        );
        let rest = line
            .strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("{line}"));
        let (check, total) = rest
            .strip_suffix(')')
            .and_then(|rest| rest.split_once(" total_ms="))
            .unwrap_or_else(|| panic!("{line}"));
        let check: u64 = check.parse().unwrap();
        let total: u64 = total.parse().unwrap();
        assert!(check <= total, "{line}");
    }
}

#[test]
fn a_new_volume_with_no_signature_is_formatted_checked_mounted_and_grown() {
    let scene = Scene::new("none");
    let outcome = scene.run("new");
    outcome.mounted();
    let calls: Vec<_> = outcome
        .calls
        .lines()
        .map(|line| line.split(' ').next().unwrap())
        .collect();
    assert_eq!(
        calls,
        [
            "blkid",
            "dumpe2fs",
            "mkfs.ext4",
            "e2fsck",
            "mount",
            "resize2fs",
            "chown",
            "chown",
            "mount"
        ]
    );
    assert!(
        outcome
            .calls
            .contains("mkfs.ext4 -q -F -E lazy_itable_init=1,lazy_journal_init=1")
    );
    assert!(outcome.calls.contains("e2fsck -f -p"));
    assert!(
        outcome
            .calls
            .contains(&format!("chown 1000:1000 {}\n", scene.root.display()))
    );
    assert!(!outcome.calls.contains("wipefs"));
    outcome.mounted_line("new", 1);
    let tmp = scene.root.join(".codewire/tmp");
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&tmp).unwrap().permissions())
            & 0o7777,
        0o1777
    );
}

/// A new LUKS volume reads as random bytes, which may match a short foreign
/// magic by chance: its signatures are wiped before it is formatted.
#[test]
fn a_new_volume_with_a_chance_signature_is_wiped_and_formatted() {
    for signature in ["xfs", "ambiguous"] {
        let scene = Scene::new(signature);
        let outcome = scene.run("new");
        outcome.mounted();
        let wiped = outcome
            .calls
            .find("wipefs -a -q")
            .unwrap_or_else(|| panic!("{signature}: {}", outcome.calls));
        let formatted = outcome.calls.find("mkfs.ext4 -q -F").unwrap();
        assert!(wiped < formatted, "{signature}: {}", outcome.calls);
        outcome.mounted_line("new", 1);
    }
}

/// The random bytes around a real filesystem may match a foreign magic too,
/// which makes `blkid` ambiguous: a valid ext4 superblock is never wiped or
/// formatted, new or not, and still mounts.
#[test]
fn a_real_ext4_superblock_is_never_wiped_whatever_the_probe_says() {
    for (volume, signature) in [
        ("new", "ambiguous"),
        ("existing", "ambiguous"),
        ("new", "error"),
    ] {
        let scene = Scene::new(signature);
        scene.set("superblock", "yes");
        let outcome = scene.run(volume);
        outcome.mounted();
        assert!(
            !outcome.calls.contains("mkfs.ext4") && !outcome.calls.contains("wipefs"),
            "{volume} {signature}: {}",
            outcome.calls
        );
        outcome.mounted_line(volume, 0);
    }
}

#[test]
fn a_volume_that_already_has_a_filesystem_is_never_formatted() {
    for volume in ["new", "existing"] {
        let scene = Scene::new("ext4");
        std::fs::create_dir_all(scene.root.join(".codewire/tmp/left-over")).unwrap();
        let outcome = scene.run(volume);
        outcome.mounted();
        assert!(
            !outcome.calls.contains("mkfs.ext4") && !outcome.calls.contains("wipefs"),
            "{volume}: {}",
            outcome.calls
        );
        // A filesystem it did not format keeps its root's owner.
        assert!(
            !outcome
                .calls
                .contains(&format!("chown 1000:1000 {}\n", scene.root.display()))
        );
        // `/tmp` starts empty at every boot (R1).
        assert!(!scene.root.join(".codewire/tmp/left-over").exists());
        outcome.mounted_line(volume, 0);
    }
}

#[test]
fn an_existing_volume_with_no_filesystem_is_refused_not_formatted() {
    Scene::new("none")
        .run("existing")
        .refused("the existing workspace volume has no filesystem; it is not formatted");
}

#[test]
fn a_device_that_cannot_be_read_is_never_probed_or_formatted() {
    let scene = Scene::new("none");
    let missing = scene.root.join("no-such-device");
    let outcome = scene.run_on(&missing, "new");
    outcome.refused(&format!(
        "the workspace device {} cannot be read",
        missing.display()
    ));
    assert!(!outcome.calls.contains("blkid"), "{}", outcome.calls);
}

#[test]
fn an_existing_volume_must_be_ext4_and_a_failed_probe_is_never_formatted_over() {
    Scene::new("error")
        .run("existing")
        .refused("probing the workspace device failed (blkid exit 4)");
    Scene::new("ambiguous")
        .run("existing")
        .refused("probing the workspace device failed (blkid exit 8)");
    Scene::new("xfs")
        .run("existing")
        .refused("the workspace volume holds 'xfs', not ext4");
    // A probe that failed outright refuses, even for a new volume.
    Scene::new("error")
        .run("new")
        .refused("probing the workspace device failed (blkid exit 4)");
}

#[test]
fn a_failed_format_check_or_mount_is_refused() {
    let scene = Scene::new("none");
    scene.set("mkfs", "fail");
    scene
        .run("new")
        .refused_after_trying("formatting the new workspace volume failed");

    let scene = Scene::new("ext4");
    scene.set("e2fsck", "4");
    scene
        .run("existing")
        .refused("checking the workspace filesystem failed (e2fsck exit 4)");

    // e2fsck's 1 means it corrected something: the volume still mounts.
    let scene = Scene::new("ext4");
    scene.set("e2fsck", "1");
    scene.run("existing").mounted();

    let scene = Scene::new("ext4");
    scene.set("mount", "32");
    let outcome = scene.run("existing");
    assert_eq!(outcome.status, 1);
    assert_eq!(
        outcome.stderr.lines().collect::<Vec<_>>(),
        ["codewire mount-workspace: mounting the workspace filesystem failed"]
    );
    assert!(!outcome.calls.contains("mount --bind"));
}

#[test]
fn a_failed_grow_keeps_the_previous_size() {
    let scene = Scene::new("ext4");
    scene.set("resize2fs", "1");
    let outcome = scene.run("existing");
    outcome.mounted();
    assert!(
        outcome
            .stderr
            .contains("did not grow; it keeps its previous size")
    );
}

#[test]
fn an_unknown_volume_state_and_a_linked_codewire_directory_are_refused() {
    Scene::new("ext4")
        .run("")
        .refused("the volume state must be new or existing, not ''");
    let scene = Scene::new("ext4");
    std::os::unix::fs::symlink("/etc", scene.root.join(".codewire")).unwrap();
    let outcome = scene.run("existing");
    assert_eq!(outcome.status, 1);
    assert_eq!(
        outcome.stderr.lines().collect::<Vec<_>>(),
        ["codewire mount-workspace: the workspace's .codewire is a symbolic link"]
    );
    assert!(!outcome.calls.contains("mount --bind"));
    assert!(!outcome.calls.contains("mkfs.ext4"));
}

/// infra's Kyverno policy `codewire-shared-sandbox-runtime-security` admits
/// the privileged `mount-workspace` only when `sha256(command[2])` is this
/// value (infra#2229, moved by infra#2234 and the writeback-defaults pin; `MOUNT_WORKSPACE_SCRIPT_SHA256` in
/// `scripts/test-codewire-sandbox-runtime-admission`). A changed script lands
/// after infra's pin moves with it, or Kyverno refuses every commodity Pod.
const INFRA_MOUNT_WORKSPACE_SCRIPT_SHA256: &str =
    "8e81452565e4077767089beaa91b7730ed26f49ab852a67fdc009af2ade24681";

#[test]
fn the_script_is_the_one_infra_admits() {
    use sha2::{Digest, Sha256};
    let hash = format!("{:x}", Sha256::digest(MOUNT_WORKSPACE_SCRIPT));
    println!("mount-workspace script sha256 {hash}");
    assert_eq!(
        hash, INFRA_MOUNT_WORKSPACE_SCRIPT_SHA256,
        "MOUNT_WORKSPACE_SCRIPT changed: move infra's Kyverno pin first"
    );
}

#[test]
fn the_guest_keeps_the_kernel_writeback_defaults() {
    // Owner, 2026-11-02: "Just put the disk in there. If the sandbox
    // crashes, the sandbox crashes." Only a planned stop flushes.
    assert!(!MOUNT_WORKSPACE_SCRIPT.contains("/proc/sys"));
    assert!(!MOUNT_WORKSPACE_SCRIPT.contains("commit="));
    assert!(MOUNT_WORKSPACE_SCRIPT.contains(r#"mount -t ext4 -o noatime "$dev" "$ws""#));
}

const DOCKER_DATA: [(&str, &str); 3] = [
    // The rendered path, which the script never follows: it prepares the
    // image on the mounted workspace.
    (
        "CODEWIRE_DOCKER_DATA_IMAGE",
        "/workspace/.codewire/docker-data.ext4",
    ),
    ("CODEWIRE_DOCKER_DATA_SIZE", "1G"),
    ("CODEWIRE_DOCKER_MOUNT_MODE", "loop"),
];

#[test]
fn beside_dind_the_docker_data_image_is_prepared_on_the_mounted_workspace() {
    let scene = Scene::new("ext4");
    let outcome = scene.run_with(&scene.device, "existing", &DOCKER_DATA);
    outcome.mounted();
    outcome.mounted_line("existing", 0);
    let image = scene.root.join(".codewire/docker-data.ext4");
    assert_eq!(std::fs::metadata(&image).unwrap().len(), 1 << 30);
    assert!(
        outcome.calls.contains(&format!(
            "mkfs.ext4 -q -F -E lazy_itable_init=1,lazy_journal_init=1 {}",
            image.display()
        )),
        "{}",
        outcome.calls
    );
}

#[test]
fn a_failed_docker_data_image_never_stops_the_workspace() {
    let scene = Scene::new("ext4");
    scene.set("mkfs", "fail");
    let outcome = scene.run_with(&scene.device, "existing", &DOCKER_DATA);
    outcome.mounted();
    outcome.mounted_line("existing", 0);
    assert!(!scene.root.join(".codewire/docker-data.ext4").exists());
    assert!(
        outcome
            .stderr
            .contains("was not created; Docker does not start"),
        "{}",
        outcome.stderr
    );
}

/// Whether any process's parent is `pid`. The parent is the second field
/// after the command name, which is in parentheses and may hold spaces.
#[cfg(target_os = "linux")] // The kubelet workspace-stop fixture reads Linux /proc.
fn has_child(pid: u32) -> bool {
    std::fs::read_dir("/proc").unwrap().flatten().any(|entry| {
        std::fs::read_to_string(entry.path().join("stat"))
            .ok()
            .and_then(|stat| {
                let after = &stat[stat.rfind(')')? + 1..];
                after.split_whitespace().nth(1)?.parse::<u32>().ok()
            })
            == Some(pid)
    })
}

/// Runs `workspace-flush` until it waits, then stops it as the kubelet does.
/// `sync` is the real one unless `fail_sync` puts a failing stand-in first.
#[cfg(target_os = "linux")]
fn stop_workspace_flush(fail_sync: bool) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    if fail_sync {
        let sync = bin.join("sync");
        std::fs::write(&sync, "#!/bin/sh\nexit 3\n").unwrap();
        let mut permissions = std::fs::metadata(&sync).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
        std::fs::set_permissions(&sync, permissions).unwrap();
    }
    let child = Command::new("sh")
        .args(["-c", WORKSPACE_FLUSH_SCRIPT])
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("CODEWIRE_WORKSPACE_FLUSH_ROOT", dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // The trap is set once the script waits on its sleep, a child of the
    // shell. Children are found by their parent in `/proc/*/stat`, which
    // every Linux has (`/proc/<pid>/task/<pid>/children` needs
    // CONFIG_PROC_CHILDREN).
    let mut waited = 0;
    while !has_child(child.id()) {
        assert!(waited < 500, "workspace-flush never started waiting");
        std::thread::sleep(std::time::Duration::from_millis(10));
        waited += 1;
    }
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    child.wait_with_output().unwrap()
}

#[test]
#[cfg(target_os = "linux")]
fn workspace_flush_syncs_the_workspace_when_stopped() {
    let output = stop_workspace_flush(false);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.starts_with("codewire workspace-flush: flushed the workspace (flush_ms="),
        "{stdout}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn a_failed_flush_is_logged_and_the_pod_still_stops() {
    let output = stop_workspace_flush(true);
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with(
            "codewire workspace-flush: flushing the workspace failed (status=3 flush_ms="
        ),
        "{stderr}"
    );
}

#[test]
fn the_flush_bound_and_the_grace_period_fit_together() {
    let bound: u32 = WORKSPACE_FLUSH_SCRIPT
        .split_once("timeout ")
        .and_then(|(_, rest)| rest.split_once(" sync -f"))
        .map(|(seconds, _)| seconds.parse().unwrap())
        .expect("workspace-flush bounds its sync");
    assert_eq!(bound, 35);
    // The flush comes after the workspace and DinD shutdowns, up to 15 s.
    assert!(bound + 15 <= super::workspace::BLOCK_WORKSPACE_GRACE_SECONDS);
}
