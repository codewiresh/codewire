//! The Docker data init's preparation, run with the real e2fsprogs of the
//! support image's pinned Debian base against a scratch sparse image
//! (#3208). It needs Docker and that image, so it is ignored by default:
//!
//! ```sh
//! cargo test -p codewire-orchestration --lib docker_data_image_prepare_smoke -- --ignored --nocapture
//! ```
//!
//! The container runs as root without `--privileged` and mounts nothing: the
//! script works on a file in a Docker volume, which the test removes.

use std::process::Command;

use super::docker_data_image_prepare_script;

/// The support image's final stage (`deployments/docker/daemon.Dockerfile`,
/// `ARG DEBIAN_IMAGE`), whose e2fsprogs the data init runs.
const SUPPORT_BASE_IMAGE: &str =
    "debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587";

const DATA_IMAGE: &str = "/workspace/.codewire/docker-data.ext4";

/// The smoke runs the image the support image is built from.
#[test]
fn the_smoke_runs_the_support_image_base() {
    let dockerfile = std::fs::read_to_string(format!(
        "{}/../../deployments/docker/daemon.Dockerfile",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    assert!(
        dockerfile
            .lines()
            .any(|line| line == format!("ARG DEBIAN_IMAGE={SUPPORT_BASE_IMAGE}")),
        "the support image's Debian base moved; move SUPPORT_BASE_IMAGE with it"
    );
    assert!(
        dockerfile
            .lines()
            .any(|line| line == "FROM ${DEBIAN_IMAGE}")
    );
}

/// A Docker volume the test removes when it ends.
struct ScratchVolume(String);

impl Drop for ScratchVolume {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["volume", "rm", "-f", &self.0])
            .output();
    }
}

/// One run's result: the prepare script's exit status, its stderr, and
/// the inspection's stdout.
struct Run {
    status: i32,
    stderr: String,
    inspect: String,
}

/// Run `before`, then the prepare script with `size` and `mode`, then
/// `inspect`, in one container on `volume` at `/workspace`.
fn run(volume: &str, size: &str, mode: &str, before: &str, inspect: &str) -> Run {
    let script = format!(
        "{before}\nsh -c \"$PREPARE\" 2>/tmp/prepare.err; echo \"$?\" >/tmp/prepare.status\n{inspect}"
    );
    let output = Command::new("docker")
        .args(["run", "--rm", "--network", "none", "--entrypoint", "sh"])
        .args(["-v", &format!("{volume}:/workspace")])
        .args(["-e", &format!("PREPARE={}", docker_data_image_prepare_script())])
        .args(["-e", &format!("CODEWIRE_DOCKER_DATA_IMAGE={DATA_IMAGE}")])
        .args(["-e", &format!("CODEWIRE_DOCKER_DATA_SIZE={size}")])
        .args(["-e", &format!("CODEWIRE_DOCKER_MOUNT_MODE={mode}")])
        .arg(SUPPORT_BASE_IMAGE)
        .args([
            "-c",
            &format!(
                "{script}\necho '--status'; cat /tmp/prepare.status; echo '--stderr'; cat /tmp/prepare.err"
            ),
        ])
        .output()
        .expect("docker runs");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        output.status.success(),
        "inspection failed: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let (inspect, rest) = stdout.split_once("--status\n").unwrap();
    let (status, stderr) = rest.split_once("--stderr\n").unwrap();
    Run {
        status: status.trim().parse().unwrap(),
        stderr: stderr.to_owned(),
        inspect: inspect.to_owned(),
    }
}

/// `key=value` lines of an inspection.
fn field<'a>(inspect: &'a str, key: &str) -> &'a str {
    inspect
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("{key} missing from {inspect}"))
}

/// The image's file size, its filesystem's size and UUID, whether a forced
/// read-only check is clean, the marker a test wrote into it, and its
/// directory's owner and mode.
const INSPECT: &str = r#"image=/workspace/.codewire/docker-data.ext4
if [ -e "$image" ]; then
  echo "exists=yes"
  echo "file_bytes=$(stat -c %s "$image")"
  echo "fs_bytes=$(dumpe2fs -h "$image" 2>/dev/null | awk -F: '$1 == "Block count" { count = $2 } $1 == "Block size" { size = $2 } END { printf "%.0f", count * size }')"
  echo "uuid=$(dumpe2fs -h "$image" 2>/dev/null | awk -F': *' '$1 == "Filesystem UUID" { print $2 }')"
  if e2fsck -fn "$image" >/dev/null 2>&1; then echo "clean=yes"; else echo "clean=no"; fi
  echo "marker=$(debugfs -R 'cat /marker' "$image" 2>/dev/null)"
else
  echo "exists=no"
fi
echo "dir=$(stat -c '%u:%g %a' /workspace/.codewire)""#;

const GIB: u64 = 1 << 30;

#[test]
#[ignore = "requires Docker and the support image's pinned Debian base; run with -- --ignored"]
fn docker_data_image_prepare_smoke() {
    let name = format!("codewire-docker-data-smoke-{}", std::process::id());
    let created = Command::new("docker")
        .args(["volume", "create", &name])
        .output()
        .expect("docker runs");
    assert!(created.status.success(), "docker volume create failed");
    let volume = ScratchVolume(name);
    let volume = volume.0.as_str();

    // Fresh: a sparse 1 GiB image, formatted and clean, in a directory the
    // workspace user owns and only it can write.
    let fresh = run(volume, "1G", "loop", "", INSPECT);
    assert_eq!(fresh.status, 0, "{}", fresh.stderr);
    assert_eq!(fresh.stderr, "");
    assert_eq!(field(&fresh.inspect, "file_bytes"), (GIB).to_string());
    assert_eq!(field(&fresh.inspect, "fs_bytes"), (GIB).to_string());
    assert_eq!(field(&fresh.inspect, "clean"), "yes");
    assert_eq!(field(&fresh.inspect, "dir"), "1000:1000 755");
    let uuid = field(&fresh.inspect, "uuid").to_owned();
    assert!(!uuid.is_empty());

    // Data written into the filesystem, then a rerun: a no-op that keeps it.
    let write_marker = r#"printf kept >/tmp/marker && debugfs -w -R 'write /tmp/marker marker' /workspace/.codewire/docker-data.ext4 >/dev/null 2>&1"#;
    let rerun = run(volume, "1G", "loop", write_marker, INSPECT);
    assert_eq!(rerun.status, 0, "{}", rerun.stderr);
    assert_eq!(rerun.stderr, "");
    assert_eq!(field(&rerun.inspect, "file_bytes"), (GIB).to_string());
    assert_eq!(field(&rerun.inspect, "uuid"), uuid);
    assert_eq!(field(&rerun.inspect, "marker"), "kept");

    // Grow 1 GiB to 2 GiB offline: the same filesystem, clean, with its data.
    let grown = run(volume, "2G", "loop", "", INSPECT);
    assert_eq!(grown.status, 0, "{}", grown.stderr);
    assert_eq!(field(&grown.inspect, "file_bytes"), (2 * GIB).to_string());
    assert_eq!(field(&grown.inspect, "fs_bytes"), (2 * GIB).to_string());
    assert_eq!(field(&grown.inspect, "clean"), "yes");
    assert_eq!(field(&grown.inspect, "uuid"), uuid);
    assert_eq!(field(&grown.inspect, "marker"), "kept");

    // A malformed size is ignored, and a smaller one never shrinks it.
    for size in ["2X", "abc", "G", "1G"] {
        let kept = run(volume, size, "loop", "", INSPECT);
        assert_eq!(kept.status, 0, "{size}: {}", kept.stderr);
        assert_eq!(kept.stderr, "", "{size}");
        assert_eq!(
            field(&kept.inspect, "file_bytes"),
            (2 * GIB).to_string(),
            "{size}"
        );
        assert_eq!(
            field(&kept.inspect, "fs_bytes"),
            (2 * GIB).to_string(),
            "{size}"
        );
        assert_eq!(field(&kept.inspect, "marker"), "kept", "{size}");
    }

    // An interrupted grow, whose file grew but whose filesystem did not,
    // finishes at the next start.
    let interrupted = run(
        volume,
        "2G",
        "loop",
        "truncate -s 3G /workspace/.codewire/docker-data.ext4",
        INSPECT,
    );
    assert_eq!(interrupted.status, 0, "{}", interrupted.stderr);
    assert_eq!(
        field(&interrupted.inspect, "file_bytes"),
        (3 * GIB).to_string()
    );
    assert_eq!(
        field(&interrupted.inspect, "fs_bytes"),
        (3 * GIB).to_string()
    );
    assert_eq!(field(&interrupted.inspect, "clean"), "yes");
    assert_eq!(field(&interrupted.inspect, "marker"), "kept");

    // A plain directory needs no image: nothing is touched.
    let none = run(
        volume,
        "4G",
        "none",
        "",
        "echo \"file_bytes=$(stat -c %s /workspace/.codewire/docker-data.ext4)\"",
    );
    assert_eq!(none.status, 0, "{}", none.stderr);
    assert_eq!(field(&none.inspect, "file_bytes"), (3 * GIB).to_string());

    // An image that is not a filesystem fails its grow, which is reported
    // and never fails the init container; DinD then reports the mount.
    let corrupt = run(
        volume,
        "4G",
        "loop",
        "head -c 1048576 /dev/urandom >/workspace/.codewire/docker-data.ext4",
        INSPECT,
    );
    assert_eq!(corrupt.status, 0, "{}", corrupt.stderr);
    assert!(
        corrupt
            .stderr
            .contains("the Docker data filesystem did not grow to 4G"),
        "{}",
        corrupt.stderr
    );
    assert_eq!(field(&corrupt.inspect, "file_bytes"), (4 * GIB).to_string());

    // A fresh image that cannot be created is removed, so the next start
    // tries again, and DinD reports it missing; the init container succeeds.
    let failed = run(
        volume,
        "4X",
        "loop",
        "rm -f /workspace/.codewire/docker-data.ext4",
        INSPECT,
    );
    assert_eq!(failed.status, 0, "{}", failed.stderr);
    assert!(
        failed
            .stderr
            .contains("was not created; Docker does not start"),
        "{}",
        failed.stderr
    );
    assert_eq!(field(&failed.inspect, "exists"), "no");
}
