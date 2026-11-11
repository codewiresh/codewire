//! Commodity DinD startup: an owned cgroup domain and a persistent modern store.

pub(super) const BOOTSTRAP_FAILURE: &str = r#"docker_bootstrap_fail() {
  printf 'Codewire Docker startup failed: %s\n' "$1" >&2
  exit 1
}"#;

/// Run before any daemon or utility can leave a process in the namespace root.
/// The one synchronous mkdir has exited before the shell moves only itself.
pub(super) const CGROUP_INIT: &str = r#"cgroup_root=/sys/fs/cgroup
if [ -f "$cgroup_root/cgroup.controllers" ]; then
  IFS= read -r cgroup_type < "$cgroup_root/cgroup.type" || docker_bootstrap_fail 'cannot read the Docker cgroup type'
  [ "$cgroup_type" = domain ] || docker_bootstrap_fail 'Docker needs a fresh domain cgroup; existing cgroups were left unchanged'
  mkdir -p "$cgroup_root/init" || docker_bootstrap_fail 'cannot create the Docker process cgroup'
  printf '%s\n' "$$" > "$cgroup_root/init/cgroup.procs" || docker_bootstrap_fail 'cannot delegate the Docker startup process'
  if IFS= read -r _unexpected_pid < "$cgroup_root/cgroup.procs"; then
    docker_bootstrap_fail 'the Docker cgroup root contains another process; it was not moved'
  fi
  IFS= read -r controllers < "$cgroup_root/cgroup.controllers" || docker_bootstrap_fail 'cannot read available Docker cgroup controllers'
  for required in cpu memory pids; do
    case " $controllers " in
      *" $required "*) ;;
      *) docker_bootstrap_fail "the Docker cgroup lacks the $required controller" ;;
    esac
  done
  enable_controllers=
  for controller in $controllers; do
    enable_controllers="$enable_controllers+$controller "
  done
  printf '%s\n' "$enable_controllers" > "$cgroup_root/cgroup.subtree_control" || docker_bootstrap_fail 'cannot enable Docker cgroup delegation'
  IFS= read -r delegated < "$cgroup_root/cgroup.subtree_control" || docker_bootstrap_fail 'cannot verify Docker cgroup delegation'
  for required in cpu memory pids; do
    case " $delegated " in
      *" $required "*) ;;
      *) docker_bootstrap_fail "Docker did not receive the $required controller" ;;
    esac
  done
fi"#;

/// Fail closed before resetting data: both the mount and its loop backing file
/// must name the product's Docker image, never another workspace filesystem.
pub(super) const VERIFY_STORE_MOUNT: &str = r#"case "$data_image" in
/workspace/.codewire/docker-data.ext4 | /mnt/home/.codewire/docker-data.ext4) ;;
*) docker_bootstrap_fail 'the commodity Docker data paths are invalid' ;;
esac
[ "$data_root" = /var/lib/docker ] && [ "$mount_mode" = loop ] || docker_bootstrap_fail 'the commodity Docker data paths are invalid'
[ ! -L "$data_root" ] && [ ! -L "$data_image" ] && [ ! -L "${data_image%/*}" ] || docker_bootstrap_fail 'the commodity Docker data path is a symlink'
data_device="$(awk '$2 == "/var/lib/docker" && $3 == "ext4" { print $1; exit }' /proc/mounts)"
case "$data_device" in
  /dev/loop*) loop_number="${data_device#/dev/loop}" ;;
  *) docker_bootstrap_fail 'the commodity Docker data filesystem is not a loop-mounted ext4 image' ;;
esac
case "$loop_number" in ''|*[!0-9]*) docker_bootstrap_fail 'the Docker loop device is invalid' ;; esac
IFS= read -r loop_backing < "/sys/block/loop$loop_number/loop/backing_file" || docker_bootstrap_fail 'cannot verify the Docker loop backing file'
[ "$loop_backing" = "$data_image" ] || docker_bootstrap_fail 'the Docker loop device belongs to another image'"#;

/// One-time commodity cutover. Only this mounted Docker filesystem is reset;
/// the workspace containing it is never traversed. The marker follows snapshots.
pub(super) const PREPARE_STORE: &str = r#"docker_store_marker="$data_root/.codewire-containerd-store-v1"
if [ -L "$docker_store_marker" ] || { [ -e "$docker_store_marker" ] && [ ! -f "$docker_store_marker" ]; }; then
  docker_bootstrap_fail 'the Docker format marker is not a regular file'
fi
if [ -f "$docker_store_marker" ]; then
  printf 'containerd-overlayfs-v1\n' | cmp -s - "$docker_store_marker" || docker_bootstrap_fail 'the Docker data format is unsupported'
else
  # Owner-authorized clean cutover: old Docker images, containers and volumes
  # are disposable. rm does not follow symlinks outside the Docker filesystem.
  for entry in "$data_root"/* "$data_root"/.[!.]* "$data_root"/..?*; do
    if [ ! -e "$entry" ] && [ ! -L "$entry" ]; then continue; fi
    if [ "$entry" = "$data_root/lost+found" ] && [ -d "$entry" ] && [ ! -L "$entry" ]; then continue; fi
    rm -rf -- "$entry" || docker_bootstrap_fail 'cannot reset the old Docker data'
  done
  marker_temporary="$data_root/.codewire-containerd-store-v1.tmp.$$"
  (umask 077; set -C; printf 'containerd-overlayfs-v1\n' > "$marker_temporary") || docker_bootstrap_fail 'cannot prepare the Docker format marker'
  mv -f "$marker_temporary" "$docker_store_marker" || docker_bootstrap_fail 'cannot commit the Docker format marker'
fi"#;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::process::{Command, Output};

    const MARKER: &str = ".codewire-containerd-store-v1";

    fn prepare(root: &std::path::Path) -> Output {
        Command::new("sh")
            .args([
                "-ec",
                &format!("{BOOTSTRAP_FAILURE}\ndata_root=\"$TEST_DOCKER_ROOT\"\n{PREPARE_STORE}"),
            ])
            .env("TEST_DOCKER_ROOT", root)
            .output()
            .unwrap()
    }

    #[test]
    fn cutover_discards_only_docker_state_and_runs_once() {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path().join("docker-root");
        fs::create_dir_all(root.join("lost+found")).unwrap();
        fs::create_dir_all(root.join("volumes/old-volume")).unwrap();
        fs::write(workspace.path().join("source"), b"keep source").unwrap();
        symlink(workspace.path().join("source"), root.join("source-link")).unwrap();
        let result = prepare(&root);
        assert!(result.status.success(), "{result:?}");
        assert_eq!(
            fs::read(root.join(MARKER)).unwrap(),
            b"containerd-overlayfs-v1\n"
        );
        assert!(root.join("lost+found").is_dir());
        assert!(!root.join("volumes").exists());
        assert!(!root.join("source-link").exists());
        assert_eq!(
            fs::read(workspace.path().join("source")).unwrap(),
            b"keep source"
        );
        fs::create_dir_all(root.join("containerd/daemon")).unwrap();
        fs::write(root.join("containerd/daemon/retained"), b"modern state").unwrap();
        assert!(prepare(&root).status.success());
        assert_eq!(
            fs::read(root.join("containerd/daemon/retained")).unwrap(),
            b"modern state"
        );
    }

    #[test]
    fn malformed_marker_never_discards_existing_state() {
        for value in [
            "",
            "containerd-overlayfs-v1",
            "containerd-overlayfs-v1\n\n",
            "unsupported\n",
        ] {
            let root = tempfile::tempdir().unwrap();
            fs::write(root.path().join(MARKER), value).unwrap();
            fs::write(root.path().join("retained"), b"keep").unwrap();
            assert!(!prepare(root.path()).status.success());
            assert_eq!(fs::read(root.path().join("retained")).unwrap(), b"keep");
            assert_eq!(
                fs::read(root.path().join(MARKER)).unwrap(),
                value.as_bytes()
            );
        }
    }

    #[test]
    fn marker_symlink_is_not_followed() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("retained");
        fs::write(&target, b"keep").unwrap();
        symlink(&target, root.path().join(MARKER)).unwrap();
        assert!(!prepare(root.path()).status.success());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn cleanup_requires_the_expected_loop_backing_image() {
        for (device, backing, accepted) in [
            ("/dev/loop0", "expected", true),
            ("/dev/cwws", "expected", false),
            ("/dev/loop0", "another-image", false),
            ("/dev/loop../unexpected", "expected", false),
        ] {
            let workspace = tempfile::tempdir().unwrap();
            let root = workspace.path().join("docker-root");
            let image = workspace.path().join("docker-data.ext4");
            let mounts = workspace.path().join("mounts");
            let sys = workspace.path().join("sys");
            fs::create_dir(&root).unwrap();
            fs::write(root.join("old-data"), b"old Docker state").unwrap();
            fs::write(&image, b"fixture image").unwrap();
            fs::write(
                &mounts,
                format!("{device} {} ext4 rw 0 0\n", root.display()),
            )
            .unwrap();
            fs::create_dir_all(sys.join("loop0/loop")).unwrap();
            fs::write(
                sys.join("loop0/loop/backing_file"),
                format!(
                    "{}\n",
                    if backing == "expected" {
                        image.display().to_string()
                    } else {
                        backing.into()
                    }
                ),
            )
            .unwrap();
            let verification = VERIFY_STORE_MOUNT
                .replace("/var/lib/docker", root.to_str().unwrap())
                .replace(
                    "/workspace/.codewire/docker-data.ext4",
                    image.to_str().unwrap(),
                )
                .replace("/proc/mounts", mounts.to_str().unwrap())
                .replace("/sys/block", sys.to_str().unwrap());
            let script = format!(
                "{BOOTSTRAP_FAILURE}\ndata_root=\"$TEST_DOCKER_ROOT\"\ndata_image=\"$TEST_DOCKER_IMAGE\"\nmount_mode=loop\n{verification}\n{PREPARE_STORE}"
            );
            let result = Command::new("sh")
                .args(["-ec", &script])
                .env("TEST_DOCKER_ROOT", &root)
                .env("TEST_DOCKER_IMAGE", &image)
                .output()
                .unwrap();
            assert_eq!(
                result.status.success(),
                accepted,
                "{device} {backing}: {result:?}"
            );
            assert_eq!(root.join("old-data").exists(), !accepted);
            assert_eq!(fs::read(&image).unwrap(), b"fixture image");
        }
    }

    fn initialize(root: &std::path::Path) -> Output {
        let script = CGROUP_INIT.replace(
            "cgroup_root=/sys/fs/cgroup",
            "cgroup_root=\"$TEST_CGROUP_ROOT\"",
        );
        Command::new("sh")
            .args(["-ec", &format!("{BOOTSTRAP_FAILURE}\n{script}")])
            .env("TEST_CGROUP_ROOT", root)
            .output()
            .unwrap()
    }

    #[test]
    fn cgroup_v1_is_left_unchanged() {
        let root = tempfile::tempdir().unwrap();
        assert!(initialize(root.path()).status.success());
        assert!(!root.path().join("init").exists());
    }

    #[test]
    fn a_contaminated_threaded_root_is_refused_without_process_moves() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        fs::write(root.path().join("cgroup.type"), "domain threaded\n").unwrap();
        let result = initialize(root.path());
        assert!(!result.status.success());
        assert!(!root.path().join("init").exists());
    }

    #[test]
    fn a_foreign_root_process_is_never_evacuated() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("cgroup.controllers"), "cpu memory pids\n").unwrap();
        fs::write(root.path().join("cgroup.type"), "domain\n").unwrap();
        fs::write(root.path().join("cgroup.procs"), "424242\n").unwrap();
        fs::write(root.path().join("cgroup.subtree_control"), "\n").unwrap();
        let result = initialize(root.path());
        assert!(!result.status.success());
        assert_eq!(
            fs::read_to_string(root.path().join("cgroup.procs")).unwrap(),
            "424242\n"
        );
        assert_eq!(
            fs::read_to_string(root.path().join("cgroup.subtree_control")).unwrap(),
            "\n"
        );
        let moved = fs::read_to_string(root.path().join("init/cgroup.procs")).unwrap();
        assert_ne!(moved.trim(), "424242");
        assert!(moved.trim().parse::<u32>().is_ok());
    }
}
