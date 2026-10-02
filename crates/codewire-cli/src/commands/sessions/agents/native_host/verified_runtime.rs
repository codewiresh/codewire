//! Verify retained guest `cw` bytes before every public control invocation.
//!
//! The checked-in workspace installs `/usr/bin/python3` (`python3-full`). Its
//! isolated, fixed launcher opens the retained runtime through no-follow
//! directory descriptors, hashes a bounded copy into a sealed memfd, and
//! executes that same sealed ELF. Neither request stdin nor launch values are
//! read into diagnostics. Recovery never provisions or replaces an artifact.
//!
//! The guest driver must use `/proc/self/exe` for subsequent self-spawns: a
//! sealed executable has no retained pathname that `current_exe()` can reopen.

const RUNTIME_ROOT: &str = "/run/codewire-runtime/cw";
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;

/// Arguments are separate argv entries; the script never interpolates them.
pub(super) fn command(executable: &str, arguments: &[String]) -> anyhow::Result<Vec<String>> {
    let digest = executable
        .strip_prefix(RUNTIME_ROOT)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .and_then(|suffix| suffix.strip_suffix("/cw"));
    if !digest.is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        anyhow::bail!("managed guest runtime must name its retained pinned executable");
    }
    let bytes = arguments
        .iter()
        .try_fold(0_usize, |total, argument| total.checked_add(argument.len()));
    if arguments.len() > MAX_ARGUMENTS
        || bytes.is_none_or(|bytes| bytes > MAX_ARGUMENT_BYTES)
        || arguments.iter().any(|argument| argument.contains('\0'))
    {
        anyhow::bail!("managed guest runtime arguments exceed the bounded argv contract");
    }
    let mut command = vec![
        "/usr/bin/python3".to_owned(),
        "-I".to_owned(),
        "-B".to_owned(),
        "-c".to_owned(),
        LAUNCHER.to_owned(),
        executable.to_owned(),
    ];
    command.extend_from_slice(arguments);
    Ok(command)
}

const LAUNCHER: &str = r#"import errno
import fcntl
import hashlib
import os
import stat
import sys

RUNTIME_ROOT = "/run/codewire-runtime/cw"
MAX_BYTES = 256 * 1024 * 1024
MAX_ARGUMENTS = 64
MAX_ARGUMENT_BYTES = 64 * 1024

class Rejected(Exception):
    pass

def require(condition, reason):
    if not condition:
        raise Rejected(reason)

SYSTEM_UID = 0
SYSTEM_GID = 0

def read_only(fd):
    return os.fstatvfs(fd).f_flag & os.ST_RDONLY

def private_directory(fd):
    metadata = os.fstat(fd)
    require(stat.S_ISDIR(metadata.st_mode)
            and metadata.st_uid == SYSTEM_UID and metadata.st_gid == SYSTEM_GID
            and stat.S_IMODE(metadata.st_mode) == 0o555, "directory")
    require(read_only(fd), "readonly")

def selected_file(fd):
    metadata = os.fstat(fd)
    require(stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == SYSTEM_UID and metadata.st_gid == SYSTEM_GID
            and stat.S_IMODE(metadata.st_mode) == 0o555
            and metadata.st_nlink == 1
            and 4 <= metadata.st_size <= MAX_BYTES, "file")
    require(read_only(fd), "readonly")
    return metadata

def executable_copy():
    flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    # Request executable memfds explicitly on kernels with memfd_noexec policy.
    # Older kernels reject MFD_EXEC with EINVAL; their original memfd semantics
    # permit execution. Permission failures never fall back.
    try:
        return os.memfd_create("codewire-verified-runtime", flags | 0x0010)
    except OSError as error:
        if error.errno != errno.EINVAL:
            raise
        return os.memfd_create("codewire-verified-runtime", flags)

def main():
    require(len(sys.argv) >= 2, "arguments")
    executable = sys.argv[1]
    arguments = sys.argv[2:]
    require(len(arguments) <= MAX_ARGUMENTS
            and sum(len(os.fsencode(value)) for value in arguments) <= MAX_ARGUMENT_BYTES,
            "arguments")
    prefix = RUNTIME_ROOT + "/"
    require(executable.startswith(prefix) and executable.endswith("/cw"), "path")
    digest = executable[len(prefix):-3]
    require(len(digest) == 64 and all(value in "0123456789abcdef" for value in digest), "path")
    require(executable == prefix + digest + "/cw", "path")
    require(os.execve in os.supports_fd, "capability")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", directory_flags)
    try:
        components = executable.split("/")[1:]
        for index, component in enumerate(components[:-1]):
            child = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
            # Global ancestors need not be read-only (for example /run), but
            # every component is opened without following a symlink.
            if index >= len(components) - 3:
                private_directory(directory)
        source = os.open("cw", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=directory)
    finally:
        os.close(directory)

    sealed = None
    try:
        before = selected_file(source)
        sealed = executable_copy()
        checksum = hashlib.sha256()
        copied = 0
        magic = b""
        while True:
            chunk = os.read(source, min(65536, MAX_BYTES - copied + 1))
            if not chunk:
                break
            copied += len(chunk)
            require(copied <= MAX_BYTES, "size")
            if not magic:
                magic = chunk[:4]
            checksum.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(sealed, view)
                require(written > 0, "copy")
                view = view[written:]
        after = selected_file(source)
        require(copied == before.st_size == after.st_size
                and before.st_mtime_ns == after.st_mtime_ns
                and before.st_ctime_ns == after.st_ctime_ns, "changed")
        require(checksum.hexdigest() == digest, "digest")
        require(magic == b"\x7fELF", "format")
        os.fchmod(sealed, 0o500)
        seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                 | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(sealed, fcntl.F_ADD_SEALS, seals)
        require(fcntl.fcntl(sealed, fcntl.F_GET_SEALS) & seals == seals, "seal")
        os.set_inheritable(sealed, False)
        os.close(source)
        source = None
        # Seal any pre-existing private descriptors too. Stdin is untouched;
        # the managed helper receives exactly the original request bytes.
        for name in os.listdir("/proc/self/fd"):
            descriptor = int(name)
            if descriptor > 2:
                try:
                    os.set_inheritable(descriptor, False)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        raise
        os.execve(sealed, [executable] + arguments, os.environ)
    finally:
        if source is not None:
            os.close(source)
        if sealed is not None:
            os.close(sealed)

try:
    main()
except Rejected as error:
    message = "managed guest runtime verification failed: " + str(error) + "\n"
    try:
        os.write(2, message.encode("ascii"))
    except OSError:
        pass
    os._exit(125)
except BaseException:
    try:
        os.write(2, b"managed guest runtime verification failed: launch\n")
    except OSError:
        pass
    os._exit(125)
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};
    use tempfile::TempDir;

    // No providers or credentials: this tiny static ELF prints its first argv
    // entry and copies stdin verbatim. The test only executes its own file.
    const EXECUTABLE_SOURCE: &str = r#"#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    const char marker[] = "verified-runtime\n";
    if (write(1, marker, sizeof(marker) - 1) != sizeof(marker) - 1) return 1;
    if (argc > 1) {
        size_t size = strlen(argv[1]);
        if (write(1, argv[1], size) != size || write(1, "\n", 1) != 1) return 1;
    }
    char bytes[4096];
    ssize_t size;
    while ((size = read(0, bytes, sizeof(bytes))) > 0) {
        ssize_t offset = 0;
        while (offset < size) {
            ssize_t wrote = write(1, bytes + offset, size - offset);
            if (wrote <= 0) return 1;
            offset += wrote;
        }
    }
    return size < 0;
}
"#;

    struct Fixture {
        temporary: TempDir,
        root: PathBuf,
        executable: PathBuf,
        digest: String,
        bytes: Vec<u8>,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let selected = temporary.path().join("selected");
            let mut compiler = Command::new("/usr/bin/cc")
                .args(["-O2", "-static", "-s", "-x", "c", "-o"])
                .arg(&selected)
                .arg("-")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("TMPDIR", temporary.path())
                .current_dir(temporary.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            compiler
                .stdin
                .take()
                .unwrap()
                .write_all(EXECUTABLE_SOURCE.as_bytes())
                .unwrap();
            let built = compiler.wait_with_output().unwrap();
            assert!(
                built.status.success(),
                "{}",
                String::from_utf8_lossy(&built.stderr)
            );
            let bytes = fs::read(&selected).unwrap();
            let digest = Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let root = temporary.path().canonicalize().unwrap().join("runtime");
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let directory = root.join(&digest);
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let executable = directory.join("cw");
            fs::write(&executable, &bytes).unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o555)).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o555)).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();
            Self {
                temporary,
                root,
                executable,
                digest,
                bytes,
            }
        }

        fn argv(&self, root: &Path) -> Vec<String> {
            let mut argv = command(&format!("{RUNTIME_ROOT}/{}/cw", self.digest), &[]).unwrap();
            // Only tests change the fixed launcher root; production has no
            // environment setting or argv option capable of selecting a root.
            let declaration = format!("RUNTIME_ROOT = {RUNTIME_ROOT:?}");
            assert_eq!(LAUNCHER.matches(&declaration).count(), 1);
            argv[4] = LAUNCHER.replace(
                &declaration,
                &format!(
                    "RUNTIME_ROOT = {}",
                    serde_json::to_string(root.to_str().unwrap()).unwrap()
                ),
            );
            // Only this unit fixture substitutes the two admission properties
            // unavailable without root/mount privileges. Actual VM acceptance
            // exercises production UID/GID 0 and real ST_RDONLY together.
            argv[4] = argv[4]
                .replace(
                    "SYSTEM_UID = 0",
                    &format!("SYSTEM_UID = {}", unsafe { libc::geteuid() }),
                )
                .replace(
                    "SYSTEM_GID = 0",
                    &format!("SYSTEM_GID = {}", unsafe { libc::getegid() }),
                )
                .replace(
                    "return os.fstatvfs(fd).f_flag & os.ST_RDONLY",
                    "return True",
                );
            argv[5] = root
                .join(&self.digest)
                .join("cw")
                .to_str()
                .unwrap()
                .to_owned();
            argv
        }

        fn run(&self, hook: &str, argument: Option<&str>, input: &[u8]) -> Output {
            let mut argv = self.argv(&self.root);
            if !hook.is_empty() {
                argv[4] = format!("{hook}\n{}", argv[4]);
            }
            if let Some(argument) = argument {
                argv.push(argument.to_owned());
            }
            run(&argv, input)
        }

        fn replace_bytes(&self, bytes: &[u8]) {
            fs::set_permissions(&self.executable, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&self.executable, bytes).unwrap();
            fs::set_permissions(&self.executable, fs::Permissions::from_mode(0o555)).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
            let _ = fs::set_permissions(
                self.executable.parent().unwrap(),
                fs::Permissions::from_mode(0o700),
            );
        }
    }

    #[test]
    fn system_owner_and_real_writable_mount_are_rejected() {
        let fixture = Fixture::new();
        let mut argv = fixture.argv(&fixture.root);
        argv[4] = argv[4].replace(
            "return True",
            "return os.fstatvfs(fd).f_flag & os.ST_RDONLY",
        );
        rejected(run(&argv, b""));
        argv = fixture.argv(&fixture.root);
        let declaration = format!("SYSTEM_UID = {}", unsafe { libc::geteuid() });
        argv[4] = argv[4].replace(&declaration, "SYSTEM_UID = 4294967294");
        rejected(run(&argv, b""));
    }

    fn run(argv: &[String], input: &[u8]) -> Output {
        let mut child = Command::new(&argv[0])
            .args(&argv[1..])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    fn rejected(output: Output) {
        assert_eq!(output.status.code(), Some(125));
        assert!(output.stdout.is_empty());
        assert!(
            output
                .stderr
                .starts_with(b"managed guest runtime verification failed: ")
        );
        assert!(output.stderr.len() <= 96);
    }

    #[test]
    fn command_refuses_unpinned_paths_and_unbounded_arguments() {
        let executable = format!("{RUNTIME_ROOT}/{}/cw", "a".repeat(64));
        assert!(command(&executable, &["_agent-control".into()]).is_ok());
        for path in [
            "/usr/local/bin/cw".to_owned(),
            format!("{RUNTIME_ROOT}/{}/cw", "A".repeat(64)),
            format!("{RUNTIME_ROOT}/{}/../cw", "a".repeat(64)),
            format!("{RUNTIME_ROOT}/{}/cw/", "a".repeat(64)),
        ] {
            assert!(command(&path, &[]).is_err());
        }
        assert!(command(&executable, &vec![String::new(); MAX_ARGUMENTS + 1]).is_err());
        assert!(command(&executable, &["a".repeat(MAX_ARGUMENT_BYTES + 1)]).is_err());
        assert!(command(&executable, &["secret\0value".into()]).is_err());
    }

    #[test]
    fn pinned_static_elf_preserves_stdin_and_separate_argv() {
        let fixture = Fixture::new();
        let input = b"{\"operation\":\"synthetic\"}\n\0unchanged\xff";
        let argument = "literal;$(never-a-shell)";
        let output = fixture.run("", Some(argument), input);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert_eq!(
            output.stdout,
            [
                b"verified-runtime\n".as_slice(),
                argument.as_bytes(),
                b"\n",
                input
            ]
            .concat()
        );
    }

    #[test]
    fn retained_wrong_hash_is_rejected_without_execution() {
        let fixture = Fixture::new();
        let mut changed = fixture.bytes.clone();
        changed.push(0);
        fixture.replace_bytes(&changed);
        let output = fixture.run("", None, b"");
        assert_eq!(
            output.stderr,
            b"managed guest runtime verification failed: digest\n"
        );
        rejected(output);
    }

    #[test]
    fn pathname_replacement_before_copy_is_rejected_without_execution() {
        let fixture = Fixture::new();
        fs::set_permissions(
            fixture.executable.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let replaced = fixture.temporary.path().join("replaced");
        fs::rename(&fixture.executable, replaced).unwrap();
        let mut changed = fixture.bytes.clone();
        changed.push(0);
        fs::write(&fixture.executable, changed).unwrap();
        fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(
            fixture.executable.parent().unwrap(),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        rejected(fixture.run("", None, b""));
    }

    #[test]
    fn oversized_or_empty_retained_files_are_rejected_before_copy() {
        let fixture = Fixture::new();
        for size in [0, 256 * 1024 * 1024 + 1] {
            fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o700)).unwrap();
            fs::OpenOptions::new()
                .write(true)
                .open(&fixture.executable)
                .unwrap()
                .set_len(size)
                .unwrap();
            fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o555)).unwrap();
            rejected(fixture.run("", None, b""));
        }
    }

    #[test]
    fn symlink_file_directory_and_ancestor_are_rejected() {
        let fixture = Fixture::new();
        let held = fixture.temporary.path().join("held");
        fs::set_permissions(
            fixture.executable.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::rename(&fixture.executable, &held).unwrap();
        symlink(&held, &fixture.executable).unwrap();
        fs::set_permissions(
            fixture.executable.parent().unwrap(),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        rejected(fixture.run("", None, b""));
        fs::set_permissions(
            fixture.executable.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::remove_file(&fixture.executable).unwrap();
        fs::rename(&held, &fixture.executable).unwrap();
        fs::set_permissions(
            fixture.executable.parent().unwrap(),
            fs::Permissions::from_mode(0o555),
        )
        .unwrap();

        let directory = fixture.executable.parent().unwrap();
        let held_directory = fixture.temporary.path().join("held-directory");
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(directory, &held_directory).unwrap();
        fs::set_permissions(&held_directory, fs::Permissions::from_mode(0o555)).unwrap();
        symlink(&held_directory, directory).unwrap();
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o555)).unwrap();
        rejected(fixture.run("", None, b""));
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_file(directory).unwrap();
        fs::set_permissions(&held_directory, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(&held_directory, directory).unwrap();
        fs::set_permissions(directory, fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&fixture.root, fs::Permissions::from_mode(0o555)).unwrap();

        let ancestor = fixture.temporary.path().join("ancestor");
        symlink(&fixture.root, &ancestor).unwrap();
        rejected(run(&fixture.argv(&ancestor), b""));
    }

    #[test]
    fn writable_system_modes_and_hardlink_alias_are_rejected() {
        let fixture = Fixture::new();
        for directory in [&fixture.root, fixture.executable.parent().unwrap()] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
            rejected(fixture.run("", None, b""));
            fs::set_permissions(directory, fs::Permissions::from_mode(0o555)).unwrap();
        }
        for mode in [0o700, 0o500, 0o400, 0o4555] {
            fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(mode)).unwrap();
            rejected(fixture.run("", None, b""));
        }
        fs::set_permissions(&fixture.executable, fs::Permissions::from_mode(0o555)).unwrap();
        let alias = fixture.temporary.path().join("alias");
        fs::hard_link(&fixture.executable, alias).unwrap();
        rejected(fixture.run("", None, b""));
    }

    // Hooks only wrap the final syscall in the isolated test Python process;
    // the production script has no hook, alternate root, or mutation option.
    const EXEC_HOOK: &str = r#"import errno, fcntl, os
real_execve = os.execve
def execute_verified(fd, argv, environment):
    assert isinstance(fd, int) and not os.get_inheritable(fd)
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals == seals
    try:
        os.write(fd, b"cannot change sealed bytes")
    except OSError as error:
        assert error.errno == errno.EPERM
    else:
        raise AssertionError("sealed executable was writable")
    mutate_retained(argv[0])
    return real_execve(fd, argv, environment)
os.execve = execute_verified
# supports_fd holds the original builtin, so preserve this capability check.
os.supports_fd.add(execute_verified)
"#;

    #[test]
    fn pathname_replacement_after_copy_executes_the_selected_sealed_bytes() {
        let fixture = Fixture::new();
        let hook = format!(
            "{EXEC_HOOK}\ndef mutate_retained(path):\n    os.chmod(os.path.dirname(path), 0o700)\n    os.rename(path, path + '.old')\n    with open(path, 'wb') as replacement:\n        replacement.write(b'not the selected executable')\n    os.chmod(path, 0o555)\n    os.chmod(os.path.dirname(path), 0o555)\n"
        );
        let output = fixture.run(&hook, None, b"after replacement\n");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"verified-runtime\nafter replacement\n");
        assert!(output.stderr.is_empty());
        rejected(fixture.run("", None, b""));
    }

    #[test]
    fn in_place_mutation_after_copy_executes_the_selected_sealed_bytes() {
        let fixture = Fixture::new();
        let hook = format!(
            "{EXEC_HOOK}\ndef mutate_retained(path):\n    os.chmod(path, 0o700)\n    with open(path, 'r+b') as source:\n        source.write(b'changed in place')\n    os.chmod(path, 0o555)\n    os.chmod(os.path.dirname(path), 0o555)\n"
        );
        let output = fixture.run(&hook, None, b"after mutation\n");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"verified-runtime\nafter mutation\n");
        assert!(output.stderr.is_empty());
        rejected(fixture.run("", None, b""));
    }
}
