//! A parent's pre-exec isolation of a child it starts: the descriptors the
//! child inherits and its open-file limit and, on Linux, its parent-death
//! signal and privilege lock. Everything here that runs in the child runs
//! between fork and exec.

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt as _;
#[cfg(target_os = "linux")]
use std::process::Stdio;

#[cfg(target_os = "linux")]
use crate::linux::lock_process_privileges;

/// Inherited sources are duplicated at or above this descriptor, above every
/// fixed target a child uses, so placing one never overwrites another.
pub const INHERITED_SOURCE_FLOOR: RawFd = 64;

/// The soft open-file limit of the network worker and egress broker (#2638).
/// The worker holds up to 256 guest connections, 64 inbound streams and every
/// broker session; macOS starts processes at 256. Never above the hard limit.
pub const NETWORK_ROLE_OPEN_FILE_LIMIT: libc::rlim_t = 1024;

/// Raise the soft open-file limit to [`NETWORK_ROLE_OPEN_FILE_LIMIT`], or to
/// the hard limit if that is lower. Runs in the child before exec.
pub fn raise_open_file_limit() -> io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live, mutably borrowed `rlimit`, and getrlimit
    // writes exactly one.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let wanted = NETWORK_ROLE_OPEN_FILE_LIMIT.min(limit.rlim_max);
    if limit.rlim_cur < wanted {
        limit.rlim_cur = wanted;
        // SAFETY: setrlimit only reads `limit`, a live `rlimit` that getrlimit
        // filled in above.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Duplicate `descriptor` at or above [`INHERITED_SOURCE_FLOOR`], close-on-exec,
/// as a source for [`inherit_descriptors`].
pub fn duplicate_inherited_descriptor(descriptor: i32) -> io::Result<OwnedFd> {
    // SAFETY: F_DUPFD_CLOEXEC reads no memory; the result is checked below.
    let duplicated =
        unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, INHERITED_SOURCE_FLOOR) };
    if duplicated == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicated` is a new descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

/// Runs in the child before exec: the child dies with `expected_parent`, takes
/// only `descriptors` across exec and locks its privileges.
///
/// The parent-death signal follows the thread that forked, not its process:
/// the child is killed when that thread exits. Start a child from a thread
/// that lives as long as the child must, never from one a pool may retire.
#[cfg(target_os = "linux")]
pub fn prepare_isolated_child(
    expected_parent: libc::pid_t,
    descriptors: &[(RawFd, RawFd)],
) -> io::Result<()> {
    // SAFETY: PR_SET_PDEATHSIG takes integer arguments and no pointer, so it
    // cannot touch this process's memory.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == -1
        // SAFETY: getppid takes no argument and reads no memory of ours.
        || unsafe { libc::getppid() } != expected_parent
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: close_range takes integer arguments and no pointer. With
    // CLOSE_RANGE_CLOEXEC it closes nothing: it marks every descriptor from 3
    // up close-on-exec, and no owner of one loses it.
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    inherit_descriptors(descriptors)?;
    lock_process_privileges()
}

/// Place each (source, target) descriptor at its fixed number for the child.
/// Sources are duplicated at [`INHERITED_SOURCE_FLOOR`] or above and every
/// target is below it, so no target overwrites a source.
pub fn inherit_descriptors(descriptors: &[(RawFd, RawFd)]) -> io::Result<()> {
    let duplicate_target = descriptors.iter().enumerate().any(|(index, &(_, target))| {
        descriptors[index + 1..]
            .iter()
            .any(|&(_, other)| other == target)
    });
    if duplicate_target
        || descriptors.iter().any(|&(source, target)| {
            source < INHERITED_SOURCE_FLOOR || target >= INHERITED_SOURCE_FLOOR
        })
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    for &(source, target) in descriptors {
        // SAFETY: dup2 takes two descriptor numbers and no pointer, so it
        // cannot touch this process's memory. It replaces whatever is open at
        // `target`: this runs in a child between fork and exec, where the
        // numbers below the floor are the child's to assign.
        if source != target && unsafe { libc::dup2(source, target) } == -1 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: F_SETFD takes integer arguments and no pointer. It only
        // clears close-on-exec on `target`, which the child is to inherit.
        if unsafe { libc::fcntl(target, libc::F_SETFD, 0) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The most arguments [`OwnImage::command`] gives a child, `argv[0]` included.
#[cfg(target_os = "linux")]
pub const MAX_IMAGE_ARGUMENTS: usize = 8;

/// The calling process's own executable, held open so that every child it
/// starts is this image: a child is started from the open descriptor, never
/// by looking up a path.
///
/// Holding the image open exempts the start from nothing else: a mount that
/// forbids execution, or a Landlock or seccomp rule on the parent that
/// forbids it, still refuses the child.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct OwnImage {
    image: OwnedFd,
}

#[cfg(target_os = "linux")]
impl OwnImage {
    pub fn open() -> io::Result<Self> {
        Self::at("/proc/self/exe")
    }

    /// Another executable as the image, to test what a held image guarantees.
    #[cfg(test)]
    fn open_path(path: &std::path::Path) -> io::Result<Self> {
        Self::at(path)
    }

    fn at(path: impl rustix::path::Arg) -> io::Result<Self> {
        let image = rustix::fs::open(
            path,
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        // Above the floor, so placing a child's descriptors never lands on it.
        Ok(Self {
            image: duplicate_inherited_descriptor(image.as_raw_fd())?,
        })
    }

    /// The image's device and inode, to compare with a child's executable.
    pub fn identity(&self) -> io::Result<(u64, u64)> {
        let stat = rustix::fs::fstat(&self.image)?;
        Ok((stat.st_dev, stat.st_ino))
    }

    /// A command whose child is this image, isolated as
    /// [`prepare_isolated_child`] isolates one: it runs with `arguments` (the
    /// first is `argv[0]`), an empty environment, null standard streams and,
    /// of this process's descriptors, only `descriptors` at their targets.
    /// The thread that starts it must outlive the child, as
    /// [`prepare_isolated_child`] says.
    pub fn command(
        &self,
        arguments: &[&str],
        descriptors: Vec<(RawFd, RawFd)>,
    ) -> io::Result<ImageCommand> {
        let invalid = || io::Error::from_raw_os_error(libc::EINVAL);
        if arguments.is_empty() || arguments.len() > MAX_IMAGE_ARGUMENTS {
            return Err(invalid());
        }
        let arguments = arguments
            .iter()
            .map(|argument| CString::new(*argument).map_err(|_| invalid()))
            .collect::<io::Result<Vec<_>>>()?;
        // The command owns its copy, so it stays valid whatever outlives what.
        let image = duplicate_inherited_descriptor(self.image.as_raw_fd())?;
        let expected_parent = libc::pid_t::try_from(std::process::id()).map_err(|_| invalid())?;

        // This path is never executed: the child becomes the image in the
        // closure below, or the spawn fails.
        let mut command = std::process::Command::new("/proc/self/exe");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let become_image = move || {
            raise_open_file_limit()?;
            prepare_isolated_child(expected_parent, &descriptors)?;
            let mut argv = [std::ptr::null::<libc::c_char>(); MAX_IMAGE_ARGUMENTS + 1];
            for (slot, argument) in argv.iter_mut().zip(&arguments) {
                *slot = argument.as_ptr();
            }
            let environment = [std::ptr::null::<libc::c_char>()];
            // SAFETY: `argv` and `environment` are null-terminated arrays of
            // pointers to NUL-terminated strings that live until the call
            // returns, and `image` is an open descriptor. rustix has no
            // execveat outside its unstable runtime module. On success the
            // call does not return.
            unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    image.as_raw_fd(),
                    c"".as_ptr(),
                    argv.as_ptr(),
                    environment.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
            }
            Err(io::Error::last_os_error())
        };
        // SAFETY: the closure runs in the child between fork and exec. It
        // only makes system calls on values built before the fork: it
        // allocates nothing and takes no lock another thread could hold.
        unsafe {
            command.pre_exec(become_image);
        }
        Ok(ImageCommand(command))
    }
}

/// A child of an [`OwnImage`], built and not yet started. It can only be
/// started as built: nothing can add an argument, which the child would never
/// see, or change a stream, which would change its isolation.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct ImageCommand(std::process::Command);

#[cfg(target_os = "linux")]
impl ImageCommand {
    /// Forks the child. `Ok` does not mean the child became the image. The
    /// standard library reports a failure before exec through a pipe at
    /// whatever descriptor was free, and placing the child's descriptors can
    /// take that number, after which a failure is no longer reported here:
    /// the child just exits. A caller learns that a child started from the
    /// child itself, by the first thing it says.
    pub fn spawn(mut self) -> io::Result<std::process::Child> {
        self.0.spawn()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2638: a network role starts with at least 1024 open files, or its
    /// hard limit, even from a process that has the macOS default of 256.
    #[test]
    fn network_roles_start_with_their_open_file_limit() {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "ulimit -Sn; ulimit -Hn"]);
        // SAFETY: only getrlimit and setrlimit run between fork and exec.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut command, || {
                let mut limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
                limit.rlim_cur = limit.rlim_cur.min(256);
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
                raise_open_file_limit()
            });
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        let mut lines = text.lines();
        let soft: u64 = lines.next().unwrap().parse().unwrap();
        let hard = lines.next().unwrap();
        let expected = match hard.parse::<u64>() {
            Ok(hard) => hard.min(NETWORK_ROLE_OPEN_FILE_LIMIT),
            Err(_) => NETWORK_ROLE_OPEN_FILE_LIMIT,
        };
        assert_eq!(soft, expected, "{text}");
    }

    /// Where the image test's child finds the parent's socket.
    #[cfg(target_os = "linux")]
    const IMAGE_CHILD_FD: RawFd = 5;

    /// The child's half of the test below, run only as that test's child:
    /// `cargo test -- --ignored` finds no socket at the descriptor and stops.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run as the child of a_child_of_the_image_is_this_image_and_nothing_more"]
    fn image_child() {
        use std::io::{Read as _, Write as _};
        use std::os::unix::net::UnixStream;

        // SAFETY: fstat only writes the `stat` it is given.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `stat` is a live, mutably borrowed `stat`.
        let is_socket = unsafe { libc::fstat(IMAGE_CHILD_FD, &mut stat) } == 0
            && stat.st_mode & libc::S_IFMT == libc::S_IFSOCK;
        if !is_socket {
            return;
        }
        // SAFETY: the parent placed this socket here for this process alone.
        let mut parent = UnixStream::from(unsafe { OwnedFd::from_raw_fd(IMAGE_CHILD_FD) });

        let environment = std::env::vars_os().count();
        let mut descriptors: Vec<RawFd> = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .parse()
                    .unwrap()
            })
            .collect();
        // The listing held a descriptor of its own, closed by now.
        // SAFETY: F_GETFD takes integer arguments and no pointer.
        descriptors.retain(|descriptor| unsafe { libc::fcntl(*descriptor, libc::F_GETFD) } != -1);
        descriptors.sort_unstable();
        let report = format!("{environment} {descriptors:?}\n");
        parent.write_all(report.as_bytes()).unwrap();
        // Stay alive until the parent has looked at this process.
        let mut done = [0_u8; 1];
        let _ = parent.read(&mut done);
    }

    /// Starts `image`'s child half of these tests with one socket and one
    /// descriptor it must not inherit, and returns what the child reported
    /// and its executable's device and inode.
    #[cfg(target_os = "linux")]
    fn run_image_child(image: &OwnImage) -> (String, (u64, u64)) {
        use std::io::{BufRead as _, BufReader, Write as _};
        use std::os::linux::fs::MetadataExt as _;
        use std::os::unix::net::UnixStream;

        let (mine, theirs) = UnixStream::pair().unwrap();
        let inherited = duplicate_inherited_descriptor(theirs.as_raw_fd()).unwrap();
        // Something a child must not inherit: open, not close-on-exec, and
        // above every target so that placing the child's socket cannot
        // happen to replace it.
        let (leak, _other) = UnixStream::pair().unwrap();
        let leak = duplicate_inherited_descriptor(leak.as_raw_fd()).unwrap();
        // SAFETY: F_SETFD takes integer arguments and no pointer.
        let cleared = unsafe { libc::fcntl(leak.as_raw_fd(), libc::F_SETFD, 0) };
        assert_eq!(cleared, 0);

        let mut child = image
            .command(
                &[
                    "image-child",
                    "--ignored",
                    "--exact",
                    "spawn::tests::image_child",
                ],
                vec![(inherited.as_raw_fd(), IMAGE_CHILD_FD)],
            )
            .unwrap()
            .spawn()
            .unwrap();
        drop(inherited);
        drop(theirs);

        mine.set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        let mut report = String::new();
        BufReader::new(&mine).read_line(&mut report).unwrap();
        let executable = std::fs::metadata(format!("/proc/{}/exe", child.id())).unwrap();
        let executable = (executable.st_dev(), executable.st_ino());

        (&mine).write_all(b"k").unwrap();
        assert!(child.wait().unwrap().success());
        (report, executable)
    }

    /// A file beside the test binary, where files may be executed whatever
    /// the temporary directory's mount allows. Removed when dropped.
    #[cfg(target_os = "linux")]
    struct Beside(std::path::PathBuf);

    #[cfg(target_os = "linux")]
    impl Beside {
        fn new(name: &str) -> Self {
            let directory = std::env::current_exe().unwrap();
            let directory = directory.parent().unwrap();
            Self(directory.join(format!("{name}-{}", std::process::id())))
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for Beside {
        fn drop(&mut self) {
            // The file may never have been made.
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_child_of_the_image_is_this_image_and_nothing_more() {
        use std::os::linux::fs::MetadataExt as _;

        let image = OwnImage::open().unwrap();
        let own = std::fs::metadata("/proc/self/exe").unwrap();
        assert_eq!(image.identity().unwrap(), (own.st_dev(), own.st_ino()));

        let (report, executable) = run_image_child(&image);
        // No environment, and only the standard streams and its socket.
        assert_eq!(report, format!("0 [0, 1, 2, {IMAGE_CHILD_FD}]\n"));
        assert_eq!(executable, image.identity().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_path_replaced_after_the_image_was_opened_still_starts_the_held_image() {
        use std::os::linux::fs::MetadataExt as _;

        let path = Beside::new("held-image");
        std::fs::copy(std::env::current_exe().unwrap(), &path.0).unwrap();
        let image = OwnImage::open_path(&path.0).unwrap();
        let held = image.identity().unwrap();

        // Another file takes the path, as an attacker's or an upgrade's would.
        let replacement = Beside::new("held-image-replacement");
        std::fs::write(&replacement.0, b"#!/bin/sh\nexit 7\n").unwrap();
        std::fs::rename(&replacement.0, &path.0).unwrap();
        let now = std::fs::metadata(&path.0).unwrap();
        assert_ne!((now.st_dev(), now.st_ino()), held);

        let (report, executable) = run_image_child(&image);
        assert_eq!(report, format!("0 [0, 1, 2, {IMAGE_CHILD_FD}]\n"));
        assert_eq!(executable, held);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_image_that_cannot_be_executed_fails_the_spawn() {
        let path = Beside::new("not-executable");
        // Readable, and not executable by anyone.
        std::fs::write(&path.0, b"not a program\n").unwrap();
        let image = OwnImage::open_path(&path.0).unwrap();

        let error = image.command(&["x"], vec![]).unwrap().spawn().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_command_without_arguments_or_with_too_many_is_refused() {
        let image = OwnImage::open().unwrap();
        let too_many = ["x"; MAX_IMAGE_ARGUMENTS + 1];
        for arguments in [&[][..], &too_many[..], &["nul\0inside"][..]] {
            assert_eq!(
                image.command(arguments, vec![]).unwrap_err().raw_os_error(),
                Some(libc::EINVAL)
            );
        }
    }

    #[test]
    fn inherited_descriptors_must_sit_above_every_target() {
        // A source below the floor, a target at or above it, or two sources
        // for one target could be overwritten while descriptors are placed.
        for descriptors in [
            &[(9, 4)][..],
            &[(70, INHERITED_SOURCE_FLOOR)],
            &[(70, 4), (71, 4)],
        ] {
            assert_eq!(
                inherit_descriptors(descriptors).unwrap_err().raw_os_error(),
                Some(libc::EINVAL)
            );
        }
    }
}
