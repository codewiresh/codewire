//! One fixed verifier child, no configured key retrieval or helper startup.

use std::fs::File;
use std::io::{self, Seek as _, SeekFrom};
use std::os::fd::AsRawFd as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, ChildStderr, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use codewire_cw_release::release::{valid_fingerprint, validate_signature};

use super::scratch::Scratch;

const MAX_STATUS: usize = 64 * 1024;
const MAX_STDERR: usize = 16 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(10);
const REAP_TIMEOUT: Duration = Duration::from_secs(2);
const TOOL_PATH: &str = "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin";

pub(super) struct Verifier {
    scratch: Arc<Scratch>,
    fingerprint: String,
    sequence: usize,
}

impl Verifier {
    pub(super) async fn import(
        scratch: Arc<Scratch>,
        key: &[u8],
        fingerprint: &str,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            valid_fingerprint(fingerprint) && key.len() <= 16 * 1024 && !key.is_empty(),
            "compiled release trust is invalid"
        );
        let file = scratch.write("public-key.asc", key)?;
        let value = Self {
            scratch,
            fingerprint: fingerprint.to_owned(),
            sequence: 0,
        };
        let status = value.run(&["--import"], vec![file]).await?;
        let imported: Vec<_> = status_lines(&status)?
            .into_iter()
            .filter(|fields| fields[0] == "IMPORT_OK")
            .collect();
        anyhow::ensure!(
            imported.len() == 1 && imported[0].len() == 3 && imported[0][2] == value.fingerprint,
            "compiled release key fingerprint differs from its pin"
        );
        Ok(value)
    }

    pub(super) async fn verify(&mut self, data: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        validate_signature(signature)?;
        self.sequence += 1;
        let data_file = self
            .scratch
            .write(&format!("signed-{}.json", self.sequence), data)?;
        let signature_file = self
            .scratch
            .write(&format!("signature-{}.asc", self.sequence), signature)?;
        let status = self
            .run(&["--verify"], vec![signature_file, data_file])
            .await?;
        admit_signature_status(&status, &self.fingerprint)
    }

    async fn run(&self, action: &[&str], mut files: Vec<File>) -> anyhow::Result<Vec<u8>> {
        self.scratch.check_paths()?;
        let mut command = Command::new("gpg");
        command
            .env_clear()
            .env("PATH", TOOL_PATH)
            .env("LC_ALL", "C")
            .current_dir(self.scratch.path())
            .args([
                "--batch",
                "--no-options",
                "--no-auto-key-retrieve",
                "--no-auto-key-import",
                "--disable-dirmngr",
                "--no-autostart",
                "--no-auto-check-trustdb",
                "--status-fd",
                "1",
                "--homedir",
            ])
            .arg(self.scratch.gnupg_home())
            .args(action)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut inherited = Vec::new();
        for file in &mut files {
            self.scratch.check_file(file)?;
            file.seek(SeekFrom::Start(0))
                .context("rewind verifier input")?;
            let fd = file.as_raw_fd();
            inherited.push(fd);
            let prefix = if cfg!(target_os = "linux") {
                "/proc/self/fd/"
            } else {
                "/dev/fd/"
            };
            command.arg(format!("{prefix}{fd}"));
        }
        // Only these public input FDs lose CLOEXEC in the forked child; the
        // parent and concurrent invocations retain their descriptor flags.
        #[cfg(target_os = "linux")]
        let parent = std::process::id();
        unsafe {
            command.pre_exec(move || {
                #[cfg(target_os = "linux")]
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                    || libc::getppid() != parent as libc::pid_t
                {
                    return Err(io::Error::other("release verifier parent custody changed"));
                }
                for fd in &inherited {
                    let flags = libc::fcntl(*fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(*fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        self.scratch.check_paths()?;
        run_child(command, self.scratch.clone(), PROCESS_TIMEOUT).await
    }
}

fn status_lines(status: &[u8]) -> anyhow::Result<Vec<Vec<&str>>> {
    let text = std::str::from_utf8(status).context("verifier status is not UTF-8")?;
    let mut lines = Vec::new();
    for line in text.lines() {
        let fields: Vec<_> = line
            .strip_prefix("[GNUPG:] ")
            .context("unexpected verifier status framing")?
            .split_ascii_whitespace()
            .collect();
        anyhow::ensure!(!fields.is_empty(), "empty verifier status");
        anyhow::ensure!(
            !matches!(
                fields[0],
                "BADSIG"
                    | "ERRSIG"
                    | "EXPSIG"
                    | "EXPKEYSIG"
                    | "REVKEYSIG"
                    | "KEYEXPIRED"
                    | "SIGEXPIRED"
                    | "KEYREVOKED"
                    | "NO_PUBKEY"
                    | "NODATA"
                    | "FAILURE"
                    | "ERROR"
            ),
            "release signature is bad, expired, revoked or unverifiable"
        );
        lines.push(fields);
    }
    Ok(lines)
}

fn admit_signature_status(status: &[u8], fingerprint: &str) -> anyhow::Result<()> {
    let lines = status_lines(status)?;
    let valid: Vec<_> = lines
        .iter()
        .filter(|fields| fields[0] == "VALIDSIG")
        .collect();
    anyhow::ensure!(
        valid.len() == 1
            && valid[0].len() == 11
            && valid[0][10] == fingerprint
            && matches!(valid[0][8], "8" | "9" | "10")
            && valid[0][9] == "00",
        "release must have exactly one valid detached signature by its pinned primary key"
    );
    Ok(())
}

struct ChildGuard {
    child: Child,
    scratch: Arc<Scratch>,
    reaped: bool,
    output_closed: bool,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.reaped && self.output_closed {
            return;
        }
        if !self.reaped {
            let _ = self.child.kill();
        }
        let readable = self.stdout.as_ref().is_some_and(|p| nonblocking(p).is_ok())
            && self.stderr.as_ref().is_some_and(|p| nonblocking(p).is_ok());
        let deadline = Instant::now() + REAP_TIMEOUT;
        loop {
            if !self.reaped {
                match self.child.try_wait() {
                    Ok(Some(_)) => self.reaped = true,
                    Ok(None) => {}
                    Err(_) => {
                        self.scratch.retain();
                        return;
                    }
                }
            }
            if self.reaped && readable {
                let out = self.stdout.as_mut().is_some_and(discard_closed);
                let err = self.stderr.as_mut().is_some_and(discard_closed);
                if out && err {
                    self.output_closed = true;
                    return;
                }
            }
            if Instant::now() >= deadline {
                self.scratch.retain();
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

fn discard_closed(pipe: &mut impl io::Read) -> bool {
    let mut buffer = [0_u8; 4096];
    for _ in 0..16 {
        match pipe.read(&mut buffer) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    false
}

fn nonblocking(pipe: &impl std::os::fd::AsRawFd) -> anyhow::Result<()> {
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error()).context("bound verifier output pipe");
    }
    Ok(())
}

fn read_output(pipe: &mut impl io::Read, bytes: &mut Vec<u8>, cap: usize) -> anyhow::Result<bool> {
    let mut buffer = [0_u8; 4096];
    for _ in 0..16 {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                anyhow::ensure!(
                    n <= cap.saturating_sub(bytes.len()),
                    "verifier output exceeds its bound"
                );
                bytes.extend_from_slice(&buffer[..n]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error).context("read bounded verifier output"),
        }
    }
    // Do not let an always-readable pipe starve the process deadline or the
    // caller's cancellation point. The next poll resumes the bounded stream.
    Ok(false)
}

pub(super) async fn run_child(
    mut command: Command,
    scratch: Arc<Scratch>,
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    let child = command
        .spawn()
        .context("start the installed GPG release verifier")?;
    let mut guard = ChildGuard {
        child,
        scratch,
        reaped: false,
        output_closed: false,
        stdout: None,
        stderr: None,
    };
    guard.stdout = guard.child.stdout.take();
    guard.stderr = guard.child.stderr.take();
    nonblocking(guard.stdout.as_ref().context("hold verifier status pipe")?)?;
    nonblocking(
        guard
            .stderr
            .as_ref()
            .context("hold verifier diagnostic pipe")?,
    )?;
    let deadline = Instant::now() + timeout;
    let mut status = Vec::new();
    let mut diagnostics = Vec::new();
    let mut exit = None;
    loop {
        let output_eof = read_output(
            guard.stdout.as_mut().expect("held status pipe"),
            &mut status,
            MAX_STATUS,
        )?;
        let diagnostic_eof = read_output(
            guard.stderr.as_mut().expect("held diagnostic pipe"),
            &mut diagnostics,
            MAX_STDERR,
        )?;
        if exit.is_none() {
            exit = guard.child.try_wait().context("reap release verifier")?;
        }
        if let Some(exit) = exit {
            guard.reaped = true;
            if output_eof && diagnostic_eof {
                guard.output_closed = true;
                anyhow::ensure!(
                    exit.success(),
                    "GPG rejected the release trust or signature"
                );
                return Ok(status);
            }
        }
        if Instant::now() >= deadline {
            // If the child is reaped but its pipes remain open, an unexpected
            // holder exists. Never turn direct-child exit into cleanup proof.
            if guard.reaped {
                guard.scratch.retain();
            }
            anyhow::bail!("release verifier exceeded its deadline or output closure is unknown");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
