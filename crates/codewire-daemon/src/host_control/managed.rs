//! Closed, bounded invocation of the cw-bearing target owner's record helper.
//! No requested program, provider endpoint or raw environment is accepted.
use super::{Error, Origin, Scope, canonical_uuid, session_id};
use codewire_daemon_proto::daemon::v1;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) const PROTOCOL: u32 = 1;
pub(crate) const MAX_RECORD_REPLY: usize = 5 * 1024 * 1024;
pub(crate) const CHUNK_DATA: usize = 240 * 1024;
pub(crate) const MAX_CHUNK: usize = 256 * 1024;
// A legal 64 KiB text can expand sixfold in JSON. The closed metadata,
// including a 4 KiB working directory, fits in the remaining 128 KiB.
const MAX_REQUEST: usize = 512 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn is_managed(value: i32) -> bool {
    matches!(
        v1::HostControlVerb::try_from(value),
        Ok(v1::HostControlVerb::ManagedLaunch
            | v1::HostControlVerb::ManagedMessage
            | v1::HostControlVerb::ManagedSteer
            | v1::HostControlVerb::ManagedInterrupt
            | v1::HostControlVerb::ManagedStop
            | v1::HostControlVerb::ManagedRestart
            | v1::HostControlVerb::ManagedRead)
    )
}
pub(crate) fn is_launch(value: i32) -> bool {
    value == v1::HostControlVerb::Launch as i32
        || value == v1::HostControlVerb::ManagedLaunch as i32
}
pub(crate) fn is_input(value: i32) -> bool {
    matches!(
        v1::HostControlVerb::try_from(value),
        Ok(v1::HostControlVerb::Input
            | v1::HostControlVerb::ManagedMessage
            | v1::HostControlVerb::ManagedSteer
            | v1::HostControlVerb::ManagedInterrupt)
    )
}
pub(crate) fn is_stop(value: i32) -> bool {
    value == v1::HostControlVerb::Stop as i32 || value == v1::HostControlVerb::ManagedStop as i32
}
pub(crate) fn verbs(managed: bool) -> Vec<i32> {
    let mut verbs = vec![1, 2, 3, 4];
    if managed {
        verbs.extend(5..=11);
    }
    verbs
}
fn token(value: &str) -> Result<(), Error> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn text(value: &str) -> Result<(), Error> {
    if value.trim().is_empty() || value.len() > 64 * 1024 || value.contains('\0') {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub(crate) fn validate_launch(value: &v1::HostControlManagedLaunch) -> Result<(), Error> {
    let agent = v1::HostManagedAgent::try_from(value.agent).map_err(|_| Error::Invalid)?;
    if !matches!(
        agent,
        v1::HostManagedAgent::Codex | v1::HostManagedAgent::Claude
    ) {
        return Err(Error::Invalid);
    }
    token(&value.model)?;
    if let Some(effort) = &value.effort {
        token(effort)?;
        if agent == v1::HostManagedAgent::Claude
            && !matches!(effort.as_str(), "low" | "medium" | "high" | "xhigh" | "max")
        {
            return Err(Error::Invalid);
        }
    } else if agent == v1::HostManagedAgent::Codex {
        return Err(Error::Invalid);
    }
    if value.working_dir.len() > 4096
        || value.working_dir.contains('\0')
        || (!value.working_dir.is_empty() && !Path::new(&value.working_dir).is_absolute())
        || (!value.name.is_empty() && !codewire_daemon_proto::valid_session_name(&value.name))
    {
        return Err(Error::Invalid);
    }
    if let Some(prompt) = &value.prompt {
        text(prompt)?;
    }
    if value.parent_session_id.is_empty() {
        if value.expected_parent_launch_generation != 0 {
            return Err(Error::Invalid);
        }
    } else {
        session_id(&value.parent_session_id)?;
        if value.expected_parent_launch_generation == 0 {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}
pub(crate) fn validate_control(value: &v1::HostControlManagedControl) -> Result<(), Error> {
    session_id(&value.session_id)?;
    canonical_uuid(&value.driver_id)?;
    if value.session_id != format!("session-{}", value.driver_id)
        || value.expected_launch_generation == 0
    {
        return Err(Error::Invalid);
    }
    let action = v1::HostManagedAction::try_from(value.action).map_err(|_| Error::Invalid)?;
    if let Some(id) = &value.reply_to {
        canonical_uuid(id)?;
    }
    if let Some(id) = &value.expected_active_message_id {
        canonical_uuid(id)?;
    }
    if let Some(id) = &value.expected_turn_id {
        token(id)?;
    }
    match action {
        v1::HostManagedAction::Message => {
            text(&value.text)?;
            if value.expected_turn_id.is_some() || value.expected_active_message_id.is_some() {
                return Err(Error::Invalid);
            }
        }
        v1::HostManagedAction::Steer => {
            text(&value.text)?;
            if value.expected_turn_id.is_none() || value.expected_active_message_id.is_none() {
                return Err(Error::Invalid);
            }
        }
        v1::HostManagedAction::Interrupt => {
            if !value.text.is_empty()
                || value.reply_to.is_some()
                || value.expected_active_message_id.is_none()
            {
                return Err(Error::Invalid);
            }
        }
        v1::HostManagedAction::Stop | v1::HostManagedAction::Restart => {
            if !value.text.is_empty()
                || value.reply_to.is_some()
                || value.expected_turn_id.is_some()
                || value.expected_active_message_id.is_some()
                || (action == v1::HostManagedAction::Restart
                    && value.expected_launch_generation == u64::MAX)
            {
                return Err(Error::Invalid);
            }
        }
        _ => return Err(Error::Invalid),
    }
    Ok(())
}
pub(crate) fn verb(value: &v1::HostControlManagedControl) -> v1::HostControlVerb {
    match v1::HostManagedAction::try_from(value.action) {
        Ok(v1::HostManagedAction::Message) => v1::HostControlVerb::ManagedMessage,
        Ok(v1::HostManagedAction::Steer) => v1::HostControlVerb::ManagedSteer,
        Ok(v1::HostManagedAction::Interrupt) => v1::HostControlVerb::ManagedInterrupt,
        Ok(v1::HostManagedAction::Stop) => v1::HostControlVerb::ManagedStop,
        Ok(v1::HostManagedAction::Restart) => v1::HostControlVerb::ManagedRestart,
        _ => v1::HostControlVerb::Unspecified,
    }
}

/// Match the retained pathname to the actual cw-bearing running inode. A
/// deleted/diverged image, standalone daemon, symlink or writable image refuses.
/// /proc/self/exe itself is used for helper invocation; only this admitted
/// original path is saved for the durable driver/restart.
pub(crate) fn retained_executable() -> Result<PathBuf, Error> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let args = std::fs::read("/proc/self/cmdline").map_err(|_| Error::Unavailable)?;
    if args.len() > 16 * 1024 || args.split(|b| *b == 0).nth(1) != Some(b"_host-daemon".as_slice())
    {
        return Err(Error::Unavailable);
    }
    let path = std::env::current_exe().map_err(|_| Error::Unavailable)?;
    if !path.is_absolute() || std::fs::canonicalize(&path).map_err(|_| Error::Unavailable)? != path
    {
        return Err(Error::Unavailable);
    }
    let held = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| Error::Unavailable)?;
    let a = held.metadata().map_err(|_| Error::Unavailable)?;
    let b = std::fs::metadata("/proc/self/exe").map_err(|_| Error::Unavailable)?;
    let uid = unsafe { libc::geteuid() };
    if !a.is_file()
        || !matches!(a.uid(), 0) && a.uid() != uid
        || a.nlink() != 1
        || a.mode() & 0o022 != 0
        || a.mode() & 0o111 == 0
        || a.dev() != b.dev()
        || a.ino() != b.ino()
        || a.len() != b.len()
    {
        return Err(Error::Unavailable);
    }
    Ok(path)
}
pub(crate) fn driver_command(
    config: &crate::Config,
    environment: &str,
    driver: &str,
) -> Result<Vec<String>, Error> {
    let root = &config.host.as_ref().ok_or(Error::Denied)?.state_root;
    Ok(vec![
        retained_executable()?
            .to_str()
            .ok_or(Error::Unavailable)?
            .into(),
        "_agent-driver".into(),
        "--environment".into(),
        environment.into(),
        "--driver-id".into(),
        driver.into(),
        "--registry-root".into(),
        root.parent()
            .and_then(|p| p.to_str())
            .ok_or(Error::Unavailable)?
            .into(),
    ])
}
pub(crate) fn is_driver(command: &[String]) -> bool {
    command.get(1).is_some_and(|v| v == "_agent-driver")
}
pub(crate) fn driver_command_shape(command: &[String], environment: &str, driver: &str) -> bool {
    command.len() == 8
        && Path::new(&command[0]).is_absolute()
        && command[1] == "_agent-driver"
        && command[2] == "--environment"
        && command[3] == environment
        && command[4] == "--driver-id"
        && command[5] == driver
        && command[6] == "--registry-root"
        && Path::new(&command[7]).is_absolute()
}

fn encode_request(request: &Value) -> Result<Vec<u8>, Error> {
    let request = serde_json::to_vec(request).map_err(|_| Error::Invalid)?;
    if request.len() > MAX_REQUEST {
        return Err(Error::Capacity);
    }
    Ok(request)
}

pub(crate) async fn helper(
    config: &crate::Config,
    environment: &str,
    request: Value,
) -> Result<Value, Error> {
    let host = config.host.as_ref().ok_or(Error::Denied)?;
    if host.state_root.file_name().and_then(|p| p.to_str()) != Some(environment) {
        return Err(Error::Denied);
    }
    retained_executable()?;
    let request = encode_request(&request)?;
    let mut child = tokio::process::Command::new("/proc/self/exe")
        .arg("__host-agent-control")
        .arg("--environment")
        .arg(environment)
        .arg("--registry-root")
        .arg(host.state_root.parent().ok_or(Error::Denied)?)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| Error::Unavailable)?;
    exchange_record_pipe(&mut child, &request).await
}

// The production caller supplies only its admitted retained-image child. Keep
// this private seam separate from executable selection so real pipe fixtures
// can verify EOF and cancellation without a production helper override.
pub(crate) async fn exchange_record_pipe(
    child: &mut tokio::process::Child,
    request: &[u8],
) -> Result<Value, Error> {
    let mut input = child.stdin.take().ok_or(Error::Unavailable)?;
    let output = child.stdout.take().ok_or(Error::Unavailable)?;
    let result = tokio::time::timeout(HELPER_TIMEOUT, async {
        let write = async {
            input.write_all(request).await?;
            input.shutdown().await?;
            // Unix ChildStdin shutdown is a no-op. Closing this owned writer
            // delivers EOF before the child can parse and answer the request.
            drop(input);
            Ok::<_, std::io::Error>(())
        };
        let read = async {
            let mut bytes = Vec::new();
            output
                .take(MAX_RECORD_REPLY as u64 + 1)
                .read_to_end(&mut bytes)
                .await?;
            Ok::<_, std::io::Error>(bytes)
        };
        let (_, bytes, status) =
            tokio::try_join!(write, read, child.wait()).map_err(|_| Error::Unavailable)?;
        if !status.success() {
            return Err(Error::Unavailable);
        }
        if bytes.len() > MAX_RECORD_REPLY {
            return Err(Error::Capacity);
        }
        serde_json::from_slice(&bytes).map_err(|_| Error::Unavailable)
    })
    .await
    .map_err(|_| Error::Unavailable)
    .and_then(|value| value);
    if result.is_err() {
        let _ = child.kill().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    }
    result
}
pub(crate) fn scoped(op: &str, scope: &Scope, driver: &str, session: &str) -> Value {
    json!({"op":op,"scope":scope,"driver_id":driver,"session_id":session})
}
pub(crate) fn prepare(origin: &Origin, launch: &v1::HostControlManagedLaunch) -> Value {
    json!({"op":"prepare","origin":origin,"agent":if launch.agent==v1::HostManagedAgent::Codex as i32 {"codex"}else{"claude"},
        "model":launch.model,"effort":launch.effort,"working_dir":launch.working_dir,"name":launch.name,
        "prompt":launch.prompt,"parent_session_id":launch.parent_session_id,
        "expected_parent_launch_generation":launch.expected_parent_launch_generation})
}
pub(crate) fn queue(origin: &Origin, control: &v1::HostControlManagedControl) -> Value {
    json!({"op":"queue","origin":origin,"driver_id":control.driver_id,"session_id":control.session_id,
        "action":match v1::HostManagedAction::try_from(control.action) {
            Ok(v1::HostManagedAction::Message)=>"message",Ok(v1::HostManagedAction::Steer)=>"steer",_=>"interrupt"},
        "text":control.text,"reply_to":control.reply_to,"expected_turn_id":control.expected_turn_id,
        "expected_active_message_id":control.expected_active_message_id,
        "launch_generation":control.expected_launch_generation})
}
pub(crate) fn line(driver: &str, message: &str, shutdown: bool) -> Result<Vec<u8>, Error> {
    let mut bytes = serde_json::to_vec(&json!({"v":1,"op":if shutdown{"shutdown"}else{"deliver"},
        "driver_id":driver,"message_id":message}))
    .map_err(|_| Error::Invalid)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    async fn pipe_child(body: &str) -> tokio::process::Child {
        let mut child = tokio::process::Command::new("/usr/bin/python3")
            .args(["-I", "-B", "-S", "-c"])
            .arg(format!(
                "import json, os, sys, time\nos.write(2, b'READY\\n')\n{body}"
            ))
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut ready = [0; 6];
        let mut stderr = child.stderr.take().unwrap();
        tokio::time::timeout(Duration::from_secs(2), stderr.read_exact(&mut ready))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ready, b"READY\n");
        child
    }

    #[cfg(target_os = "linux")]
    fn small_pipe(child: &tokio::process::Child) {
        use std::os::fd::AsRawFd;
        // A real small owned pipe makes the partial-write cancellation case
        // deterministic; no host or production pipe settings are changed.
        assert_eq!(
            unsafe {
                libc::fcntl(
                    child.stdin.as_ref().unwrap().as_raw_fd(),
                    libc::F_SETPIPE_SZ,
                    4096,
                )
            },
            4096
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn managed_pipe_complete_frame_delivers_eof_before_waiting_for_reply() {
        let origin =
            crate::host_control::tests::launch(3, &crate::host_control::tests::scope(), "exit 0")
                .origin();
        let mut control = control(v1::HostManagedAction::Message);
        control.text = "\u{1}".repeat(64 * 1024);
        validate_control(&control).unwrap();
        let request = encode_request(&queue(&origin, &control)).unwrap();
        let mut child = pipe_child(
            "raw = sys.stdin.buffer.read(524289)\nvalue = json.loads(raw)\nassert value['op'] == 'queue'\nassert value['text'] == '\\x01' * 65536\nos.write(1, json.dumps({'bytes': len(raw), 'complete': True}).encode())",
        )
        .await;
        small_pipe(&child);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            exchange_record_pipe(&mut child, &request),
        )
        .await;
        // Even a regression leaves the owned handle here for exact cleanup.
        if result.is_err() {
            child.kill().await.unwrap();
        }
        let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            result.unwrap().unwrap(),
            json!({"bytes": request.len(), "complete": true})
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn managed_pipe_write_failure_closes_and_reaps_only_its_owned_child() {
        let mut child = pipe_child("os.close(0)\ntime.sleep(2)").await;
        small_pipe(&child);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            exchange_record_pipe(&mut child, &vec![b'x'; MAX_REQUEST]),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        assert!(child.stdin.is_none() && child.stdout.is_none());
        assert!(child.try_wait().unwrap().is_some());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn managed_pipe_failed_exit_and_excess_reply_refuse_with_owned_child_reaped() {
        for (body, capacity) in [
            (
                "sys.stdin.buffer.read(262145)\nos.write(1, b'{}')\nsys.exit(29)".to_owned(),
                false,
            ),
            (
                format!(
                    "sys.stdin.buffer.read(262145)\nraw = b'x' * {}\nwhile raw:\n n = os.write(1, raw)\n raw = raw[n:]",
                    MAX_RECORD_REPLY + 1
                ),
                true,
            ),
        ] {
            let mut child = pipe_child(&body).await;
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                exchange_record_pipe(&mut child, b"{}"),
            )
            .await
            .unwrap();
            assert!(if capacity {
                matches!(result, Err(Error::Capacity))
            } else {
                result.is_err()
            });
            assert!(child.try_wait().unwrap().is_some());
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn managed_pipe_cancelled_partial_write_closes_before_owned_wait() {
        let mut child = pipe_child(
            "time.sleep(0.2)\nraw = sys.stdin.buffer.read(262145)\nassert 0 < len(raw) < 262144",
        )
        .await;
        small_pipe(&child);
        let request = vec![b'x'; MAX_REQUEST];
        assert!(
            tokio::time::timeout(
                Duration::from_millis(30),
                exchange_record_pipe(&mut child, &request),
            )
            .await
            .is_err()
        );
        // The exchange future's owned descriptors close on cancellation. This
        // still-owned child sees EOF and exits; no process is signaled/adopted.
        let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(status.success());
        assert!(child.stdin.is_none() && child.stdout.is_none());
    }

    fn control(action: v1::HostManagedAction) -> v1::HostControlManagedControl {
        let driver = uuid::Uuid::new_v4().to_string();
        v1::HostControlManagedControl {
            action: action as i32,
            session_id: format!("session-{driver}"),
            driver_id: driver,
            expected_launch_generation: 1,
            ..Default::default()
        }
    }
    #[test]
    fn managed_helper_serialization_preserves_maximally_escaped_legal_text() {
        let mut scope = crate::host_control::tests::scope();
        scope.org_id = "\"".repeat(256);
        scope.network_id = "\\".repeat(256);
        scope.grant_revision = u64::MAX;
        scope.validate().unwrap();
        let origin = crate::host_control::tests::launch(3, &scope, "exit 0").origin();
        let text = "\u{1}".repeat(64 * 1024);
        let mut launch = v1::HostControlManagedLaunch {
            agent: v1::HostManagedAgent::Codex as i32,
            model: "m".repeat(128),
            effort: Some("max".into()),
            working_dir: format!("/{}", "\u{1}".repeat(4095)),
            name: "n".repeat(64),
            prompt: Some(text.clone()),
            ..Default::default()
        };
        let mut control = control(v1::HostManagedAction::Message);
        control.text = text;
        control.expected_launch_generation = u64::MAX;
        validate_launch(&launch).unwrap();
        validate_control(&control).unwrap();
        for request in [prepare(&origin, &launch), queue(&origin, &control)] {
            let encoded = encode_request(&request).unwrap();
            assert!(encoded.len() > 256 * 1024);
            assert_eq!(serde_json::from_slice::<Value>(&encoded).unwrap(), request);
        }
        launch.prompt.as_mut().unwrap().push('\u{1}');
        control.text.push('\u{1}');
        assert!(validate_launch(&launch).is_err());
        assert!(validate_control(&control).is_err());
        control.text = "x".repeat(MAX_REQUEST);
        assert!(matches!(
            encode_request(&queue(&origin, &control)),
            Err(Error::Capacity)
        ));
    }

    #[test]
    fn managed_protocol_refuses_unbounded_or_ambiguous_agent_controls_before_dispatch() {
        let mut launch = v1::HostControlManagedLaunch {
            agent: v1::HostManagedAgent::Codex as i32,
            model: "synthetic".into(),
            effort: Some("max".into()),
            ..Default::default()
        };
        validate_launch(&launch).unwrap();
        launch.effort = None;
        assert!(validate_launch(&launch).is_err());
        launch.effort = Some("max".into());
        launch.agent = 0;
        assert!(validate_launch(&launch).is_err());
        launch.agent = 1;
        launch.prompt = Some("x".repeat(64 * 1024 + 1));
        assert!(validate_launch(&launch).is_err());
        let mut value = control(v1::HostManagedAction::Message);
        value.text = "message".into();
        validate_control(&value).unwrap();
        value.expected_launch_generation = 0;
        assert!(validate_control(&value).is_err());
        value.expected_launch_generation = 1;
        value.action = v1::HostManagedAction::Steer as i32;
        assert!(validate_control(&value).is_err());
        value.expected_turn_id = Some("turn-A".into());
        value.expected_active_message_id = Some(uuid::Uuid::new_v4().to_string());
        validate_control(&value).unwrap();
        value.action = v1::HostManagedAction::Stop as i32;
        assert!(validate_control(&value).is_err());
        let mut restart = control(v1::HostManagedAction::Restart);
        validate_control(&restart).unwrap();
        restart.expected_launch_generation = u64::MAX;
        assert!(validate_control(&restart).is_err());
    }
    #[test]
    fn managed_helper_requests_forward_original_generations_without_program_or_environment_fields()
    {
        let scope = crate::host_control::tests::scope();
        let request = crate::host_control::tests::launch(3, &scope, "exit 0");
        let mut launch = v1::HostControlManagedLaunch {
            agent: 1,
            model: "synthetic".into(),
            effort: Some("max".into()),
            parent_session_id: format!("session-{}", uuid::Uuid::new_v4()),
            expected_parent_launch_generation: 4,
            ..Default::default()
        };
        let prepared = prepare(&request.origin(), &launch);
        assert_eq!(prepared["expected_parent_launch_generation"], 4);
        for key in ["program", "registry_root", "env", "provider_endpoint"] {
            assert!(prepared.get(key).is_none());
        }
        launch.parent_session_id.clear();
        assert!(validate_launch(&launch).is_err());
        let mut value = control(v1::HostManagedAction::Message);
        value.text = "message".into();
        value.expected_launch_generation = 9;
        assert_eq!(queue(&request.origin(), &value)["launch_generation"], 9);
        assert!(
            retained_executable().is_err(),
            "a standalone lib test image is never a cw-bearing daemon"
        );
    }
}
