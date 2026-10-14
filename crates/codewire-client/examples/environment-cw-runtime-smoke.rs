//! Mandatory retained-Pod CW bootstrap/update/rollback acceptance.
//!
//! The ordinary journey retains its original Pod, attachment and processes.
//! Managed mode explicitly restarts the lead after known-clean family Stop.
//! Each mutation is sent once and observed under its original request UUID.
//! The Kind owner supplies producer-reopened assets and a synthetic login.
//! Ordinary UID1000 sessions are covered. The explicit managed Kind mode also
//! retains the original stock worker families through the same update journey.

#[cfg(target_os = "linux")]
#[path = "support/platform_managed.rs"]
mod platform_managed;

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("the platform runtime custody journey requires a Linux host");
}

#[cfg(target_os = "linux")]
#[tokio::main(worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    match linux::main().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            // Render only the fixed outer context; never a remote error chain,
            // HTTP details, command diagnostics or the synthetic login.
            eprintln!("environment-cw-runtime-smoke: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write as _};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::{Component, Path, PathBuf};
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    use anyhow::{Context as _, ensure};
    use codewire_client::cw_runtime::{
        EnvironmentCwRuntimeExpectation, EnvironmentCwRuntimeIdentity,
        EnvironmentCwRuntimeIncarnation, EnvironmentCwRuntimeOperation,
        EnvironmentCwRuntimeSelection, GetEnvironmentCwRuntimeRequest,
        GetEnvironmentCwRuntimeResponse, ObserveEnvironmentCwRuntimeRequest,
        UpdateEnvironmentCwRuntimeHeader, environment_cw_runtime_acknowledgement,
    };
    use codewire_client::{
        AttachSessionOpen, ClientConfig, ClientError, CodewireClient, EnvironmentSession,
        EnvironmentSessionAttachment, EnvironmentSessionOutputChunk, EnvironmentSessionState,
        ErrorCode, GetSessionRequest, LaunchSessionRequest, ReadSessionOutputRequest,
        SendSessionInputRequest, StaticTokenProvider, StopSessionRequest, attach_session_response,
    };
    use codewire_cw_release::build_record;
    use codewire_cw_release::identity::{
        Arch, CwPayloadIdentity, MAX_EXECUTABLE_BYTES, MAX_IDENTITY_BYTES, Os, Platform,
        canonical_json,
    };
    use futures_util::{Stream, stream};
    use rustix::fs::{Mode, OFlags};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};
    use tokio::io::AsyncReadExt as _;
    use tokio::sync::mpsc;
    use uuid::Uuid;

    // External admission tools may spell the owning build.rs marker. The
    // production CW executable still contains exactly one compiled record.
    const CW_MARKER: &[u8] = b"\0codewire-cw-build-record-v1\0";
    const PROBE: &str = include_str!("../../../scripts/ci/verify/kind/cw_runtime_probe.py");
    const MAX_JSON: usize = 64 * 1024;
    const MAX_OUTPUT: usize = 1024 * 1024;
    const MAX_LINE: usize = 16 * 1024;
    const MAX_JOURNAL_BYTES: usize = 512 * 1024;
    const COMMAND_BUDGET: Duration = Duration::from_secs(180);
    const JOURNEY_BUDGET: Duration = Duration::from_secs(840);
    const READ_BUDGET: Duration = Duration::from_secs(60);
    const HISTORY_BUDGET: Duration = Duration::from_secs(30);
    const STORE: &str = "/home/codewire/.local/share/codewire/cli";

    pub(super) async fn main() -> anyhow::Result<()> {
        if std::env::var("SMOKE_CW_MANAGED_AGENTS").as_deref() == Ok("only") {
            return managed_only().await;
        }
        let inputs = Inputs::open().context("admit all original journey inputs")?;
        let client = inputs
            .client()
            .context("configure the synthetic public client")?;
        let initial = status(&client, &inputs).await?;
        validate_status(&initial, &inputs, None)?;
        let original = initial.incarnation.as_option().unwrap().clone();
        let image = initial.bootstrap_identity.as_option().unwrap().clone();
        admit_original_image(&image, &inputs.support.identity)?;
        let mut managed = match std::env::var("SMOKE_CW_MANAGED_AGENTS") {
            Err(std::env::VarError::NotPresent) => None,
            Ok(value) if value == "1" => {
                let mut journey = super::platform_managed::Journey::launch(
                    &client,
                    &inputs.org,
                    &inputs.environment,
                    &original,
                    &image,
                )
                .await?;
                journey.validate_scope(&original, &image)?;
                journey.begin_continuity(&client).await?;
                Some(journey)
            }
            _ => anyhow::bail!("managed Kind mode must be absent or exactly1"),
        };
        let original_images = OriginalImages {
            support: &image,
            workspace: &inputs.a.identity,
        };
        let selection = initial.selection.as_option().unwrap();
        ensure!(
            selection.generation == 0
                && selection.current.as_option().is_none()
                && selection.previous.as_option().is_none()
                && selection.retained_count == 0,
            "the owned Pod must start with an absent ordinary CW Store"
        );
        ensure!(
            PROBE.len() <= 48 * 1024,
            "the fixed observer exceeds its launch bound"
        );
        let nonce = Uuid::new_v4().simple().to_string();
        let mut journal = InputJournal::create(&inputs.home, &nonce)?;
        let mut launch_request = LaunchSessionRequest {
            org_id: inputs.org.clone(),
            environment_id: inputs.environment.clone(),
            command: vec![
                "/usr/bin/python3".into(),
                "-I".into(),
                "-u".into(),
                "-B".into(),
                "-c".into(),
                PROBE.into(),
                "--environment-id".into(),
                inputs.environment.clone(),
                "--nonce".into(),
                nonce.clone(),
                "--daemon-sha256".into(),
                image.sha256.clone(),
                "--daemon-size".into(),
                image.size.to_string(),
                "--daemon-version".into(),
                image.package_version.clone(),
                "--workspace-sha256".into(),
                inputs.a.identity.sha256.clone(),
                "--workspace-size".into(),
                inputs.a.identity.size.to_string(),
                "--workspace-version".into(),
                inputs.a.identity.package_version.clone(),
            ],
            working_dir: "/workspace".into(),
            pty: false,
            name: format!("cw-runtime-{}", &nonce[..16]),
            ..Default::default()
        };
        if let Some(journey) = &managed {
            launch_request.command.extend([
                "--managed-peers-json".into(),
                serde_json::to_string(&journey.process_witness())?,
            ]);
        }
        let launched = client
            .launch_session(launch_request.clone())
            .await
            .context("launch the one fixed UID1000 observer session")?
            .session
            .into_option()
            .context("observer launch omitted its session")?;
        session_id(&launched.session_id)?;
        ensure!(
            launched.launch_generation > 0
                && launched.command == launch_request.command
                && launched.working_dir == launch_request.working_dir
                && launched.name == launch_request.name
                && !launched.pty
                && launched.parent_session_id.is_none()
                && launched.created_at.as_option().is_some()
                && !launched.cleanup_unknown
                && launched.output_start_offset == 0,
            "observer launch changed its fixed durable binding"
        );
        let attachment_result = client
            .attach_session(AttachSessionOpen {
                org_id: inputs.org.clone(),
                environment_id: inputs.environment.clone(),
                session_id: launched.session_id.clone(),
                output_offset: 0,
                ..Default::default()
            })
            .await;
        let attachment = match attachment_result {
            Ok(attachment) => attachment,
            Err(_) => {
                // The durable launch can outlive an Attach refusal. Stop only
                // its already-returned exact ID; never launch another observer.
                let cleanup = tokio::time::timeout(
                    READ_BUDGET,
                    client.stop_session(StopSessionRequest {
                        org_id: inputs.org.clone(),
                        environment_id: inputs.environment.clone(),
                        session_id: launched.session_id.clone(),
                        ..Default::default()
                    }),
                )
                .await;
                let known = matches!(cleanup,Ok(Ok(ref response)) if response.session.as_option()
                    .is_some_and(|view|view.session_id==launched.session_id
                        && view.launch_generation==launched.launch_generation && !view.cleanup_unknown));
                eprintln!(
                    "{}",
                    serde_json::json!({"schema_version":1,"outcome":"failed","stage":"original-attach",
                    "environment_id":inputs.environment,"session_id":launched.session_id,"observer_cleanup_known":known,
                    "request_journal":journal.path})
                );
                anyhow::bail!(
                    "original Attach failed; exact observer cleanup/evidence requires review"
                );
            }
        };
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let observed_session = launched.clone();
        let observer_nonce = nonce.clone();
        let environment = inputs.environment.clone();
        let mut reader = tokio::spawn(async move {
            consume(
                attachment,
                observed_session,
                &observer_nonce,
                &environment,
                events_tx,
            )
            .await
        });

        // The consumer starts before gen0 bootstrap, and is never stopped or
        // replaced during a mutation. Ready includes held kernel identities.
        let mut submitted = Vec::new();
        let mut stage = "baseline";
        let result = tokio::time::timeout(JOURNEY_BUDGET, async {
            let baseline = next_event(&mut events_rx).await?;
            validate_probe(&baseline, 0, "ready", "baseline", None, &original_images, None)?;
            ensure!(baseline.managed.len() == if managed.is_some() { 9 } else { 0 },
                "observer omitted the selected original managed process handles");
            let session = get_session(&client, &inputs, &launched.session_id).await?;
            validate_session(&session, &launched, false)?;
            ensure!(session.started_at.as_option().is_some(), "original session has no settled birth");
            ensure!(!reader.is_finished(), "original attachment terminated before bootstrap");
            let mut current = initial.clone();
            let mut operations = Vec::new();
            let mut previous_samples = baseline.samples;
            for (phase, payload) in [("bootstrapped-a", &inputs.a), ("selected-b", &inputs.b)] {
                stage = phase;
                unchanged(&client, &inputs, &current, &session, &reader).await?;
                let request = Uuid::new_v4().to_string();
                let generation = current.selection.as_option().unwrap().generation;
                journal.request(&request,"update",generation,&original,&session,&payload.identity)?;
                submitted.push(request.clone());
                let operation: EnvironmentCwRuntimeOperation = inputs.cli_json(&[
                    "env", "--platform", "runtime", "update", &inputs.environment,
                    "--from", payload.directory.to_str().context("release path is not UTF8")?,
                    "--target-sha256", &payload.identity.sha256,
                    "--expected-generation", &generation.to_string(),
                    "--request-id", &request, "--output", "json",
                ]).await.context("public CW update did not return an acknowledged operation")?;
                validate_operation(&operation, &request, "update", &original, &current, &payload.identity)?;
                journal.acknowledged(&operation)?;
                observe_twice(&client, &inputs, &operation).await?;
                current = status(&client, &inputs).await?;
                validate_status(&current, &inputs, Some(&original))?;
                selected(&current, &payload.identity, &operation)?;
                checkpoint(&client, &inputs, &session, phase, payload).await?;
                let event = next_event(&mut events_rx).await?;
                let sequence = if phase == "bootstrapped-a" { 1 } else { 2 };
                validate_probe(&event, sequence, "checkpoint", phase, Some(&payload.identity), &original_images,
                    Some(&baseline))?;
                ensure!(event.samples > previous_samples, "observer sample counter regressed");
                previous_samples = event.samples;
                unchanged(&client, &inputs, &current, &session, &reader).await?;
                if let Some(journey) = &managed {
                    journey.checkpoint(&client, phase).await?;
                }
                operations.push(operation);
                if phase == "bootstrapped-a" {
                    // These are valid typed requests with a stale captured
                    // incarnation / corrupted stream, not Pod replacement or
                    // failure injection. No journal/effect may be admitted.
                    refusal_cases(&client, &inputs, &current,&session,&mut journal,&mut submitted).await?;
                    unchanged(&client, &inputs, &current, &session, &reader).await?;
                    let stale = generation.to_string();
                    let negative_id = Uuid::new_v4().to_string();
                    journal.request(&negative_id,"refusal-stale-generation",generation,&original,&session,&inputs.b.identity)?;
                    submitted.push(negative_id.clone());
                    ensure!(inputs.cli_json::<EnvironmentCwRuntimeOperation>(&[
                        "env", "--platform", "runtime", "update", &inputs.environment,
                        "--from", inputs.b.directory.to_str().unwrap(),
                        "--target-sha256", &inputs.b.identity.sha256,
                        "--expected-generation", &stale, "--request-id", &negative_id,
                        "--output", "json",
                    ]).await.is_err(), "public CLI admitted a stale Store generation");
                    absent_operation(&client, &inputs, &negative_id).await?;
                    unchanged(&client, &inputs, &current, &session, &reader).await?;
                }
            }
            stage = "rolled-back-a";
            let rollback = Uuid::new_v4().to_string();
            let generation = current.selection.as_option().unwrap().generation;
            ensure!(current.selection.as_option().unwrap().previous.as_option()
                == Some(&proto_identity(&inputs.a.identity)), "B does not retain exact release A");
            journal.request(&rollback,"rollback",generation,&original,&session,&inputs.a.identity)?;
            submitted.push(rollback.clone());
            let operation: EnvironmentCwRuntimeOperation = inputs.cli_json(&[
                "env", "--platform", "runtime", "rollback", &inputs.environment,
                "--expected-generation", &generation.to_string(), "--request-id", &rollback,
                "--output", "json",
            ]).await.context("public rollback did not return an acknowledged operation")?;
            validate_operation(&operation, &rollback, "rollback", &original, &current, &inputs.a.identity)?;
            journal.acknowledged(&operation)?;
            observe_twice(&client, &inputs, &operation).await?;
            current = status(&client, &inputs).await?;
            validate_status(&current, &inputs, Some(&original))?;
            selected(&current, &inputs.a.identity, &operation)?;
            ensure!(current.selection.as_option().unwrap().previous.as_option()
                == Some(&proto_identity(&inputs.b.identity)), "rollback did not retain exact B");
            checkpoint(&client, &inputs, &session, "rolled-back-a", &inputs.a).await?;
            let returned = next_event(&mut events_rx).await?;
            validate_probe(&returned, 3, "checkpoint", "rolled-back-a", Some(&inputs.a.identity), &original_images,
                Some(&baseline))?;
            ensure!(returned.samples > previous_samples, "observer sample counter regressed");
            previous_samples = returned.samples;
            unchanged(&client, &inputs, &current, &session, &reader).await?;
            if let Some(journey) = &managed {
                journey.checkpoint(&client, "rolled-back-a").await?;
            }
            let mut close_sequence = 4;
            if let Some(journey) = &mut managed {
                stage = "managed-controls-and-revocation";
                journey.controls(&client).await?;
                for (variable, prefix, worker) in MANAGED_CREDENTIALS {
                    let name = managed_credential(variable, prefix)?;
                    inputs.cli_json::<serde_json::Value>(&[
                        "credentials", "--platform", "revoke", &name, "--output", "json",
                    ]).await.context("revoke the exact selected synthetic provider credential")?;
                    journey.revoked(&client, worker).await?;
                }
                unchanged(&client, &inputs, &current, &session, &reader).await?;
                send(&client, &inputs, &session.session_id, b"{\"op\":\"managed-stop-ready\"}\n".to_vec()).await?;
                let ready = next_event(&mut events_rx).await?;
                validate_probe(&ready, 4, "managed-stop-ready", "rolled-back-a",
                    Some(&inputs.a.identity), &original_images, Some(&baseline))?;
                ensure!(ready.samples > previous_samples, "managed live observer samples regressed");
                previous_samples = ready.samples;
                stage = "managed-known-clean-stop";
                journey.stop(&client).await?;
                send(&client, &inputs, &session.session_id, b"{\"op\":\"managed-stopped\"}\n".to_vec()).await?;
                let stopped = next_event(&mut events_rx).await?;
                validate_probe(&stopped, 5, "managed-stopped", "rolled-back-a",
                    Some(&inputs.a.identity), &original_images, Some(&baseline))?;
                ensure!(stopped.samples > previous_samples && stopped.managed_terminal,
                    "the original nine held managed process handles did not terminate");
                previous_samples = stopped.samples;
                close_sequence = 6;
            }
            send(&client, &inputs, &session.session_id, b"{\"op\":\"close\"}\n".to_vec()).await?;
            stage = "close-and-history";
            let closed = next_event(&mut events_rx).await?;
            validate_probe(&closed, close_sequence, "closed", "closed", Some(&inputs.a.identity), &original_images,
                Some(&baseline))?;
            ensure!(closed.samples > previous_samples, "observer sample counter regressed");
            let captured = tokio::time::timeout(READ_BUDGET, &mut reader).await
                .context("original attachment did not reach normal terminal EOF")??
                .context("original attachment custody/history failed")?;
            let final_session = get_session(&client, &inputs, &session.session_id).await?;
            validate_session(&final_session, &session, true)?;
            ensure!(final_session.output_end_offset==captured.len() as u64,"original final output cursor changed");
            let retained = retained_history(&client, &inputs, &session.session_id).await?;
            ensure!(retained == captured, "original retained history differs from the one attachment");
            if let Some(journey) = &mut managed {
                stage = "managed-restart-and-reconnect";
                let reconnected = inputs.client()?;
                journey.restart(&client, &reconnected).await?;
            }
            inputs.recheck()?;
            ensure!(status(&client, &inputs).await? == current, "selection/incarnation changed at handoff");
            operations.push(operation);
            println!("{}", serde_json::to_string(&serde_json::json!({
                "schema_version": 1, "outcome": "passed", "environment_id": inputs.environment,
                "incarnation": original, "original_image": image,
                "release_a": inputs.a.identity, "release_b": inputs.b.identity,
                "support_cw": inputs.support.identity,
                "session_id": session.session_id, "launch_generation": session.launch_generation,
                "attachment_count": 1, "history_sha256": hex_digest(&captured),
                "history_bytes": captured.len(), "operations": operations,
                "probe_ready": baseline, "probe_final": closed,
                "input_witness_sha256": inputs.witness_sha256,
                "original_requests": submitted, "request_journal": journal.path,
                "claims": ["UID1000_same_Pod", "original_kernel_processes",
                    "original_session_and_Attach", "ordinary_CW_A_B_A", "public_journal_no_replay"],
                "managed_agents_qualified": managed.is_some(),
                "not_claimed": ["live_providers", "physical_Mac"]
            }))?);
            Ok::<_, anyhow::Error>(())
        }).await.context("bounded same-Pod runtime journey expired").and_then(|r| r);
        if result.is_err() {
            // Cleanup is an exact public Stop, never actor signaling or a Pod
            // restart. It does not convert a failed/Unknown journey to success.
            let cleanup = tokio::time::timeout(READ_BUDGET, async {
                let stopped = client
                    .stop_session(StopSessionRequest {
                        org_id: inputs.org.clone(),
                        environment_id: inputs.environment.clone(),
                        session_id: launched.session_id.clone(),
                        ..Default::default()
                    })
                    .await
                    .context("stop the exact owned observer")?
                    .session
                    .into_option()
                    .context("cleanup omitted its session")?;
                ensure!(
                    stopped.session_id == launched.session_id
                        && stopped.launch_generation == launched.launch_generation
                        && !stopped.cleanup_unknown,
                    "observer cleanup identity is unknown"
                );
                if !reader.is_finished() {
                    let _ = (&mut reader).await;
                }
                Ok::<_, anyhow::Error>(())
            })
            .await;
            eprintln!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "schema_version": 1, "outcome": "failed", "stage": stage,
                    "environment_id": inputs.environment, "session_id": launched.session_id,
                    "request_ids": submitted, "observer_cleanup_known": matches!(cleanup, Ok(Ok(()))),
                    "request_journal": journal.path,
                    "recovery": "preserve environment; observe SAME request UUID; never reissue"
                }))?
            );
        }
        // Do not expose a remote/provider source chain at the executable's
        // outer error renderer. The fixed stage and original IDs above retain
        // recovery context without conferring mutation permission.
        result.map_err(|_| {
            anyhow::anyhow!("same-Pod runtime acceptance failed; retained evidence requires review")
        })
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Stamp {
        device: u64,
        inode: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        links: u64,
        size: u64,
        mtime: i64,
        mtime_ns: i64,
        ctime: i64,
        ctime_ns: i64,
    }
    impl Stamp {
        fn of(file: &File) -> anyhow::Result<Self> {
            let m = file.metadata()?;
            Ok(Self {
                device: m.dev(),
                inode: m.ino(),
                mode: m.mode(),
                uid: m.uid(),
                gid: m.gid(),
                links: m.nlink(),
                size: m.len(),
                mtime: m.mtime(),
                mtime_ns: m.mtime_nsec(),
                ctime: m.ctime(),
                ctime_ns: m.ctime_nsec(),
            })
        }
        fn directory_equal(self, other: Self) -> bool {
            (self.device, self.inode, self.mode, self.uid, self.gid)
                == (other.device, other.inode, other.mode, other.uid, other.gid)
        }
    }
    struct Held {
        path: PathBuf,
        file: File,
        stamp: Stamp,
        directories: Vec<(PathBuf, File, Stamp)>,
    }
    impl Held {
        fn open(path: &Path, maximum: u64) -> anyhow::Result<Self> {
            ensure!(
                path.is_absolute() && path.as_os_str().len() <= 4096,
                "input path is not bounded absolute"
            );
            ensure!(
                path.components().collect::<PathBuf>().as_os_str() == path.as_os_str(),
                "input path is not canonical"
            );
            let mut at = PathBuf::new();
            let mut directories = Vec::new();
            for component in path.parent().context("input has no parent")?.components() {
                match component {
                    Component::RootDir => at.push("/"),
                    Component::Normal(name) => at.push(name),
                    _ => anyhow::bail!("input ancestry is not canonical"),
                }
                ensure!(directories.len() < 64, "input ancestry exceeds its bound");
                let file: File = rustix::fs::open(
                    &at,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?
                .into();
                let stamp = Stamp::of(&file)?;
                let uid = rustix::process::geteuid().as_raw();
                ensure!(
                    stamp.uid == 0 || stamp.uid == uid,
                    "foreign-owned input ancestor"
                );
                ensure!(
                    stamp.mode & 0o022 == 0 || (stamp.uid == 0 && stamp.mode & 0o7777 == 0o1777),
                    "writable input ancestor"
                );
                directories.push((at.clone(), file, stamp));
            }
            let file: File = rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?
            .into();
            let stamp = Stamp::of(&file)?;
            let uid = rustix::process::geteuid().as_raw();
            ensure!(
                file.metadata()?.is_file()
                    && stamp.links == 1
                    && (stamp.uid == uid || stamp.uid == 0)
                    && stamp.mode & 0o6022 == 0
                    && (1..=maximum).contains(&stamp.size),
                "unsafe or unbounded input file"
            );
            let result = Self {
                path: path.into(),
                file,
                stamp,
                directories,
            };
            result.recheck()?;
            Ok(result)
        }
        fn recheck(&self) -> anyhow::Result<()> {
            for (path, file, stamp) in &self.directories {
                ensure!(
                    stamp.directory_equal(Stamp::of(file)?),
                    "held input ancestor changed"
                );
                let current: File = rustix::fs::open(
                    path,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?
                .into();
                ensure!(
                    stamp.directory_equal(Stamp::of(&current)?),
                    "input ancestor name changed"
                );
            }
            ensure!(
                Stamp::of(&self.file)? == self.stamp,
                "held input file changed"
            );
            let current: File = rustix::fs::open(
                &self.path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?
            .into();
            ensure!(
                Stamp::of(&current)? == self.stamp,
                "input file name changed"
            );
            Ok(())
        }
        fn bytes(&mut self, maximum: usize) -> anyhow::Result<Vec<u8>> {
            self.recheck()?;
            self.file.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            (&mut self.file)
                .take(maximum as u64 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == self.stamp.size && bytes.len() <= maximum,
                "input was truncated or oversized"
            );
            self.recheck()?;
            Ok(bytes)
        }
        fn hash(&mut self) -> anyhow::Result<String> {
            self.recheck()?;
            self.file.seek(SeekFrom::Start(0))?;
            let deadline = Instant::now() + COMMAND_BUDGET;
            let mut hasher = Sha256::new();
            let mut total = 0_u64;
            let mut buffer = vec![0; 1024 * 1024];
            loop {
                ensure!(
                    Instant::now() < deadline,
                    "input hashing exceeded its bound"
                );
                let n = self.file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                ensure!(total <= self.stamp.size, "input grew during hashing");
                hasher.update(&buffer[..n]);
            }
            ensure!(total == self.stamp.size, "input ended during hashing");
            self.recheck()?;
            Ok(format!("{:x}", hasher.finalize()))
        }
    }

    struct Payload {
        directory: PathBuf,
        identity: CwPayloadIdentity,
        executable: Held,
        descriptor: Held,
    }
    impl Payload {
        fn open(directory: PathBuf, pin: &str) -> anyhow::Result<Self> {
            sha256(pin)?;
            let mut descriptor = Held::open(
                &directory.join("cw-runtime.json"),
                MAX_IDENTITY_BYTES as u64,
            )?;
            let bytes = descriptor.bytes(MAX_IDENTITY_BYTES)?;
            let identity = CwPayloadIdentity::decode(&bytes)?;
            ensure!(
                identity.encode()? == bytes
                    && identity.sha256 == pin
                    && identity.target == "x86_64-unknown-linux-musl",
                "release identity differs from its pin/target"
            );
            let mut executable = Held::open(&directory.join("cw"), MAX_EXECUTABLE_BYTES)?;
            ensure!(
                executable.stamp.mode & 0o111 != 0,
                "release is not executable"
            );
            build_record::admit_incoming(
                &mut executable.file,
                &executable.path,
                &identity,
                Platform::new(Os::Linux, Arch::X86_64),
                CW_MARKER,
            )?;
            ensure!(
                executable.stamp.size == identity.size,
                "release size mismatch"
            );
            executable.recheck()?;
            Ok(Self {
                directory,
                identity,
                executable,
                descriptor,
            })
        }
        fn recheck(&self) -> anyhow::Result<()> {
            self.descriptor.recheck()?;
            self.executable.recheck()
        }
        fn chunks(
            &self,
            corrupt: bool,
        ) -> anyhow::Result<impl Stream<Item = Result<Vec<u8>, ClientError>> + Send + 'static>
        {
            self.recheck()?;
            let mut file = Held::open(&self.executable.path, self.identity.size)?;
            ensure!(
                file.stamp == self.executable.stamp,
                "release was replaced before typed stream"
            );
            file.file.seek(SeekFrom::Start(0))?;
            Ok(stream::unfold(
                (file, 0_u64, corrupt),
                |(mut held, count, corrupt)| async move {
                    if count == held.stamp.size {
                        return None;
                    }
                    let result = (|| -> anyhow::Result<Vec<u8>> {
                        held.recheck()?;
                        let mut bytes = vec![0; (held.stamp.size - count).min(64 * 1024) as usize];
                        held.file.read_exact(&mut bytes)?;
                        held.recheck()?;
                        if corrupt && count == 0 {
                            bytes[0] ^= 1;
                        }
                        Ok(bytes)
                    })();
                    match result {
                        Ok(bytes) => {
                            let next = count + bytes.len() as u64;
                            Some((Ok(bytes), (held, next, false)))
                        }
                        Err(_) => {
                            let end = held.stamp.size;
                            Some((
                                Err(ClientError::new(
                                    ErrorCode::InvalidArgument,
                                    "held release changed during typed stream",
                                )),
                                (held, end, false),
                            ))
                        }
                    }
                },
            ))
        }
    }

    #[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Source {
        revision: String,
        git_tree: String,
        source_tree_sha256: String,
        index_sha256: String,
        object_count: u64,
    }
    #[derive(Debug, Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Descriptor {
        path: PathBuf,
        sha256: String,
        size: u64,
    }
    #[derive(Debug, Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct ReleaseInput {
        release_dir: PathBuf,
        identity: CwPayloadIdentity,
        build_receipt: Descriptor,
        producer_receipt: Descriptor,
        image: Descriptor,
        index_sha256: String,
        compilation_source: Source,
        profile: String,
        version: String,
        build_ref: String,
    }
    #[derive(Debug, Clone, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Witness {
        schema_version: u32,
        source_sha: String,
        current_source: Source,
        support_cw: ReleaseInput,
        release_a: ReleaseInput,
        release_b: ReleaseInput,
    }
    /// The synthetic public route, login and pinned CLI every journey uses.
    struct Access {
        org: String,
        environment: String,
        base: String,
        ca: Option<Vec<u8>>,
        token: String,
        cli: Held,
        home: PathBuf,
        references: Vec<Held>,
    }
    /// Access plus the admitted support, A and B producers of the ordinary
    /// CW update journey.
    struct Inputs {
        access: Access,
        support: Payload,
        a: Payload,
        b: Payload,
        witness: Held,
        witness_sha256: String,
        references: Vec<Held>,
    }
    impl std::ops::Deref for Inputs {
        type Target = Access;
        fn deref(&self) -> &Access {
            &self.access
        }
    }
    impl Access {
        fn open() -> anyhow::Result<Self> {
            let org = env("SMOKE_ORG_ID")?;
            ensure!(
                !org.is_empty() && org.len() <= 128,
                "organization exceeds its bound"
            );
            let environment = env("SMOKE_ENVIRONMENT_ID")?;
            uuid(&environment)?;
            let base = env("SMOKE_CW_RUNTIME_BASE_URL")?;
            let route = ClientConfig::new(&base)?;
            ensure!(
                route.server_url().username().is_empty() && route.server_url().password().is_none(),
                "synthetic public route must not carry URL credentials"
            );
            let token = env("SMOKE_ACCESS_TOKEN")?;
            ensure!(
                token == "at_kind_connect_oidc_codewire_api",
                "only the fixed synthetic personal login is admitted"
            );
            let mut ca_file = std::env::var_os("SMOKE_CA_CERT_FILE")
                .map(PathBuf::from)
                .map(|path| Held::open(&path, MAX_JSON as u64))
                .transpose()?;
            let ca = ca_file
                .as_mut()
                .map(|held| held.bytes(MAX_JSON))
                .transpose()?;
            let mut cli = Held::open(
                &PathBuf::from(env("SMOKE_CW_CLI_PATH")?),
                MAX_EXECUTABLE_BYTES,
            )?;
            let cli_pin = env("SMOKE_CW_CLI_SHA256")?;
            sha256(&cli_pin)?;
            ensure!(
                cli.stamp.mode & 0o111 != 0 && cli.hash()? == cli_pin,
                "original CLI executable differs from its pin"
            );
            let home = PathBuf::from(env("SMOKE_CW_CLI_HOME")?);
            let probe_file = Held::open(&home.join("cw/config.json"), MAX_JSON as u64)?;
            ensure!(
                probe_file.directories.iter().rev().take(2).count() == 2
                    && probe_file
                        .directories
                        .iter()
                        .rev()
                        .take(2)
                        .all(|(_, _, s)| s.uid == rustix::process::geteuid().as_raw()
                            && s.mode & 0o7777 == 0o700),
                "synthetic CLI config parent is not owner-private"
            );
            let mut references = vec![probe_file];
            if let Some(held) = ca_file {
                references.push(held);
            }
            Ok(Self {
                org,
                environment,
                base,
                ca,
                token,
                cli,
                home,
                references,
            })
        }
        fn recheck(&self) -> anyhow::Result<()> {
            self.cli.recheck()?;
            for held in &self.references {
                held.recheck()?;
            }
            Ok(())
        }
    }
    impl Inputs {
        fn open() -> anyhow::Result<Self> {
            let access = Access::open()?;
            let a = Payload::open(
                PathBuf::from(env("SMOKE_CW_RELEASE_A")?),
                &env("SMOKE_CW_SHA256_A")?,
            )?;
            let b = Payload::open(
                PathBuf::from(env("SMOKE_CW_RELEASE_B")?),
                &env("SMOKE_CW_SHA256_B")?,
            )?;
            ensure!(
                a.identity.sha256 != b.identity.sha256,
                "A and B must have distinct admitted bytes"
            );
            let witness_sha256 = env("SMOKE_CW_INPUT_WITNESS_SHA256")?;
            sha256(&witness_sha256)?;
            let mut witness = Held::open(
                &PathBuf::from(env("SMOKE_CW_INPUT_WITNESS_FILE")?),
                MAX_JSON as u64,
            )?;
            ensure!(
                witness.stamp.uid == rustix::process::geteuid().as_raw()
                    && witness.stamp.mode & 0o777 == 0o400,
                "input witness is not owned mode0400"
            );
            let bytes = witness.bytes(MAX_JSON)?;
            let decoded = admit_witness(
                &bytes,
                &witness_sha256,
                &a.directory,
                &a.identity,
                &b.directory,
                &b.identity,
            )?;
            let support = Payload::open(
                decoded.support_cw.release_dir.clone(),
                &decoded.support_cw.identity.sha256,
            )?;
            ensure!(
                support.identity == decoded.support_cw.identity,
                "support-CI payload differs from pinned producer identity"
            );
            // The owning producer authenticates source/build references; this
            // consumer additionally checks every original descriptor and exact
            // payload. A manifest is never treated as a successful producer.
            let mut references = Vec::new();
            for entry in [&decoded.support_cw, &decoded.release_a, &decoded.release_b] {
                for (descriptor, maximum) in [
                    (&entry.build_receipt, 1024 * 1024_u64),
                    (&entry.producer_receipt, 1024 * 1024),
                    (&entry.image, 1024 * 1024 * 1024),
                ] {
                    sha256(&descriptor.sha256)?;
                    let mut held = Held::open(&descriptor.path, maximum)?;
                    ensure!(
                        held.stamp.size == descriptor.size && held.hash()? == descriptor.sha256,
                        "original producer/receipt/archive descriptor differs"
                    );
                    references.push(held);
                }
            }
            Ok(Self {
                access,
                support,
                a,
                b,
                witness,
                witness_sha256,
                references,
            })
        }
        fn recheck(&self) -> anyhow::Result<()> {
            self.access.recheck()?;
            self.support.recheck()?;
            self.a.recheck()?;
            self.b.recheck()?;
            self.witness.recheck()?;
            for held in &self.references {
                held.recheck()?;
            }
            Ok(())
        }
        async fn cli_json<T: serde::de::DeserializeOwned>(
            &self,
            args: &[&str],
        ) -> anyhow::Result<T> {
            self.access.cli_json(args, &|| self.recheck()).await
        }
    }
    impl Access {
        fn client(&self) -> anyhow::Result<CodewireClient> {
            let config = ClientConfig::new(&self.base)?
                .with_user_agent("codewire-platform-cw-runtime-smoke/1")?;
            let token = StaticTokenProvider::new(self.token.clone())?;
            if let Some(ca) = &self.ca {
                let http = reqwest::Client::builder()
                    .add_root_certificate(reqwest::Certificate::from_pem(ca)?)
                    .build()?;
                Ok(CodewireClient::with_http(config, token, http)?)
            } else {
                Ok(CodewireClient::new(config, token)?)
            }
        }
        /// Run the pinned CLI once; `recheck` admits every held input before
        /// and after it.
        async fn cli_json<T: serde::de::DeserializeOwned>(
            &self,
            args: &[&str],
            recheck: &(dyn Fn() -> anyhow::Result<()> + Sync),
        ) -> anyhow::Result<T> {
            recheck()?;
            let mut command = tokio::process::Command::new(&self.cli.path);
            command
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &self.home)
                .env("XDG_CONFIG_HOME", self.home.join("config"))
                .env("XDG_DATA_HOME", self.home.join("data"))
                .env("XDG_CACHE_HOME", self.home.join("cache"))
                .env("CW_CONFIG_DIR", self.home.join("cw"))
                .env("CODEWIRE_SERVER_URL", &self.base)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            let mut child = command
                .spawn()
                .context("spawn the pinned original public CLI")?;
            let mut stdout = child.stdout.take().unwrap();
            let mut stderr = child.stderr.take().unwrap();
            let result = tokio::time::timeout(COMMAND_BUDGET, async {
                let (out, _diagnostic) = tokio::try_join!(
                    bounded_pipe(&mut stdout, MAX_JSON),
                    bounded_pipe(&mut stderr, 4096)
                )?;
                let status = child.wait().await?;
                ensure!(
                    status.success(),
                    "public runtime command failed; observe its SAME request UUID"
                );
                let decoded = serde_json::from_slice(&out)
                    .context("public CLI omitted its typed JSON receipt")?;
                recheck()?;
                Ok::<_, anyhow::Error>(decoded)
            })
            .await;
            match result {
                Ok(Ok(result)) => Ok(result),
                Ok(Err(_)) | Err(_) => {
                    // A bounded-pipe refusal can happen before child.wait(),
                    // so timeout is not the only branch requiring exact-child
                    // reap. The outer c0 still owns complete family custody.
                    let _ = child.kill().await;
                    ensure!(
                        tokio::time::timeout(READ_BUDGET, child.wait())
                            .await
                            .is_ok_and(|r| r.is_ok()),
                        "public CLI child closure is unknown; preserve SAME request UUID"
                    );
                    anyhow::bail!(
                        "public runtime command failed; preserve and observe its SAME request UUID"
                    )
                }
            }
        }
    }
    struct InputJournal {
        path: PathBuf,
        file: File,
        directory: File,
        stamp: Stamp,
        bytes: usize,
    }
    impl InputJournal {
        fn create(home: &Path, nonce: &str) -> anyhow::Result<Self> {
            ensure!(hex(nonce, 32), "request journal nonce is invalid");
            let directory: File = rustix::fs::open(
                home,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?
            .into();
            let info = Stamp::of(&directory)?;
            ensure!(
                info.uid == rustix::process::geteuid().as_raw() && info.mode & 0o7777 == 0o700,
                "request journal parent is not owner-private"
            );
            let path = home.join(format!("cw-runtime-requests-{nonce}.jsonl"));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags((OFlags::NOFOLLOW | OFlags::CLOEXEC).bits() as i32)
                .open(&path)?;
            let stamp = Stamp::of(&file)?;
            ensure!(
                stamp.uid == info.uid && stamp.mode & 0o7777 == 0o600 && stamp.links == 1,
                "request journal file is unsafe"
            );
            file.sync_all()?;
            directory.sync_all()?;
            Ok(Self {
                path,
                file,
                directory,
                stamp,
                bytes: 0,
            })
        }
        fn append<T: Serialize>(&mut self, value: &T) -> anyhow::Result<()> {
            let bytes = canonical_json(value)?;
            ensure!(
                self.bytes + bytes.len() <= MAX_JOURNAL_BYTES,
                "original request journal exceeded its bound"
            );
            let current = Stamp::of(&self.file)?;
            ensure!(
                current.device == self.stamp.device
                    && current.inode == self.stamp.inode
                    && current.uid == self.stamp.uid
                    && current.mode == self.stamp.mode
                    && current.links == 1
                    && current.size == self.bytes as u64,
                "request journal custody changed"
            );
            let named: File = rustix::fs::open(
                &self.path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?
            .into();
            ensure!(
                Stamp::of(&named)? == current,
                "request journal name changed"
            );
            self.file.write_all(&bytes)?;
            self.file.sync_all()?;
            self.directory.sync_all()?;
            self.bytes += bytes.len();
            Ok(())
        }
        fn request(
            &mut self,
            id: &str,
            action: &str,
            generation: u64,
            incarnation: &EnvironmentCwRuntimeIncarnation,
            session: &EnvironmentSession,
            identity: &CwPayloadIdentity,
        ) -> anyhow::Result<()> {
            uuid(id)?;
            self.append(
                &serde_json::json!({"schema_version":1,"event":"before-send",
                "request_id":id,"action":action,"expected_generation":generation,
                "incarnation":incarnation,"session_id":session.session_id,
                "launch_generation":session.launch_generation,"identity":identity}),
            )
        }
        fn acknowledged(
            &mut self,
            operation: &EnvironmentCwRuntimeOperation,
        ) -> anyhow::Result<()> {
            self.append(&serde_json::json!({"schema_version":1,"event":"acknowledged","operation":operation}))
        }
    }
    async fn bounded_pipe(
        input: &mut (impl tokio::io::AsyncRead + Unpin),
        maximum: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        input
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(bytes.len() <= maximum, "public CLI pipe exceeded its bound");
        Ok(bytes)
    }
    fn validate_source(source: &Source) -> anyhow::Result<()> {
        ensure!(
            hex(&source.revision, 40)
                && hex(&source.git_tree, 40)
                && hex(&source.source_tree_sha256, 64)
                && hex(&source.index_sha256, 64)
                && (1..=100_000).contains(&source.object_count),
            "unsupported source capsule identity"
        );
        Ok(())
    }
    fn admit_witness(
        bytes: &[u8],
        pin: &str,
        a_dir: &Path,
        a: &CwPayloadIdentity,
        b_dir: &Path,
        b: &CwPayloadIdentity,
    ) -> anyhow::Result<Witness> {
        sha256(pin)?;
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_JSON && hex_digest(bytes) == pin,
            "input witness differs from its external pin"
        );
        let decoded: Witness = serde_json::from_slice(bytes)
            .context("input witness has unknown or malformed fields")?;
        ensure!(
            canonical_json(&decoded)? == bytes,
            "input witness is not canonical"
        );
        ensure!(
            decoded.schema_version == 1 && hex(&decoded.source_sha, 40),
            "unsupported input witness"
        );
        validate_source(&decoded.current_source)?;
        ensure!(
            decoded.current_source.revision == decoded.source_sha,
            "witness source/head differ"
        );
        ensure!(
            a.sha256 != b.sha256 && a.package_version != b.package_version,
            "journey requires distinct A/B payloads and effective versions"
        );
        for (entry, directory, identity) in [
            (&decoded.release_a, a_dir, a),
            (&decoded.release_b, b_dir, b),
        ] {
            identity.validate()?;
            validate_source(&entry.compilation_source)?;
            ensure!(
                entry.release_dir == directory
                    && entry.identity == *identity
                    && entry.profile == "release"
                    && entry.version == identity.package_version
                    && entry.compilation_source.revision == identity.source_revision
                    && entry.compilation_source.source_tree_sha256 == identity.source_tree_sha256
                    && entry.compilation_source == decoded.current_source
                    && !entry.build_ref.is_empty()
                    && entry.build_ref.len() <= 2048
                    && entry.build_ref.bytes().all(|b| b.is_ascii_graphic()),
                "producer input/identity binding differs"
            );
            sha256(&entry.index_sha256)?;
        }
        let support = &decoded.support_cw;
        support.identity.validate()?;
        validate_source(&support.compilation_source)?;
        ensure!(
            support.profile == "ci"
                && support.version == support.identity.package_version
                && support.identity.target == "x86_64-unknown-linux-musl"
                && support.compilation_source == decoded.current_source
                && support.compilation_source.revision == support.identity.source_revision
                && support.compilation_source.source_tree_sha256
                    == support.identity.source_tree_sha256
                && !support.build_ref.is_empty()
                && support.build_ref.len() <= 2048
                && support.build_ref.bytes().all(|b| b.is_ascii_graphic()),
            "support-CI producer binding differs"
        );
        sha256(&support.index_sha256)?;
        Ok(decoded)
    }
    fn env(name: &str) -> anyhow::Result<String> {
        std::env::var(name).with_context(|| format!("required synthetic input {name} is absent"))
    }
    fn hex(value: &str, length: usize) -> bool {
        value.len() == length
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn sha256(value: &str) -> anyhow::Result<()> {
        ensure!(hex(value, 64), "invalid SHA256 pin");
        Ok(())
    }
    fn uuid(value: &str) -> anyhow::Result<()> {
        ensure!(
            Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value),
            "UUID is not canonical nonnil"
        );
        Ok(())
    }
    fn session_id(value: &str) -> anyhow::Result<()> {
        uuid(
            value
                .strip_prefix("session-")
                .context("session identity is not canonical")?,
        )
    }
    fn hex_digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    fn proto_identity(identity: &CwPayloadIdentity) -> EnvironmentCwRuntimeIdentity {
        EnvironmentCwRuntimeIdentity {
            schema_version: identity.schema_version,
            protocol_version: identity.protocol_version,
            record_version: identity.record_version,
            package_version: identity.package_version.clone(),
            target: identity.target.clone(),
            source_revision: identity.source_revision.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            rustc: identity.rustc.clone(),
            sha256: identity.sha256.clone(),
            size: identity.size,
            ..Default::default()
        }
    }
    fn payload_identity(
        identity: &EnvironmentCwRuntimeIdentity,
    ) -> anyhow::Result<CwPayloadIdentity> {
        ensure!(
            identity.__buffa_unknown_fields.is_empty(),
            "unknown payload identity fields"
        );
        let result = CwPayloadIdentity {
            schema_version: identity.schema_version,
            protocol_version: identity.protocol_version,
            record_version: identity.record_version,
            package_version: identity.package_version.clone(),
            target: identity.target.clone(),
            source_revision: identity.source_revision.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            rustc: identity.rustc.clone(),
            sha256: identity.sha256.clone(),
            size: identity.size,
        };
        result.validate()?;
        ensure!(
            result.target == "x86_64-unknown-linux-musl",
            "original image lacks static-musl role"
        );
        Ok(result)
    }
    fn admit_original_image(
        image: &EnvironmentCwRuntimeIdentity,
        support: &CwPayloadIdentity,
    ) -> anyhow::Result<()> {
        payload_identity(image)?;
        support.validate()?;
        ensure!(
            image == &proto_identity(support),
            "original running daemon differs from the genuine support-CI producer"
        );
        Ok(())
    }
    /// The synthetic provider credential each managed worker kind selects.
    const MANAGED_CREDENTIALS: [(&str, &str, usize); 2] = [
        ("SMOKE_CW_MANAGED_OPENAI_CREDENTIAL", "kind-cw-openai-", 1),
        (
            "SMOKE_CW_MANAGED_ANTHROPIC_CREDENTIAL",
            "kind-cw-anthropic-",
            2,
        ),
    ];

    fn managed_credential(variable: &str, prefix: &str) -> anyhow::Result<String> {
        let name = env(variable)?;
        ensure!(
            name.starts_with(prefix)
                && name.len() <= 100
                && name[prefix.len()..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'-'),
            "managed fixture credential name is outside the owned synthetic namespace"
        );
        Ok(name)
    }

    /// The managed-agent journey without the ordinary CW A/B/A update, for a
    /// retained Kind cluster (`make kind-test SUITES=cw-managed-agents`). It
    /// runs against whatever daemon image the environment's Pod reports, so it
    /// admits no release producers and claims no CW update: launch, steer and
    /// interrupt, revoked-provider denial, known-clean Stop, explicit Restart.
    async fn managed_only() -> anyhow::Result<()> {
        let access = Access::open().context("admit the managed journey inputs")?;
        let client = access
            .client()
            .context("configure the synthetic public client")?;
        let initial = status(&client, &access).await?;
        let original = initial
            .incarnation
            .as_option()
            .context("runtime status omitted the Pod incarnation")?
            .clone();
        let image = initial
            .bootstrap_identity
            .as_option()
            .context("runtime status omitted the daemon image identity")?
            .clone();
        tokio::time::timeout(JOURNEY_BUDGET, async {
            let mut journey = super::platform_managed::Journey::launch(
                &client,
                &access.org,
                &access.environment,
                &original,
                &image,
            )
            .await?;
            journey.validate_scope(&original, &image)?;
            journey.begin_continuity(&client).await?;
            journey.checkpoint(&client, "managed-only").await?;
            journey.controls(&client).await?;
            for (variable, prefix, worker) in MANAGED_CREDENTIALS {
                let name = managed_credential(variable, prefix)?;
                access
                    .cli_json::<serde_json::Value>(
                        &[
                            "credentials",
                            "--platform",
                            "revoke",
                            &name,
                            "--output",
                            "json",
                        ],
                        &|| access.recheck(),
                    )
                    .await
                    .context("revoke the exact selected synthetic provider credential")?;
                journey.revoked(&client, worker).await?;
            }
            journey.stop(&client).await?;
            let reconnected = access.client()?;
            journey.restart(&client, &reconnected).await?;
            access.recheck()?;
            ensure!(
                status(&client, &access).await?.incarnation.as_option() == Some(&original),
                "the managed journey changed the environment's Pod incarnation"
            );
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "schema_version": 1, "outcome": "passed", "environment_id": access.environment,
                    "incarnation": original, "daemon_image": image,
                    "managed_agents_qualified": true, "managed_only": true,
                    "not_claimed": ["ordinary_CW_A_B_A", "admitted_release_producers",
                        "original_kernel_processes", "live_providers"]
                }))?
            );
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("bounded managed journey expired")?
    }

    async fn status(
        client: &CodewireClient,
        inputs: &Access,
    ) -> anyhow::Result<GetEnvironmentCwRuntimeResponse> {
        client
            .get_environment_cw_runtime(GetEnvironmentCwRuntimeRequest {
                org_id: inputs.org.clone(),
                environment_id: inputs.environment.clone(),
                ..Default::default()
            })
            .await
            .context("read current authenticated runtime status")
    }
    fn validate_status(
        info: &GetEnvironmentCwRuntimeResponse,
        inputs: &Inputs,
        original: Option<&EnvironmentCwRuntimeIncarnation>,
    ) -> anyhow::Result<()> {
        ensure!(
            info.__buffa_unknown_fields.is_empty() && info.supported_image,
            "image role is unavailable"
        );
        let inc = info
            .incarnation
            .as_option()
            .context("status omitted original incarnation")?;
        ensure!(
            inc.__buffa_unknown_fields.is_empty()
                && inc.org_id == inputs.org
                && inc.environment_id == inputs.environment
                && inc.environment_generation > 0
                && inc.binding_generation > 0
                && inc.binding_bound_at.as_option().is_some()
                && !inc.namespace.is_empty()
                && !inc.pod_name.is_empty(),
            "status scope/binding is incomplete"
        );
        for id in [
            &inc.environment_id,
            &inc.pod_uid,
            &inc.claim_uid,
            &inc.sandbox_uid,
        ] {
            uuid(id)?;
        }
        if let Some(id) = &inc.workspace_pvc_uid {
            uuid(id)?;
        }
        if let Some(pin) = &inc.projection_selection_sha256 {
            sha256(pin)?;
        }
        if let Some(old) = original {
            ensure!(
                inc == old,
                "original Pod/binding/environment incarnation changed"
            );
        }
        payload_identity(
            info.bootstrap_identity
                .as_option()
                .context("original image identity unavailable")?,
        )?;
        let selection = info
            .selection
            .as_option()
            .context("status omitted Store selection")?;
        ensure!(
            selection.__buffa_unknown_fields.is_empty()
                && !selection.pending
                && selection.consistent
                && (selection.generation == 0) == selection.current.as_option().is_none(),
            "Store is uncertain/inconsistent"
        );
        for id in [
            selection.current.as_option(),
            selection.previous.as_option(),
        ]
        .into_iter()
        .flatten()
        {
            payload_identity(id)?;
        }
        Ok(())
    }
    fn expectation(selection: &EnvironmentCwRuntimeSelection) -> EnvironmentCwRuntimeExpectation {
        EnvironmentCwRuntimeExpectation {
            generation: selection.generation,
            current_sha256: selection.current.as_option().map(|v| v.sha256.clone()),
            previous_sha256: selection.previous.as_option().map(|v| v.sha256.clone()),
            ..Default::default()
        }
    }
    fn validate_operation(
        operation: &EnvironmentCwRuntimeOperation,
        request: &str,
        action: &str,
        original: &EnvironmentCwRuntimeIncarnation,
        before: &GetEnvironmentCwRuntimeResponse,
        target: &CwPayloadIdentity,
    ) -> anyhow::Result<()> {
        ensure!(
            operation.__buffa_unknown_fields.is_empty()
                && operation.request_id == request
                && operation.incarnation.as_option() == Some(original)
                && operation.action == action
                && operation.phase == "succeeded"
                && operation.issued_effect.as_deref() == Some("cleanup")
                && operation.error_code.is_none()
                && operation.admitted_at.as_option().is_some()
                && operation.issued_at.as_option().is_some()
                && operation.terminal_at.as_option().is_some()
                && operation.expected_selection.as_option()
                    == Some(&expectation(before.selection.as_option().unwrap()))
                && operation.identity.as_option() == Some(&proto_identity(target)),
            "operation is not the acknowledged original request/incarnation/identity"
        );
        let bootstrap = action == "update" && before.selection.as_option().unwrap().generation == 0;
        ensure!(
            operation.bootstrap_identity.as_option()
                == if bootstrap {
                    before.bootstrap_identity.as_option()
                } else {
                    None
                },
            "operation changed original bootstrap identity"
        );
        let expected: Vec<&str> = if bootstrap {
            vec!["bootstrap", "staging", "update", "cleanup"]
        } else if action == "update" {
            vec!["staging", "update", "cleanup"]
        } else {
            vec!["rollback", "cleanup"]
        };
        ensure!(
            operation.checkpoint as usize == expected.len()
                && operation.acknowledgements.len() == expected.len(),
            "operation omitted an issued effect acknowledgement"
        );
        let mut current = expectation(before.selection.as_option().unwrap());
        for (index, (ack, effect)) in operation.acknowledgements.iter().zip(expected).enumerate() {
            ensure!(
                ack.__buffa_unknown_fields.is_empty()
                    && ack.checkpoint as usize == index + 1
                    && ack.effect == effect,
                "acknowledgement order/identity changed"
            );
            match (&ack.receipt, effect) {
                (
                    Some(environment_cw_runtime_acknowledgement::Receipt::Staged(value)),
                    "staging",
                ) => {
                    ensure!(
                        value.__buffa_unknown_fields.is_empty()
                            && value.sha256 == target.sha256
                            && value.size == target.size,
                        "staging receipt differs from admitted bytes"
                    );
                }
                (
                    Some(environment_cw_runtime_acknowledgement::Receipt::Selected(value)),
                    "bootstrap" | "update" | "rollback",
                ) => {
                    let pin = if effect == "bootstrap" {
                        &before.bootstrap_identity.as_option().unwrap().sha256
                    } else {
                        &target.sha256
                    };
                    let changed = current.current_sha256.as_deref() != Some(pin);
                    let generation = if changed {
                        current
                            .generation
                            .checked_add(1)
                            .context("generation exhausted")?
                    } else {
                        current.generation
                    };
                    let previous = if changed {
                        current.current_sha256.clone()
                    } else {
                        current.previous_sha256.clone()
                    };
                    ensure!(
                        value.__buffa_unknown_fields.is_empty()
                            && value.sha256 == *pin
                            && value.changed == changed
                            && value.generation == generation
                            && value.previous_sha256 == previous,
                        "selection receipt violates exact observed CAS"
                    );
                    current = EnvironmentCwRuntimeExpectation {
                        generation,
                        current_sha256: Some(pin.clone()),
                        previous_sha256: previous,
                        ..Default::default()
                    };
                }
                (
                    Some(environment_cw_runtime_acknowledgement::Receipt::Cleaned(value)),
                    "cleanup",
                ) => {
                    ensure!(
                        value.__buffa_unknown_fields.is_empty(),
                        "unknown cleanup receipt"
                    );
                }
                _ => anyhow::bail!("effect receipt has the wrong typed body"),
            }
        }
        Ok(())
    }
    fn selected(
        info: &GetEnvironmentCwRuntimeResponse,
        target: &CwPayloadIdentity,
        operation: &EnvironmentCwRuntimeOperation,
    ) -> anyhow::Result<()> {
        let final_ack = operation
            .acknowledgements
            .iter()
            .filter_map(|ack| match &ack.receipt {
                Some(environment_cw_runtime_acknowledgement::Receipt::Selected(value)) => {
                    Some(value)
                }
                _ => None,
            })
            .next_back()
            .context("operation has no selected receipt")?;
        let selection = info.selection.as_option().unwrap();
        ensure!(
            selection.current.as_option() == Some(&proto_identity(target))
                && selection.generation == final_ack.generation
                && selection.previous.as_option().map(|v| v.sha256.as_str())
                    == final_ack.previous_sha256.as_deref()
                && selection.retained_count >= 1,
            "live Store differs from the exact acknowledged selection"
        );
        Ok(())
    }
    async fn observe_twice(
        client: &CodewireClient,
        inputs: &Inputs,
        operation: &EnvironmentCwRuntimeOperation,
    ) -> anyhow::Result<()> {
        for _ in 0..2 {
            let observed = client
                .observe_environment_cw_runtime(ObserveEnvironmentCwRuntimeRequest {
                    org_id: inputs.org.clone(),
                    environment_id: inputs.environment.clone(),
                    request_id: operation.request_id.clone(),
                    ..Default::default()
                })
                .await
                .context("observe SAME original request without reissue")?;
            ensure!(
                observed.__buffa_unknown_fields.is_empty()
                    && observed.operation.as_option() == Some(operation),
                "saved original operation metadata changed"
            );
        }
        let printed: EnvironmentCwRuntimeOperation = inputs
            .cli_json(&[
                "env",
                "--platform",
                "runtime",
                "observe",
                &inputs.environment,
                "--request-id",
                &operation.request_id,
                "--output",
                "json",
            ])
            .await?;
        ensure!(
            printed == *operation,
            "public CLI Observe changed the original operation"
        );
        Ok(())
    }
    async fn absent_operation(
        client: &CodewireClient,
        inputs: &Inputs,
        request: &str,
    ) -> anyhow::Result<()> {
        let error = client
            .observe_environment_cw_runtime(ObserveEnvironmentCwRuntimeRequest {
                org_id: inputs.org.clone(),
                environment_id: inputs.environment.clone(),
                request_id: request.into(),
                ..Default::default()
            })
            .await
            .err()
            .context("refused intake unexpectedly admitted a journal row")?;
        ensure!(
            error.code() == ErrorCode::NotFound,
            "refused operation absence was not established"
        );
        Ok(())
    }
    async fn refusal_cases(
        client: &CodewireClient,
        inputs: &Inputs,
        current: &GetEnvironmentCwRuntimeResponse,
        session: &EnvironmentSession,
        journal: &mut InputJournal,
        submitted: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        for corrupt in [false, true] {
            let request = Uuid::new_v4().to_string();
            let mut incarnation = current.incarnation.as_option().unwrap().clone();
            if !corrupt {
                incarnation.pod_uid = Uuid::new_v4().to_string();
            }
            journal.request(
                &request,
                if corrupt {
                    "refusal-corrupt-bytes"
                } else {
                    "refusal-stale-incarnation"
                },
                current.selection.as_option().unwrap().generation,
                &incarnation,
                session,
                &inputs.b.identity,
            )?;
            submitted.push(request.clone());
            let result = client
                .update_environment_cw_runtime(
                    UpdateEnvironmentCwRuntimeHeader {
                        org_id: inputs.org.clone(),
                        environment_id: inputs.environment.clone(),
                        request_id: request.clone(),
                        expected_incarnation: Some(incarnation).into(),
                        expected_selection: Some(expectation(
                            current.selection.as_option().unwrap(),
                        ))
                        .into(),
                        identity: Some(proto_identity(&inputs.b.identity)).into(),
                        ..Default::default()
                    },
                    inputs.b.chunks(corrupt)?,
                )
                .await;
            let error = result
                .err()
                .context("stale incarnation/corrupt payload was admitted")?;
            ensure!(
                matches!(
                    error.source.code(),
                    ErrorCode::FailedPrecondition | ErrorCode::InvalidArgument
                ),
                "refusal did not prove an admission rejection"
            );
            absent_operation(client, inputs, &request).await?;
            ensure!(
                status(client, inputs).await? == *current,
                "refused typed intake changed live runtime"
            );
        }
        Ok(())
    }
    async fn get_session(
        client: &CodewireClient,
        inputs: &Inputs,
        id: &str,
    ) -> anyhow::Result<EnvironmentSession> {
        client
            .get_session(GetSessionRequest {
                org_id: inputs.org.clone(),
                environment_id: inputs.environment.clone(),
                session_id: id.into(),
                ..Default::default()
            })
            .await
            .context("read the original session")?
            .session
            .into_option()
            .context("GetSession omitted original session")
    }
    fn validate_session(
        view: &EnvironmentSession,
        original: &EnvironmentSession,
        terminal: bool,
    ) -> anyhow::Result<()> {
        ensure!(
            view.__buffa_unknown_fields.is_empty()
                && view.session_id == original.session_id
                && view.launch_generation == original.launch_generation
                && view.launch_generation > 0
                && view.command == original.command
                && view.working_dir == original.working_dir
                && view.name == original.name
                && view.parent_session_id == original.parent_session_id
                && view.created_at == original.created_at
                && !view.pty
                && !view.cleanup_unknown
                && view.output_start_offset == 0,
            "original durable session identity/history changed"
        );
        if original.started_at.as_option().is_some() {
            ensure!(
                view.started_at == original.started_at,
                "original session restarted"
            );
        }
        if terminal {
            ensure!(
                view.state.as_known() == Some(EnvironmentSessionState::Exited)
                    && view.exit_code == Some(0)
                    && view.finished_at.as_option().is_some(),
                "observer did not exit normally"
            );
        } else {
            ensure!(
                view.state.as_known() == Some(EnvironmentSessionState::Running)
                    && view.exit_code.is_none()
                    && view.finished_at.as_option().is_none(),
                "original session left Running"
            );
        }
        Ok(())
    }
    async fn unchanged(
        client: &CodewireClient,
        inputs: &Inputs,
        current: &GetEnvironmentCwRuntimeResponse,
        session: &EnvironmentSession,
        reader: &tokio::task::JoinHandle<anyhow::Result<Vec<u8>>>,
    ) -> anyhow::Result<()> {
        inputs.recheck()?;
        ensure!(
            !reader.is_finished(),
            "the sole original attachment ended prematurely"
        );
        let now = status(client, inputs).await?;
        ensure!(
            now == *current,
            "current status/incarnation changed without an acknowledged request"
        );
        validate_session(
            &get_session(client, inputs, &session.session_id).await?,
            session,
            false,
        )
    }
    async fn send(
        client: &CodewireClient,
        inputs: &Inputs,
        id: &str,
        data: Vec<u8>,
    ) -> anyhow::Result<()> {
        client
            .send_session_input(SendSessionInputRequest {
                org_id: inputs.org.clone(),
                environment_id: inputs.environment.clone(),
                session_id: id.into(),
                data,
                ..Default::default()
            })
            .await
            .context("acknowledge exact original observer control input")?;
        Ok(())
    }
    async fn checkpoint(
        client: &CodewireClient,
        inputs: &Inputs,
        session: &EnvironmentSession,
        phase: &str,
        payload: &Payload,
    ) -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec(&serde_json::json!({"op":"checkpoint","phase":phase,
            "sha256":payload.identity.sha256,"size":payload.identity.size,"version":payload.identity.package_version}))?;
        bytes.push(b'\n');
        send(client, inputs, &session.session_id, bytes).await
    }

    #[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Actor {
        pid: u32,
        parent_pid: u32,
        start_ticks: u64,
        executable: String,
        device: u64,
        inode: u64,
        size: u64,
        sha256: String,
        uid: u32,
        gid: u32,
        mode: u32,
        links: u64,
    }
    #[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Actors {
        supervisor: Actor,
        daemon: Actor,
        session: Actor,
        shell: Actor,
    }
    #[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct Selection {
        logical_path: String,
        resolved_path: String,
        sha256: String,
        size: u64,
        version: String,
    }
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct Evidence {
        path: String,
        sha256: String,
        bytes: u64,
    }
    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct ProbeEvent {
        schema_version: u32,
        event: String,
        phase: String,
        nonce: String,
        environment_id: String,
        sequence: u32,
        samples: u64,
        boot_id: String,
        uid: u32,
        gid: u32,
        actors: Actors,
        #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
        managed: std::collections::BTreeMap<String, Actor>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        managed_terminal: bool,
        selection: Option<Selection>,
        shell_terminal: bool,
        evidence: Evidence,
    }
    struct OriginalImages<'a> {
        support: &'a EnvironmentCwRuntimeIdentity,
        workspace: &'a CwPayloadIdentity,
    }
    fn validate_probe(
        event: &ProbeEvent,
        sequence: u32,
        kind: &str,
        phase: &str,
        payload: Option<&CwPayloadIdentity>,
        images: &OriginalImages<'_>,
        baseline: Option<&ProbeEvent>,
    ) -> anyhow::Result<()> {
        let image = images.support;
        ensure!(
            event.schema_version == 1
                && event.sequence == sequence
                && event.event == kind
                && event.phase == phase
                && event.uid == 1000
                && event.gid == 1000
                && event.samples > 0
                && event.shell_terminal == (kind == "closed"),
            "observer phase/custody is incomplete"
        );
        uuid(&event.boot_id)?;
        ensure!(
            matches!(event.managed.len(), 0 | 9),
            "managed kernel actor inventory is incomplete"
        );
        ensure!(
            event.managed_terminal
                == (!event.managed.is_empty() && matches!(kind, "managed-stopped" | "closed")),
            "managed kernel terminal custody differs from the admitted Stop phase"
        );
        if let Some(baseline) = baseline {
            ensure!(
                event.managed == baseline.managed,
                "managed original kernel process identity changed"
            );
        }
        for index in 0..event.managed.len() / 3 {
            let driver = event
                .managed
                .get(&format!("managed{index}-driver"))
                .context("managed original driver actor is missing")?;
            let guardian = event
                .managed
                .get(&format!("managed{index}-guardian"))
                .context("managed original guardian actor is missing")?;
            let provider = event
                .managed
                .get(&format!("managed{index}-provider"))
                .context("managed original provider actor is missing")?;
            ensure!(
                driver.parent_pid == event.actors.daemon.pid
                    && guardian.parent_pid == driver.pid
                    && provider.parent_pid == guardian.pid
                    && driver.sha256 == image.sha256
                    && guardian.sha256 == image.sha256
                    && driver.size == image.size
                    && guardian.size == image.size,
                "managed original driver/guardian/provider lineage differs"
            );
            for actor in [driver, guardian, provider] {
                ensure!(
                    actor.pid > 0
                        && actor.start_ticks > 0
                        && matches!(actor.uid, 0 | 1000)
                        && matches!(actor.gid, 0 | 1000)
                        && actor.inode > 0
                        && actor.links == 1
                        && actor.mode & 0o170000 == 0o100000
                        && actor.mode & 0o6022 == 0
                        && actor.mode & 0o111 != 0
                        && (1..=512 * 1024 * 1024).contains(&actor.size),
                    "managed actor birth/executable identity is incomplete"
                );
                sha256(&actor.sha256)?;
            }
        }
        let actors = [
            &event.actors.supervisor,
            &event.actors.daemon,
            &event.actors.session,
            &event.actors.shell,
        ];
        for actor in actors {
            ensure!(
                actor.pid > 0
                    && actor.start_ticks > 0
                    && (1..=MAX_EXECUTABLE_BYTES).contains(&actor.size)
                    && matches!(actor.uid, 0 | 1000)
                    && matches!(actor.gid, 0 | 1000)
                    && actor.inode > 0
                    && actor.links == 1
                    && actor.mode & 0o170000 == 0o100000
                    && actor.mode & 0o6022 == 0
                    && actor.mode & 0o111 != 0
                    && actor.executable.starts_with('/')
                    && actor.executable.len() <= 4096
                    && !actor.executable.chars().any(char::is_control),
                "observer actor kernel identity is incomplete"
            );
            sha256(&actor.sha256)?;
        }
        ensure!(
            event.actors.supervisor.pid == 1
                && event.actors.daemon.parent_pid == event.actors.supervisor.pid
                && event.actors.session.parent_pid == event.actors.daemon.pid
                && event.actors.shell.parent_pid == event.actors.session.pid
                && event.actors.daemon.executable == "/codewire/bin/cw"
                && event.actors.daemon.sha256 == image.sha256
                && event.actors.daemon.size == image.size,
            "observer original daemon/family binding differs"
        );
        if let Some(before) = baseline {
            ensure!(
                event.actors == before.actors
                    && event.boot_id == before.boot_id
                    && event.nonce == before.nonce
                    && event.environment_id == before.environment_id
                    && event.samples > before.samples,
                "original held process images/birth changed"
            );
        }
        match (payload, &event.selection) {
            (None, Some(selected)) => {
                let (checksum, size, version) = match selected.logical_path.as_str() {
                    "/usr/local/bin/cw" => (
                        images.workspace.sha256.as_str(),
                        images.workspace.size,
                        images.workspace.package_version.as_str(),
                    ),
                    "/codewire/bin/cw" => (
                        image.sha256.as_str(),
                        image.size,
                        image.package_version.as_str(),
                    ),
                    _ => anyhow::bail!("prebootstrap cached image path differs"),
                };
                ensure!(
                    sequence == 0
                        && kind == "ready"
                        && phase == "baseline"
                        && matches!(
                            selected.logical_path.as_str(),
                            "/usr/local/bin/cw" | "/codewire/bin/cw"
                        )
                        && selected.resolved_path == selected.logical_path
                        && selected.sha256 == checksum
                        && selected.size == size
                        && selected.version == version,
                    "prebootstrap cached image CW differs"
                );
            }
            (Some(payload), Some(selected)) => {
                ensure!(
                    selected.logical_path
                        == baseline
                            .and_then(|before| before.selection.as_ref())
                            .context("prebootstrap image cache was not observed")?
                            .logical_path
                        && selected.resolved_path
                            == format!("{STORE}/versions/{}/cw", payload.sha256)
                        && selected.sha256 == payload.sha256
                        && selected.size == payload.size
                        && selected.version == payload.package_version,
                    "same-shell CW selection differs"
                );
            }
            _ => anyhow::bail!("observer selection has the wrong phase"),
        }
        ensure!(
            event.evidence.path
                == format!(
                    "/home/codewire/.local/state/codewire/cw-runtime-proof/{}/{sequence:03}-{kind}.json",
                    event.nonce
                )
                && event.evidence.bytes > 0
                && event.evidence.bytes <= MAX_LINE as u64,
            "observer evidence path/size is not bounded"
        );
        sha256(&event.evidence.sha256)?;
        let mut value = serde_json::to_value(event)?;
        value.as_object_mut().unwrap().remove("evidence");
        let body = canonical_json(&value)?;
        ensure!(
            body.len() as u64 == event.evidence.bytes && hex_digest(&body) == event.evidence.sha256,
            "observer evidence body differs from its closed descriptor"
        );
        Ok(())
    }
    async fn next_event(events: &mut mpsc::Receiver<ProbeEvent>) -> anyhow::Result<ProbeEvent> {
        tokio::time::timeout(READ_BUDGET, events.recv())
            .await
            .context("observer event deadline")?
            .context("original observer/attachment ended without its expected event")
    }
    struct OutputDecoder {
        nonce: String,
        environment: String,
        prefix: String,
        captured: Vec<u8>,
        partial: Vec<u8>,
        sequence: u32,
        managed: bool,
        closed: bool,
    }
    impl OutputDecoder {
        fn new(nonce: &str, environment: &str) -> Self {
            Self {
                nonce: nonce.into(),
                environment: environment.into(),
                prefix: format!("CW_PLATFORM_RUNTIME_PROBE {nonce} "),
                captured: vec![],
                partial: vec![],
                sequence: 0,
                managed: false,
                closed: false,
            }
        }
        fn push(
            &mut self,
            chunk: EnvironmentSessionOutputChunk,
        ) -> anyhow::Result<Vec<ProbeEvent>> {
            ensure!(
                chunk.__buffa_unknown_fields.is_empty()
                    && chunk.offset == self.captured.len() as u64
                    && chunk.next_offset == chunk.offset + chunk.data.len() as u64
                    && !chunk.data.is_empty()
                    && self.captured.len() + chunk.data.len() <= MAX_OUTPUT,
                "original Attach offsets/retention are not lossless"
            );
            ensure!(
                chunk.stream.as_known()
                    == Some(codewire_client::EnvironmentSessionOutputStream::Stdout),
                "fixed observer emitted unexpected stderr/PTY output"
            );
            self.captured.extend_from_slice(&chunk.data);
            self.partial.extend_from_slice(&chunk.data);
            let mut events = Vec::new();
            while let Some(end) = self.partial.iter().position(|&b| b == b'\n') {
                ensure!(end < MAX_LINE, "observer line exceeded its bound");
                let bytes: Vec<u8> = self.partial.drain(..=end).collect();
                let line =
                    std::str::from_utf8(&bytes[..end]).context("observer line is not UTF8")?;
                let json = line
                    .strip_prefix(&self.prefix)
                    .context("fixed observer prefix changed")?;
                let event: ProbeEvent = serde_json::from_str(json)
                    .context("observer refused or emitted an unknown event")?;
                ensure!(
                    canonical_json(&event)? == bytes[self.prefix.len()..],
                    "observer event is not canonical"
                );
                ensure!(
                    event.sequence == self.sequence
                        && event.nonce == self.nonce
                        && event.environment_id == self.environment
                        && self.sequence <= if self.managed { 6 } else { 4 }
                        && !self.closed,
                    "observer replay/order/scope changed"
                );
                if self.sequence == 0 {
                    ensure!(
                        matches!(event.managed.len(), 0 | 9),
                        "observer initial managed inventory is incomplete"
                    );
                    self.managed = !event.managed.is_empty();
                }
                let expected = match self.sequence {
                    0 => "ready",
                    1..=3 => "checkpoint",
                    4 if self.managed => "managed-stop-ready",
                    5 if self.managed => "managed-stopped",
                    _ => "closed",
                };
                ensure!(
                    event.event == expected,
                    "observer skipped or changed the admitted lifecycle phase"
                );
                self.closed = event.event == "closed";
                self.sequence += 1;
                events.push(event);
            }
            ensure!(
                self.partial.len() < MAX_LINE,
                "observer unterminated line exceeded its bound"
            );
            Ok(events)
        }
        fn finish(
            &self,
            view: &EnvironmentSession,
            original: &EnvironmentSession,
        ) -> anyhow::Result<()> {
            ensure!(
                self.closed
                    && self.sequence == if self.managed { 7 } else { 5 }
                    && self.partial.is_empty(),
                "observer terminal preceded closed proof"
            );
            validate_session(view, original, true)?;
            ensure!(
                view.output_end_offset == self.captured.len() as u64,
                "terminal output cursor changed"
            );
            Ok(())
        }
    }
    async fn consume(
        mut attachment: EnvironmentSessionAttachment,
        original: EnvironmentSession,
        nonce: &str,
        environment: &str,
        events: mpsc::Sender<ProbeEvent>,
    ) -> anyhow::Result<Vec<u8>> {
        let mut output = OutputDecoder::new(nonce, environment);
        let mut settled = None;
        loop {
            let response = attachment
                .next_output()
                .await
                .context("original Attach read failed")?
                .context("original Attach EOF preceded terminal status")?;
            ensure!(
                response.__buffa_unknown_fields.is_empty(),
                "unknown attachment fields"
            );
            match response.event {
                Some(attach_session_response::Event::Output(chunk)) => {
                    for event in output.push(*chunk)? {
                        events
                            .send(event)
                            .await
                            .context("observer event consumer ended")?;
                    }
                }
                Some(attach_session_response::Event::Status(status)) => {
                    ensure!(
                        status.__buffa_unknown_fields.is_empty(),
                        "unknown original session status fields"
                    );
                    let view = status
                        .session
                        .into_option()
                        .context("Attach status omitted original session")?;
                    if view.state.as_known() == Some(EnvironmentSessionState::Starting) {
                        ensure!(settled.is_none(), "original session regressed to Starting");
                        ensure!(
                            view.session_id == original.session_id
                                && view.launch_generation == original.launch_generation
                                && !output.closed,
                            "original session changed during Attach"
                        );
                    } else if view.state.as_known() == Some(EnvironmentSessionState::Running) {
                        // Output can precede a final Running status. Closed is
                        // not Exit: keep the same channel and original birth
                        // until normal terminal status plus actual EOF.
                        validate_session(&view, settled.as_ref().unwrap_or(&original), false)?;
                        ensure!(
                            view.started_at.as_option().is_some(),
                            "Attach omitted original session birth"
                        );
                        if settled.is_none() {
                            settled = Some(view);
                        }
                    } else {
                        output.finish(&view, settled.as_ref().unwrap_or(&original))?;
                        ensure!(
                            attachment
                                .next_output()
                                .await
                                .context("original Attach terminal EOF failed")?
                                .is_none(),
                            "original Attach emitted after terminal status"
                        );
                        return Ok(output.captured);
                    }
                }
                _ => anyhow::bail!("original attachment lost history or emitted an empty event"),
            }
        }
    }
    async fn retained_history(
        client: &CodewireClient,
        inputs: &Inputs,
        id: &str,
    ) -> anyhow::Result<Vec<u8>> {
        tokio::time::timeout(HISTORY_BUDGET, async {
            let mut bytes = Vec::new();
            loop {
                let before = bytes.len();
                let response = client
                    .read_session_output(ReadSessionOutputRequest {
                        org_id: inputs.org.clone(),
                        environment_id: inputs.environment.clone(),
                        session_id: id.into(),
                        offset: bytes.len() as u64,
                        limit: 64 * 1024,
                        allow_history_gap: false,
                        ..Default::default()
                    })
                    .await
                    .context("read original retained session output")?;
                ensure!(
                    !response.history_gap
                        && response.retained_start_offset == 0
                        && response.__buffa_unknown_fields.is_empty(),
                    "retained output lost history"
                );
                for chunk in response.chunks {
                    ensure!(
                        chunk.offset == bytes.len() as u64
                            && chunk.next_offset == chunk.offset + chunk.data.len() as u64
                            && bytes.len() + chunk.data.len() <= MAX_OUTPUT
                            && !chunk.data.is_empty()
                            && chunk.__buffa_unknown_fields.is_empty()
                            && chunk.stream.as_known()
                                == Some(codewire_client::EnvironmentSessionOutputStream::Stdout),
                        "retained output cursor/size/stream changed"
                    );
                    bytes.extend(chunk.data);
                }
                ensure!(
                    response.next_offset == bytes.len() as u64,
                    "retained cursor changed"
                );
                if response.eof {
                    return Ok::<_, anyhow::Error>(bytes);
                }
                ensure!(
                    bytes.len() > before,
                    "retained history made no progress after normal Exit"
                );
            }
        })
        .await
        .context("retained history read exceeded its bound")?
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use codewire_proto::codewire::v1::{
            EnvironmentCwRuntimeAcknowledgement, EnvironmentCwRuntimeCleaned,
            EnvironmentCwRuntimeSelected, EnvironmentCwRuntimeStaged,
        };
        use std::fs;
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        const ENVIRONMENT: &str = "550e8400-e29b-41d4-a716-446655440000";
        const NONCE: &str = "0123456789abcdef0123456789abcdef";
        fn identity(letter: char, version: &str) -> CwPayloadIdentity {
            CwPayloadIdentity {
                schema_version: 2,
                protocol_version: 1,
                record_version: 1,
                package_version: version.into(),
                target: "x86_64-unknown-linux-musl".into(),
                source_revision: "d".repeat(40),
                source_tree_sha256: "e".repeat(64),
                rustc: "rustc 1.93.0 (synthetic acceptance test)".into(),
                sha256: letter.to_string().repeat(64),
                size: 512,
            }
        }
        fn binding() -> EnvironmentCwRuntimeIncarnation {
            EnvironmentCwRuntimeIncarnation {
                org_id: "org_contract_1".into(),
                environment_id: ENVIRONMENT.into(),
                environment_generation: 7,
                namespace: "codewire-sandbox".into(),
                pod_name: "owned-workspace".into(),
                pod_uid: "550e8400-e29b-41d4-a716-446655440001".into(),
                claim_uid: "550e8400-e29b-41d4-a716-446655440002".into(),
                sandbox_uid: "550e8400-e29b-41d4-a716-446655440003".into(),
                binding_generation: 3,
                binding_bound_at: Some(buffa_types::Timestamp::from_unix(1, 0)).into(),
                ..Default::default()
            }
        }
        fn info(
            image: &CwPayloadIdentity,
            generation: u64,
            current: Option<&CwPayloadIdentity>,
            previous: Option<&CwPayloadIdentity>,
        ) -> GetEnvironmentCwRuntimeResponse {
            GetEnvironmentCwRuntimeResponse {
                incarnation: Some(binding()).into(),
                supported_image: true,
                bootstrap_identity: Some(proto_identity(image)).into(),
                selection: Some(EnvironmentCwRuntimeSelection {
                    generation,
                    current: current.map(proto_identity).into(),
                    previous: previous.map(proto_identity).into(),
                    consistent: true,
                    retained_count: u32::from(current.is_some()) + u32::from(previous.is_some()),
                    ..Default::default()
                })
                .into(),
                ..Default::default()
            }
        }
        fn acknowledgement(
            checkpoint: u32,
            effect: &str,
            receipt: environment_cw_runtime_acknowledgement::Receipt,
        ) -> EnvironmentCwRuntimeAcknowledgement {
            EnvironmentCwRuntimeAcknowledgement {
                checkpoint,
                effect: effect.into(),
                receipt: Some(receipt),
                ..Default::default()
            }
        }
        fn operation(
            before: &GetEnvironmentCwRuntimeResponse,
            target: &CwPayloadIdentity,
            action: &str,
        ) -> EnvironmentCwRuntimeOperation {
            let bootstrap = action == "update" && before.selection.generation == 0;
            let effects: Vec<&str> = if bootstrap {
                vec!["bootstrap", "staging", "update", "cleanup"]
            } else if action == "update" {
                vec!["staging", "update", "cleanup"]
            } else {
                vec!["rollback", "cleanup"]
            };
            let mut current = expectation(before.selection.as_option().unwrap());
            let acknowledgements = effects
                .iter()
                .enumerate()
                .map(|(index, &effect)| {
                    let receipt = match effect {
                        "staging" => environment_cw_runtime_acknowledgement::Receipt::Staged(
                            Box::new(EnvironmentCwRuntimeStaged {
                                sha256: target.sha256.clone(),
                                size: target.size,
                                ..Default::default()
                            }),
                        ),
                        "cleanup" => environment_cw_runtime_acknowledgement::Receipt::Cleaned(
                            Box::new(EnvironmentCwRuntimeCleaned::default()),
                        ),
                        _ => {
                            let sha = if effect == "bootstrap" {
                                before.bootstrap_identity.sha256.clone()
                            } else {
                                target.sha256.clone()
                            };
                            let changed = current.current_sha256.as_deref() != Some(&sha);
                            if changed {
                                current.generation = current.generation.checked_add(1).unwrap();
                                current.previous_sha256 = current.current_sha256.take();
                                current.current_sha256 = Some(sha.clone());
                            }
                            environment_cw_runtime_acknowledgement::Receipt::Selected(Box::new(
                                EnvironmentCwRuntimeSelected {
                                    sha256: sha,
                                    generation: current.generation,
                                    previous_sha256: current.previous_sha256.clone(),
                                    changed,
                                    ..Default::default()
                                },
                            ))
                        }
                    };
                    acknowledgement(index as u32 + 1, effect, receipt)
                })
                .collect();
            EnvironmentCwRuntimeOperation {
                request_id: "550e8400-e29b-41d4-a716-446655440009".into(),
                incarnation: before.incarnation.clone(),
                action: action.into(),
                phase: "succeeded".into(),
                checkpoint: effects.len() as u32,
                issued_effect: Some("cleanup".into()),
                expected_selection: Some(expectation(before.selection.as_option().unwrap())).into(),
                identity: Some(proto_identity(target)).into(),
                bootstrap_identity: if bootstrap {
                    before.bootstrap_identity.clone()
                } else {
                    Default::default()
                },
                acknowledgements,
                admitted_at: Some(buffa_types::Timestamp::from_unix(1, 0)).into(),
                issued_at: Some(buffa_types::Timestamp::from_unix(2, 0)).into(),
                terminal_at: Some(buffa_types::Timestamp::from_unix(3, 0)).into(),
                ..Default::default()
            }
        }
        fn validate(
            op: &EnvironmentCwRuntimeOperation,
            before: &GetEnvironmentCwRuntimeResponse,
            target: &CwPayloadIdentity,
        ) -> anyhow::Result<()> {
            validate_operation(op, &op.request_id, &op.action, &binding(), before, target)
        }
        #[test]
        fn distinct_bootstrap_and_release_are_both_acknowledged_before_b_and_rollback() {
            let image = identity('c', "image-ci");
            let a = identity('a', "release-a");
            let b = identity('b', "release-b");
            let absent = info(&image, 0, None, None);
            let bootstrap = operation(&absent, &a, "update");
            validate(&bootstrap, &absent, &a).unwrap();
            let receipt = &bootstrap.acknowledgements[2].receipt;
            assert!(
                matches!(receipt,Some(environment_cw_runtime_acknowledgement::Receipt::Selected(v))
                if v.generation==2 && v.previous_sha256.as_deref()==Some(image.sha256.as_str()))
            );
            let selected_a = info(&image, 2, Some(&a), Some(&image));
            let update = operation(&selected_a, &b, "update");
            validate(&update, &selected_a, &b).unwrap();
            let selected_b = info(&image, 3, Some(&b), Some(&a));
            let rollback = operation(&selected_b, &a, "rollback");
            validate(&rollback, &selected_b, &a).unwrap();
        }
        #[test]
        fn identical_original_image_and_release_a_is_a_valid_observed_noop() {
            let a = identity('a', "release-a");
            let absent = info(&a, 0, None, None);
            let op = operation(&absent, &a, "update");
            validate(&op, &absent, &a).unwrap();
            assert!(matches!(&op.acknowledgements[2].receipt,
                Some(environment_cw_runtime_acknowledgement::Receipt::Selected(v)) if !v.changed && v.generation==1));
        }
        #[test]
        fn running_bootstrap_requires_the_exact_ci_producer_instead_of_release_a() {
            let image = identity('c', "ci");
            let a = identity('a', "release-a");
            admit_original_image(&proto_identity(&image), &image).unwrap();
            assert!(admit_original_image(&proto_identity(&a), &image).is_err());
            let mut forged = image.clone();
            forged.source_revision = "7".repeat(40);
            assert!(admit_original_image(&proto_identity(&forged), &image).is_err());
        }
        #[test]
        fn success_requires_retained_cleanup_and_exact_original_request_scope() {
            let a = identity('a', "a");
            let b = identity('b', "b");
            let before = info(&a, 11, Some(&a), None);
            let valid = operation(&before, &b, "update");
            validate(&valid, &before, &b).unwrap();
            for mutated in 0..5 {
                let mut op = valid.clone();
                match mutated {
                    0 => op.issued_effect = None,
                    1 => op.phase = "unknown".into(),
                    2 => op
                        .incarnation
                        .modify(|v| v.pod_uid = "550e8400-e29b-41d4-a716-446655440099".into()),
                    3 => op.expected_selection.modify(|v| v.generation += 1),
                    _ => op.identity.modify(|v| v.sha256 = a.sha256.clone()),
                }
                assert!(validate(&op, &before, &b).is_err());
            }
            assert!(
                validate_operation(
                    &valid,
                    "550e8400-e29b-41d4-a716-446655440088",
                    "update",
                    &binding(),
                    &before,
                    &b
                )
                .is_err()
            );
        }
        #[test]
        fn forged_or_missing_effect_receipts_never_prove_selection() {
            let a = identity('a', "a");
            let b = identity('b', "b");
            let before = info(&a, 4, Some(&a), None);
            let valid = operation(&before, &b, "update");
            for mutated in 0..5 {
                let mut op = valid.clone();
                match mutated {
                    0 => {
                        op.acknowledgements.pop();
                    }
                    1 => op.acknowledgements.swap(0, 1),
                    2 => {
                        if let Some(environment_cw_runtime_acknowledgement::Receipt::Staged(v)) =
                            &mut op.acknowledgements[0].receipt
                        {
                            v.size += 1;
                        }
                    }
                    3 => {
                        if let Some(environment_cw_runtime_acknowledgement::Receipt::Selected(v)) =
                            &mut op.acknowledgements[1].receipt
                        {
                            v.generation += 1;
                        }
                    }
                    _ => {
                        if let Some(environment_cw_runtime_acknowledgement::Receipt::Selected(v)) =
                            &mut op.acknowledgements[1].receipt
                        {
                            v.previous_sha256 = None;
                        }
                    }
                }
                assert!(validate(&op, &before, &b).is_err());
            }
        }
        #[test]
        fn selection_cas_is_lossless_above_javascript_safe_integer() {
            let a = identity('a', "a");
            let b = identity('b', "b");
            let generation = (1_u64 << 53) + 17;
            let before = info(&a, generation, Some(&a), None);
            let op = operation(&before, &b, "update");
            let decoded: EnvironmentCwRuntimeOperation =
                serde_json::from_slice(&serde_json::to_vec(&op).unwrap()).unwrap();
            assert_eq!(decoded.expected_selection.generation, generation);
            validate(&decoded, &before, &b).unwrap();
        }
        #[test]
        fn exhausted_generation_never_becomes_wrapped_selection_permission() {
            let a = identity('a', "a");
            let b = identity('b', "b");
            let before = info(&a, u64::MAX, Some(&a), None);
            let mut fabricated = operation(&info(&a, 7, Some(&a), None), &b, "update");
            fabricated.expected_selection =
                Some(expectation(before.selection.as_option().unwrap())).into();
            assert!(validate(&fabricated, &before, &b).is_err());
        }
        fn synthetic_release(directory: &Path, version: &str) -> CwPayloadIdentity {
            let record = build_record::BuildRecord {
                package_version: version.into(),
                rustc: "rustc 1.93.0 (synthetic fixture)".into(),
                source_revision: Some("d".repeat(40)),
                source_tree_sha256: Some("e".repeat(64)),
                target: "x86_64-unknown-linux-musl".into(),
            };
            let mut bytes = vec![0; 120];
            bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            bytes[16] = 3;
            bytes[18] = 62;
            bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
            bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
            bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
            bytes[64] = 1;
            bytes.extend(record.frame(CW_MARKER).unwrap());
            let identity = CwPayloadIdentity {
                schema_version: 2,
                protocol_version: 1,
                record_version: 1,
                package_version: record.package_version,
                target: record.target,
                source_revision: record.source_revision.unwrap(),
                source_tree_sha256: record.source_tree_sha256.unwrap(),
                rustc: record.rustc,
                sha256: hex_digest(&bytes),
                size: bytes.len() as u64,
            };
            fs::write(directory.join("cw"), bytes).unwrap();
            fs::set_permissions(directory.join("cw"), fs::Permissions::from_mode(0o500)).unwrap();
            fs::write(
                directory.join("cw-runtime.json"),
                identity.encode().unwrap(),
            )
            .unwrap();
            fs::set_permissions(
                directory.join("cw-runtime.json"),
                fs::Permissions::from_mode(0o400),
            )
            .unwrap();
            identity
        }
        #[test]
        fn original_full_record_intake_refuses_tampered_bytes_and_descriptor() {
            let directory = tempfile::tempdir().unwrap();
            let id = synthetic_release(directory.path(), "a");
            Payload::open(directory.path().into(), &id.sha256).unwrap();
            assert!(Payload::open(directory.path().into(), &"f".repeat(64)).is_err());
            let mut changed = id.clone();
            changed.source_revision = "f".repeat(40);
            fs::set_permissions(
                directory.path().join("cw-runtime.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            fs::write(
                directory.path().join("cw-runtime.json"),
                changed.encode().unwrap(),
            )
            .unwrap();
            assert!(Payload::open(directory.path().into(), &id.sha256).is_err());
            fs::write(
                directory.path().join("cw-runtime.json"),
                id.encode().unwrap(),
            )
            .unwrap();
            fs::set_permissions(
                directory.path().join("cw"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            fs::write(directory.path().join("cw"), b"not the admitted executable").unwrap();
            assert!(Payload::open(directory.path().into(), &id.sha256).is_err());
        }
        #[test]
        fn held_file_refuses_links_fifo_writable_ancestor_and_named_replacement() {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("asset");
            fs::write(&path, b"original").unwrap();
            let held = Held::open(&path, 64).unwrap();
            let alias = directory.path().join("alias");
            fs::hard_link(&path, &alias).unwrap();
            assert!(held.recheck().is_err());
            assert!(Held::open(&path, 64).is_err());
            fs::remove_file(alias).unwrap();
            let symbolic = directory.path().join("symbolic");
            symlink(&path, &symbolic).unwrap();
            assert!(Held::open(&symbolic, 64).is_err());
            let fifo = directory.path().join("fifo");
            rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, Mode::from_raw_mode(0o600)).unwrap();
            assert!(Held::open(&fifo, 64).is_err());
            let held = Held::open(&path, 64).unwrap();
            fs::rename(&path, directory.path().join("old")).unwrap();
            fs::write(&path, b"original").unwrap();
            assert!(held.recheck().is_err());
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777)).unwrap();
            assert!(Held::open(&path, 64).is_err());
        }
        fn witness(a: &CwPayloadIdentity, b: &CwPayloadIdentity) -> Witness {
            let source = Source {
                revision: a.source_revision.clone(),
                git_tree: "1".repeat(40),
                source_tree_sha256: a.source_tree_sha256.clone(),
                index_sha256: "2".repeat(64),
                object_count: 17,
            };
            let entry = |identity: &CwPayloadIdentity, path: &str| ReleaseInput {
                release_dir: PathBuf::from(path),
                identity: identity.clone(),
                build_receipt: Descriptor {
                    path: "/private/build.json".into(),
                    sha256: "3".repeat(64),
                    size: 256,
                },
                producer_receipt: Descriptor {
                    path: "/private/producer.json".into(),
                    sha256: "4".repeat(64),
                    size: 512,
                },
                image: Descriptor {
                    path: "/private/cw.oci.tar".into(),
                    sha256: "5".repeat(64),
                    size: 1024,
                },
                index_sha256: "6".repeat(64),
                compilation_source: source.clone(),
                profile: "release".into(),
                version: identity.package_version.clone(),
                build_ref: "synthetic/owned-build".into(),
            };
            let mut support = entry(&identity('c', "ci"), "/private/support");
            support.profile = "ci".into();
            Witness {
                schema_version: 1,
                source_sha: source.revision.clone(),
                current_source: source.clone(),
                support_cw: support,
                release_a: entry(a, "/private/a"),
                release_b: entry(b, "/private/b"),
            }
        }
        #[test]
        fn externally_pinned_witness_refuses_source_profile_version_and_unknown_fields() {
            let a = identity('a', "a");
            let b = identity('b', "b");
            let valid = witness(&a, &b);
            let admit = |raw: &[u8], pin: &str| {
                admit_witness(
                    raw,
                    pin,
                    Path::new("/private/a"),
                    &a,
                    Path::new("/private/b"),
                    &b,
                )
            };
            let raw = canonical_json(&valid).unwrap();
            admit(&raw, &hex_digest(&raw)).unwrap();
            assert!(admit(&raw, &"0".repeat(64)).is_err());
            for changed in 0..7 {
                let mut altered = valid.clone();
                match changed {
                    0 => altered.release_a.compilation_source.git_tree = "7".repeat(40),
                    1 => altered.release_b.profile = "ci".into(),
                    2 => altered.release_a.identity.record_version = 2,
                    3 => altered.release_b.version = "different".into(),
                    4 => altered.release_a.release_dir = "/private/foreign".into(),
                    5 => altered.support_cw.profile = "release".into(),
                    _ => altered.support_cw.compilation_source.index_sha256 = "8".repeat(64),
                }
                let raw = canonical_json(&altered).unwrap();
                assert!(admit(&raw, &hex_digest(&raw)).is_err());
            }
            let mut extra = serde_json::to_value(&valid).unwrap();
            extra["credential"] = serde_json::json!("canary");
            let raw = canonical_json(&extra).unwrap();
            assert!(admit(&raw, &hex_digest(&raw)).is_err());
        }
        fn session() -> EnvironmentSession {
            EnvironmentSession {
                session_id: format!("session-{ENVIRONMENT}"),
                state: EnvironmentSessionState::Running.into(),
                launch_generation: 9,
                command: vec!["/usr/bin/python3".into(), "fixed-probe".into()],
                working_dir: "/workspace".into(),
                name: "owned-probe".into(),
                created_at: Some(buffa_types::Timestamp::from_unix(1, 0)).into(),
                started_at: Some(buffa_types::Timestamp::from_unix(2, 0)).into(),
                ..Default::default()
            }
        }
        #[test]
        fn original_session_birth_generation_command_and_history_are_all_required() {
            let original = session();
            validate_session(&original, &original, false).unwrap();
            for change in 0..5 {
                let mut view = original.clone();
                match change {
                    0 => view.launch_generation += 1,
                    1 => view.command.push("replacement".into()),
                    2 => view.started_at = Some(buffa_types::Timestamp::from_unix(3, 0)).into(),
                    3 => view.output_start_offset = 1,
                    _ => view.cleanup_unknown = true,
                }
                assert!(validate_session(&view, &original, false).is_err());
            }
        }
        fn probe(
            sequence: u32,
            image: &CwPayloadIdentity,
            workspace: &CwPayloadIdentity,
            selected: Option<&CwPayloadIdentity>,
        ) -> ProbeEvent {
            let actor = |pid, parent_pid, path: &str, sha: &str, size| Actor {
                pid,
                parent_pid,
                start_ticks: pid as u64 + 5,
                executable: path.into(),
                device: 9,
                inode: pid as u64 + 100,
                size,
                sha256: sha.into(),
                uid: 0,
                gid: 0,
                mode: 0o100555,
                links: 1,
            };
            let (event, phase) = match sequence {
                0 => ("ready", "baseline"),
                1 => ("checkpoint", "bootstrapped-a"),
                2 => ("checkpoint", "selected-b"),
                3 => ("checkpoint", "rolled-back-a"),
                _ => ("closed", "closed"),
            };
            let mut result = ProbeEvent {
                schema_version: 1,
                event: event.into(),
                phase: phase.into(),
                nonce: NONCE.into(),
                environment_id: ENVIRONMENT.into(),
                sequence,
                samples: 2 + sequence as u64,
                boot_id: ENVIRONMENT.into(),
                uid: 1000,
                gid: 1000,
                actors: Actors {
                    supervisor: actor(1, 0, "/usr/bin/dash", &"d".repeat(64), 64),
                    daemon: actor(2, 1, "/codewire/bin/cw", &image.sha256, image.size),
                    session: actor(3, 2, "/usr/bin/python3.13", &"e".repeat(64), 64),
                    shell: actor(4, 3, "/usr/bin/bash", &"f".repeat(64), 64),
                },
                managed: std::collections::BTreeMap::new(),
                managed_terminal: false,
                selection: Some(Selection {
                    logical_path: "/usr/local/bin/cw".into(),
                    resolved_path: selected.map_or_else(
                        || "/usr/local/bin/cw".into(),
                        |id| format!("{STORE}/versions/{}/cw", id.sha256),
                    ),
                    sha256: selected.unwrap_or(workspace).sha256.clone(),
                    size: selected.unwrap_or(workspace).size,
                    version: selected.unwrap_or(workspace).package_version.clone(),
                }),
                shell_terminal: sequence == 4,
                evidence: Evidence {
                    path: format!(
                        "/home/codewire/.local/state/codewire/cw-runtime-proof/{NONCE}/{sequence:03}-{event}.json"
                    ),
                    sha256: String::new(),
                    bytes: 0,
                },
            };
            seal_evidence(&mut result);
            result
        }
        fn seal_evidence(event: &mut ProbeEvent) {
            let mut value = serde_json::to_value(&*event).unwrap();
            value.as_object_mut().unwrap().remove("evidence");
            let bytes = canonical_json(&value).unwrap();
            event.evidence.sha256 = hex_digest(&bytes);
            event.evidence.bytes = bytes.len() as u64;
        }
        #[test]
        fn original_root_owned_images_are_distinct_from_uid1000_process_custody() {
            let image = identity('c', "ci");
            let a = identity('a', "a");
            let before = probe(0, &image, &a, None);
            validate_probe(
                &before,
                0,
                "ready",
                "baseline",
                None,
                &OriginalImages {
                    support: &proto_identity(&image),
                    workspace: &a,
                },
                None,
            )
            .unwrap();
            let event = probe(1, &image, &a, Some(&a));
            validate_probe(
                &event,
                1,
                "checkpoint",
                "bootstrapped-a",
                Some(&a),
                &OriginalImages {
                    support: &proto_identity(&image),
                    workspace: &a,
                },
                Some(&before),
            )
            .unwrap();
        }
        #[test]
        fn distinct_workspace_and_support_bootstrap_profiles_cannot_be_interchanged() {
            let mut image = identity('c', "ci");
            image.size = 96;
            let a = identity('a', "release-a");
            let support = proto_identity(&image);
            let images = OriginalImages {
                support: &support,
                workspace: &a,
            };
            assert_ne!(image.sha256, a.sha256);
            assert_ne!(image.size, a.size);
            assert_ne!(image.package_version, a.package_version);
            for (path, expected, wrong) in [
                ("/usr/local/bin/cw", &a, &image),
                ("/codewire/bin/cw", &image, &a),
            ] {
                let mut before = probe(0, &image, &a, None);
                let selection = before.selection.as_mut().unwrap();
                selection.logical_path = path.into();
                selection.resolved_path = path.into();
                selection.sha256 = expected.sha256.clone();
                selection.size = expected.size;
                selection.version = expected.package_version.clone();
                seal_evidence(&mut before);
                validate_probe(&before, 0, "ready", "baseline", None, &images, None).unwrap();
                assert_eq!(before.actors.daemon.sha256, image.sha256);
                let before_json = serde_json::to_vec(&before).unwrap();
                for field in 0..3 {
                    let mut swapped = serde_json::from_slice::<ProbeEvent>(&before_json).unwrap();
                    let selection = swapped.selection.as_mut().unwrap();
                    match field {
                        0 => selection.sha256 = wrong.sha256.clone(),
                        1 => selection.size = wrong.size,
                        _ => selection.version = wrong.package_version.clone(),
                    }
                    seal_evidence(&mut swapped);
                    assert!(
                        validate_probe(&swapped, 0, "ready", "baseline", None, &images, None)
                            .is_err()
                    );
                }
                let mut replaced = serde_json::from_slice::<ProbeEvent>(&before_json).unwrap();
                replaced.actors.daemon.sha256 = a.sha256.clone();
                seal_evidence(&mut replaced);
                assert!(
                    validate_probe(&replaced, 0, "ready", "baseline", None, &images, None).is_err()
                );
            }
        }

        #[test]
        fn prebootstrap_cache_and_stable_image_alias_are_mandatory() {
            let image = identity('c', "ci");
            let a = identity('a', "a");
            let before = probe(0, &image, &a, None);
            for change in 0..4 {
                let mut event = probe(0, &image, &a, None);
                match change {
                    0 => event.selection = None,
                    1 => {
                        event.selection.as_mut().unwrap().logical_path =
                            "/home/codewire/.local/bin/cw".into()
                    }
                    2 => event.selection.as_mut().unwrap().sha256 = image.sha256.clone(),
                    _ => event.selection.as_mut().unwrap().version = "stale".into(),
                }
                seal_evidence(&mut event);
                assert!(
                    validate_probe(
                        &event,
                        0,
                        "ready",
                        "baseline",
                        None,
                        &OriginalImages {
                            support: &proto_identity(&image),
                            workspace: &a,
                        },
                        None
                    )
                    .is_err()
                );
            }
            let mut event = probe(1, &image, &a, Some(&a));
            event.selection.as_mut().unwrap().logical_path = "/codewire/bin/cw".into();
            seal_evidence(&mut event);
            assert!(
                validate_probe(
                    &event,
                    1,
                    "checkpoint",
                    "bootstrapped-a",
                    Some(&a),
                    &OriginalImages {
                        support: &proto_identity(&image),
                        workspace: &a,
                    },
                    Some(&before)
                )
                .is_err()
            );
        }

        #[test]
        fn probe_refuses_actor_exec_replacement_foreign_scope_and_evidence_redirection() {
            let image = identity('c', "ci");
            let a = identity('a', "a");
            let before = probe(0, &image, &a, None);
            for change in 0..6 {
                let mut event = probe(1, &image, &a, Some(&a));
                match change {
                    0 => event.actors.daemon.inode += 1,
                    1 => event.actors.session.start_ticks += 1,
                    2 => event.environment_id = "550e8400-e29b-41d4-a716-446655440099".into(),
                    3 => event.actors.shell.sha256 = "1".repeat(64),
                    4 => {
                        event.evidence.path = format!(
                            "/home/codewire/.local/state/codewire/cw-runtime-proof/{NONCE}/../foreign.json"
                        )
                    }
                    _ => event.samples = before.samples,
                }
                seal_evidence(&mut event);
                assert!(
                    validate_probe(
                        &event,
                        1,
                        "checkpoint",
                        "bootstrapped-a",
                        Some(&a),
                        &OriginalImages {
                            support: &proto_identity(&image),
                            workspace: &a,
                        },
                        Some(&before)
                    )
                    .is_err()
                );
            }
        }
        fn frame(event: &ProbeEvent, offset: u64) -> EnvironmentSessionOutputChunk {
            let mut data = format!("CW_PLATFORM_RUNTIME_PROBE {NONCE} ").into_bytes();
            data.extend(canonical_json(event).unwrap());
            EnvironmentSessionOutputChunk {
                offset,
                next_offset: offset + data.len() as u64,
                stream: codewire_client::EnvironmentSessionOutputStream::Stdout.into(),
                data,
                ..Default::default()
            }
        }
        fn managed_probe(
            sequence: u32,
            image: &CwPayloadIdentity,
            a: &CwPayloadIdentity,
            selected: Option<&CwPayloadIdentity>,
        ) -> ProbeEvent {
            let mut event = probe(sequence, image, a, selected);
            for index in 0..3 {
                let pid = 10 + index * 3;
                for (offset, role, parent) in [
                    (0, "driver", event.actors.daemon.pid),
                    (1, "guardian", pid),
                    (2, "provider", pid + 1),
                ] {
                    let mut actor = event.actors.daemon.clone();
                    actor.pid = pid + offset;
                    actor.parent_pid = parent;
                    actor.start_ticks = actor.pid as u64 + 5;
                    actor.inode = actor.pid as u64 + 100;
                    if role == "provider" {
                        actor.executable = "/opt/codewire/agents/codex".into();
                        actor.sha256 = "e".repeat(64);
                        actor.size = 64;
                    }
                    event
                        .managed
                        .insert(format!("managed{index}-{role}"), actor);
                }
            }
            if sequence >= 4 {
                event.event = match sequence {
                    4 => "managed-stop-ready",
                    5 => "managed-stopped",
                    _ => "closed",
                }
                .into();
                event.phase = if sequence == 6 {
                    "closed"
                } else {
                    "rolled-back-a"
                }
                .into();
                event.shell_terminal = sequence == 6;
                event.managed_terminal = sequence >= 5;
            }
            event.evidence.path = format!(
                "/home/codewire/.local/state/codewire/cw-runtime-proof/{NONCE}/{sequence:03}-{}.json",
                event.event
            );
            seal_evidence(&mut event);
            event
        }
        #[test]
        fn managed_attachment_requires_original_nine_handles_and_ack_before_terminal_then_close() {
            let image = identity('c', "ci");
            let a = identity('a', "a");
            let b = identity('b', "b");
            let baseline = managed_probe(0, &image, &a, None);
            let images = OriginalImages {
                support: &proto_identity(&image),
                workspace: &a,
            };
            let mut decoder = OutputDecoder::new(NONCE, ENVIRONMENT);
            for (sequence, selected) in [
                (0, None),
                (1, Some(&a)),
                (2, Some(&b)),
                (3, Some(&a)),
                (4, Some(&a)),
                (5, Some(&a)),
                (6, Some(&a)),
            ] {
                let event = managed_probe(sequence, &image, &a, selected);
                validate_probe(
                    &event,
                    sequence,
                    &event.event,
                    &event.phase,
                    selected,
                    &images,
                    if sequence == 0 { None } else { Some(&baseline) },
                )
                .unwrap();
                let frames = decoder
                    .push(frame(&event, decoder.captured.len() as u64))
                    .unwrap();
                assert_eq!(frames.len(), 1);
            }
            let original = session();
            let mut terminal = original.clone();
            terminal.state = EnvironmentSessionState::Exited.into();
            terminal.exit_code = Some(0);
            terminal.finished_at = Some(buffa_types::Timestamp::from_unix(9, 0)).into();
            terminal.output_end_offset = decoder.captured.len() as u64;
            decoder.finish(&terminal, &original).unwrap();
            for change in 0..5 {
                let mut wrong = managed_probe(5, &image, &a, Some(&a));
                match change {
                    0 => wrong.managed_terminal = false,
                    1 => {
                        wrong.managed.remove("managed1-guardian");
                    }
                    2 => {
                        wrong
                            .managed
                            .get_mut("managed1-provider")
                            .unwrap()
                            .start_ticks += 1
                    }
                    3 => {
                        wrong
                            .managed
                            .get_mut("managed1-provider")
                            .unwrap()
                            .parent_pid = 1
                    }
                    _ => wrong.managed.get_mut("managed1-driver").unwrap().sha256 = "f".repeat(64),
                }
                seal_evidence(&mut wrong);
                assert!(
                    validate_probe(
                        &wrong,
                        5,
                        "managed-stopped",
                        "rolled-back-a",
                        Some(&a),
                        &images,
                        Some(&baseline)
                    )
                    .is_err()
                );
            }
            // An ordinary observer cannot opt into the extra lifecycle midway;
            // a managed observer cannot skip its readiness acknowledgement.
            for managed in [false, true] {
                let mut decoder = OutputDecoder::new(NONCE, ENVIRONMENT);
                for sequence in 0..4 {
                    let selected = if sequence == 0 { None } else { Some(&a) };
                    let event = if managed {
                        managed_probe(sequence, &image, &a, selected)
                    } else {
                        probe(sequence, &image, &a, selected)
                    };
                    decoder
                        .push(frame(&event, decoder.captured.len() as u64))
                        .unwrap();
                }
                let mut skipped = managed_probe(5, &image, &a, Some(&a));
                skipped.sequence = 4;
                seal_evidence(&mut skipped);
                assert!(
                    decoder
                        .push(frame(&skipped, decoder.captured.len() as u64))
                        .is_err()
                );
            }
        }
        #[test]
        fn original_attachment_fragmentation_is_lossless_through_five_frames_and_normal_exit() {
            let image = identity('c', "ci");
            let a = identity('a', "a");
            let b = identity('b', "b");
            let mut decoder = OutputDecoder::new(NONCE, ENVIRONMENT);
            for (sequence, selected) in [
                (0, None),
                (1, Some(&a)),
                (2, Some(&b)),
                (3, Some(&a)),
                (4, Some(&a)),
            ] {
                let event = probe(sequence, &image, &a, selected);
                let chunk = frame(&event, decoder.captured.len() as u64);
                let mut offset = chunk.offset;
                let mut count = 0;
                for data in chunk.data.chunks(37) {
                    count += decoder
                        .push(EnvironmentSessionOutputChunk {
                            offset,
                            next_offset: offset + data.len() as u64,
                            data: data.to_vec(),
                            stream: codewire_client::EnvironmentSessionOutputStream::Stdout.into(),
                            ..Default::default()
                        })
                        .unwrap()
                        .len();
                    offset += data.len() as u64;
                }
                assert_eq!(count, 1);
            }
            let original = session();
            let mut terminal = original.clone();
            terminal.state = EnvironmentSessionState::Exited.into();
            terminal.exit_code = Some(0);
            terminal.finished_at = Some(buffa_types::Timestamp::from_unix(9, 0)).into();
            terminal.output_end_offset = decoder.captured.len() as u64;
            decoder.finish(&terminal, &original).unwrap();
            assert!(
                decoder
                    .push(frame(
                        &probe(4, &image, &a, Some(&a)),
                        decoder.captured.len() as u64
                    ))
                    .is_err()
            );
        }
        #[test]
        fn attachment_refuses_gap_replay_stderr_oversize_and_early_terminal() {
            let image = identity('c', "ci");
            let a = identity('a', "a");
            let event = probe(0, &image, &a, None);
            for change in 0..5 {
                let mut decoder = OutputDecoder::new(NONCE, ENVIRONMENT);
                let mut chunk = frame(&event, 0);
                match change {
                    0 => chunk.offset = 1,
                    1 => {
                        chunk.stream =
                            codewire_client::EnvironmentSessionOutputStream::Stderr.into()
                    }
                    2 => {
                        chunk.data = vec![b'x'; MAX_LINE];
                        chunk.next_offset = MAX_LINE as u64;
                    }
                    3 => {
                        let mut wrong = probe(1, &image, &a, None);
                        wrong.environment_id = "550e8400-e29b-41d4-a716-446655440099".into();
                        chunk = frame(&wrong, 0);
                    }
                    _ => {
                        decoder.push(chunk.clone()).unwrap();
                        chunk = frame(&event, decoder.captured.len() as u64);
                    }
                }
                assert!(decoder.push(chunk).is_err());
            }
            assert!(
                OutputDecoder::new(NONCE, ENVIRONMENT)
                    .finish(&session(), &session())
                    .is_err()
            );
        }
        #[test]
        fn before_send_journal_is_durable_and_never_overwrites_an_original_nonce() {
            let home = tempfile::tempdir().unwrap();
            fs::set_permissions(home.path(), fs::Permissions::from_mode(0o755)).unwrap();
            assert!(InputJournal::create(home.path(), NONCE).is_err());
            fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let mut journal = InputJournal::create(home.path(), NONCE).unwrap();
            assert!(InputJournal::create(home.path(), NONCE).is_err());
            let id = "550e8400-e29b-41d4-a716-446655440099";
            journal
                .request(id, "update", 0, &binding(), &session(), &identity('a', "a"))
                .unwrap();
            let bytes = fs::read(&journal.path).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["request_id"], id);
            assert_eq!(value["event"], "before-send");
            assert!(
                !String::from_utf8(bytes)
                    .unwrap()
                    .contains("at_kind_connect")
            );
            fs::rename(&journal.path, home.path().join("retained")).unwrap();
            fs::write(&journal.path, b"foreign").unwrap();
            assert!(
                journal
                    .request(id, "update", 0, &binding(), &session(), &identity('a', "a"))
                    .is_err()
            );
        }
    }
}
