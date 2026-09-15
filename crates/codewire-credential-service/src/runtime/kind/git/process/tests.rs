use super::*;

#[test]
fn git_environment_and_arguments_exclude_ambient_authority() {
    let command = command(Path::new("/fixed-public-fixture"));
    let command = command.as_std();
    assert_eq!(command.get_program(), "/usr/bin/git");
    let env = command
        .get_envs()
        .map(|(name, value)| (name.to_str().unwrap(), value.unwrap().to_str().unwrap()))
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(env.len(), 11);
    assert_eq!(env["GIT_EXEC_PATH"], "/usr/lib/git-core");
    assert_eq!(env["HOME"], "/fixed-public-fixture");
    assert_eq!(env["GIT_CONFIG_GLOBAL"], "/dev/null");
    assert!(!env.contains_key("HTTP_PROXY"));
    assert!(!env.contains_key("GITHUB_TOKEN"));
    assert_eq!(
        command.get_current_dir().unwrap(),
        Path::new("/fixed-public-fixture")
    );
    assert_eq!(
        command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never"
        ]
    );
}

#[tokio::test]
async fn output_limit_and_cancelled_admission_fail_closed() {
    assert!(
        bounded_bytes(std::io::Cursor::new(vec![0; IO_LIMIT + 1]))
            .await
            .is_err()
    );
    assert_eq!(
        bounded_bytes(std::io::Cursor::new(vec![0; IO_LIMIT]))
            .await
            .unwrap()
            .len(),
        IO_LIMIT
    );
    let stop = CancellationToken::new();
    stop.cancel();
    assert!(
        run(&mut command(Path::new("/does-not-exist")), &[], &stop)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn timeout_kills_helpers_and_reaps_the_owned_leader() {
    let root = tempfile::tempdir().unwrap();
    let pid_file = root.path().join("helper.pid");
    // This fixed shell is solely a subprocess-custody unit test, never part of
    // the synthetic provider or the final-image smart-HTTP acceptance test.
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "sleep 30 & printf '%s' \"$!\" > \"$1\"; wait",
            "git-custody",
        ])
        .arg(&pid_file)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let started = tokio::time::Instant::now();
    let result = run_with_limit(
        &mut command,
        &[],
        &CancellationToken::new(),
        Duration::from_millis(250),
    )
    .await;
    assert!(matches!(
        result,
        Err(Failure {
            error: Error::ResourceLimit,
            drained: true
        })
    ));
    assert!(started.elapsed() < Duration::from_secs(5));
    let helper: i32 = std::fs::read_to_string(pid_file).unwrap().parse().unwrap();
    // A killed orphan can briefly be a zombie until PID1 reaps it; it cannot
    // still execute or hold our pipes. Linux procfs gives that distinction.
    assert_stopped(helper).await;
}

#[tokio::test]
async fn normal_leader_exit_also_kills_its_remaining_helpers() {
    let root = tempfile::tempdir().unwrap();
    let pid_file = root.path().join("helper.pid");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "sleep 30 </dev/null >/dev/null 2>&1 & printf '%s' \"$!\" > \"$1\"; exit 0",
            "git-custody",
        ])
        .arg(&pid_file)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    run_with_limit(
        &mut command,
        &[],
        &CancellationToken::new(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let helper: i32 = std::fs::read_to_string(pid_file).unwrap().parse().unwrap();
    assert_stopped(helper).await;
}

#[tokio::test]
async fn cancellation_stops_the_group_and_drains_its_pipes() {
    let root = tempfile::tempdir().unwrap();
    let pid_file = root.path().join("helper.pid");
    let stop = CancellationToken::new();
    let child_stop = stop.clone();
    let child_file = pid_file.clone();
    let task = tokio::spawn(async move {
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "sleep 30 & printf '%s' \"$!\" > \"$1\"; wait",
                "git-custody",
            ])
            .arg(child_file)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        run(&mut command, &[], &child_stop).await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let helper = loop {
        if let Ok(contents) = std::fs::read_to_string(&pid_file)
            && let Ok(pid) = contents.parse::<i32>()
        {
            break pid;
        }
        if tokio::time::Instant::now() >= deadline {
            stop.cancel();
            let _ = task.await;
            panic!("synthetic helper did not start within bound");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    stop.cancel();
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(Failure {
            error: Error::Protocol,
            drained: true
        })
    ));
    assert_stopped(helper).await;
}

async fn assert_stopped(helper: i32) {
    // kill(2) queues the signal; successful return does not synchronously
    // schedule/reap another process. Observe this exact owned helper boundedly.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match std::fs::read_to_string(format!("/proc/{helper}/stat")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Ok(stat) if stat.split_once(") ").unwrap().1.starts_with('Z') => return,
            _ => {}
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "owned Git helper remained alive after group kill"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
